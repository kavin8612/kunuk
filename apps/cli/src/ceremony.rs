//! Cerimonia end-to-end del gate Fase 0 (task 0.10).
//!
//! Concatena i flussi della fondamenta con crittografia **vera** prodotta dal crypto-core e
//! storage **opaco** sul backend: registrazione → login → sblocco → upload di un item cifrato
//! → rilettura e decifratura → verifica del manifest firmato. Prova end-to-end lo
//! zero-knowledge (SR-21/25): il server conserva e restituisce ciphertext byte-identico, mai
//! plaintext né chiavi.
//!
//! `account_id`/`vault_id` sono scelti dal client e **persistiti** dal server (ADR-0020): un
//! passo finale simula un dispositivo vergine che li ricostruisce da `login/start` / `GET /vault`
//! e ridecifra l'item (task 0.11, colma la lacuna multi-dispositivo del 0.10).

use kunuk_crypto_core::crypto::kdf_params::{self, KdfParams};
use kunuk_crypto_core::crypto::rng;
use kunuk_crypto_core::sync::{MergeResult, SyncDoc};
use kunuk_crypto_core::vault::item::{decode_content, encode_content, ItemContent, ItemData};
use kunuk_crypto_core::vault::manifest;
use kunuk_crypto_core::{
    derive_auth_verifier, register, unlock_with_password, RegistrationBundle, VaultKey,
};

use crate::api::{Client, Resp};
use crate::codec::{b64, unb64, uuid_from_string, uuid_to_string};

/// Parametri della cerimonia.
pub struct GateConfig {
    /// Base URL del backend, es. `https://localhost` (in dev passa da Caddy).
    pub base_url: String,
    /// CA radice in PEM da fidare (la CA interna di Caddy in dev). `None` = root di sistema.
    pub ca_pem: Option<Vec<u8>>,
    /// Email dell'account da registrare.
    pub email: String,
    /// Master password.
    pub password: String,
}

/// Mappa un errore del crypto-core in stringa (i messaggi del core sono grossolani per
/// non fare da oracolo, doc 16 §7).
fn ce(e: kunuk_crypto_core::CoreError) -> String {
    format!("crypto-core: {e}")
}

fn expect_status(r: &Resp, want: u16, step: &str) -> Result<(), String> {
    if r.status != want {
        return Err(format!(
            "{step}: atteso HTTP {want}, ricevuto {} — corpo: {}",
            r.status, r.body
        ));
    }
    Ok(())
}

/// 16 byte casuali dal CSPRNG del core (account_id / item_id).
fn rand_id() -> Result<[u8; 16], String> {
    let mut id = [0u8; 16];
    rng::fill(&mut id).map_err(ce)?;
    Ok(id)
}

/// Costruisce il JSON `kdf_params` (doc 12) dai parametri del bundle (che il core dà in CBOR).
/// Il client tiene il CBOR per la crittografia; il JSON è la forma di storage del server.
fn kdf_params_json(kdf_params_cbor: &[u8]) -> Result<serde_json::Value, String> {
    let kp = kdf_params::decode(kdf_params_cbor).map_err(ce)?;
    Ok(serde_json::json!({
        "memory_kib": kp.argon2.memory_kib,
        "iterations": kp.argon2.iterations,
        "parallelism": kp.argon2.parallelism,
        "salt": b64(&kp.salt[..]),
    }))
}

/// Item di prova: una credenziale di login con campi distintivi, per verificare che il
/// plaintext torni identico dopo il round-trip cifratura→server→decifratura.
fn sample_item() -> ItemContent {
    ItemContent {
        title: "Example".into(),
        folder: None,
        favorite: true,
        custom_fields: vec![],
        data: ItemData::Login {
            username: "alice@example.com".into(),
            password: "tromba-cavallo-graffetta-7".into(),
            uris: vec!["https://example.com/login".into()],
            notes: "creata dal gate 0.10".into(),
        },
    }
}

/// Corpo di `POST /v1/auth/register/finish` dal bundle (campi piatti, doc 12). La passkey è
/// assente (gate solo-password). `manifest`/`signature` sono lo `signed_empty_manifest` scisso.
/// `account_id`/`vault_id` sono scelti dal client e persistiti dal server (ADR-0020): permettono
/// a un dispositivo vergine di ricostruirli al login.
fn register_body(
    email: &str,
    bundle: &RegistrationBundle,
    account_id: &[u8; 16],
) -> Result<serde_json::Value, String> {
    let (manifest_body, signature) =
        manifest::split_signed_manifest(&bundle.signed_empty_manifest).map_err(ce)?;
    Ok(serde_json::json!({
        "email": email,
        "account_id": uuid_to_string(account_id),
        "vault_id": uuid_to_string(&bundle.vault_id),
        "password_verifier": b64(&bundle.auth_verifier[..]),
        "kdf_params": kdf_params_json(&bundle.kdf_params_cbor)?,
        "recovery_pubkey": b64(&bundle.recovery_pubkey),
        "password_envelope": b64(&bundle.password_envelope),
        "recovery_envelope": b64(&bundle.recovery_envelope),
        "manifest": b64(manifest_body),
        "manifest_pubkey": b64(&bundle.signing_pubkey),
        "signature": b64(signature),
        "wrapped_signing_key": b64(&bundle.wrapped_signing_key),
        "version": 1,
    }))
}

/// Esegue la cerimonia completa contro un backend vivo. Ogni passo logga una riga.
pub fn run_gate(cfg: &GateConfig, log: &mut dyn FnMut(&str)) -> Result<(), String> {
    let client = Client::new(&cfg.base_url, cfg.ca_pem.as_deref())?;
    let password = cfg.password.as_bytes();

    // ── 1) Registrazione: il core genera i segreti; al server va il bundle opaco. ──────────
    let account_id = rand_id()?;
    let mut bundle = register(password, None, &account_id).map_err(ce)?;
    let vault_id = bundle.vault_id;
    let secret_key = bundle.emergency_kit.reveal_secret_key().map_err(ce)?;
    let signing_pubkey = bundle.signing_pubkey;

    let body = register_body(&cfg.email, &bundle, &account_id)?;
    let r = client.post_json("/v1/auth/register/finish", None, &body)?;
    expect_status(&r, 201, "registrazione")?;
    log("1/8 registrazione → 201 (bundle opaco caricato)");

    // ── 2) Login via password: deriva il verificatore e ottiene un token di sessione. ──────
    let r = client.post_json(
        "/v1/auth/login/start",
        None,
        &serde_json::json!({ "email": cfg.email }),
    )?;
    expect_status(&r, 200, "login/start")?;

    let av = derive_auth_verifier(
        password,
        &secret_key[..],
        &bundle.kdf_params_cbor,
        &account_id,
    )
    .map_err(ce)?;
    if av[..] != bundle.auth_verifier[..] {
        return Err("verificatore ri-derivato diverso da quello di registrazione".into());
    }
    let r = client.post_json(
        "/v1/auth/login/finish",
        None,
        &serde_json::json!({ "email": cfg.email, "password_verifier": b64(&av[..]) }),
    )?;
    expect_status(&r, 200, "login/finish")?;
    let token = r
        .json()?
        .get("session_token")
        .and_then(|v| v.as_str())
        .ok_or("login/finish: session_token mancante")?
        .to_string();
    log("2/8 login → token di sessione ottenuto");

    // ── 3) Sblocco: scarica la busta password dal server e apre la VK (round-trip opaco). ──
    let r = client.get("/v1/envelopes", Some(&token))?;
    expect_status(&r, 200, "GET /envelopes")?;
    let password_envelope = find_password_envelope(&r.json()?)?;
    let vk = unlock_with_password(
        password,
        &secret_key[..],
        &password_envelope,
        &bundle.kdf_params_cbor,
        &account_id,
    )
    .map_err(ce)?;
    log("3/8 sblocco → VaultKey aperta dalla busta restituita dal server");

    // ── 4) Upload: cifra un item con la VK (id scelto dal client, AAD legata) e lo carica. ─
    let plaintext = sample_item();
    let content_cbor = encode_content(&plaintext).map_err(ce)?;
    let item_id = rand_id()?;
    let (ciphertext, wrapped_cek) = vk
        .encrypt_item(&vault_id, &item_id, &content_cbor)
        .map_err(ce)?;
    let item_id_str = uuid_to_string(&item_id);
    let r = client.post_json(
        "/v1/items",
        Some(&token),
        &serde_json::json!({
            "id": item_id_str,
            "ciphertext": b64(&ciphertext),
            "wrapped_cek": b64(&wrapped_cek),
        }),
    )?;
    expect_status(&r, 201, "POST /items")?;
    let returned_id = r
        .json()?
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or("POST /items: id mancante")?
        .to_string();
    if returned_id != item_id_str {
        return Err(format!(
            "id item non rispettato: inviato {item_id_str}, restituito {returned_id}"
        ));
    }
    log("4/8 upload → item cifrato caricato (id scelto dal client)");

    // ── 5) Decifratura: rilegge il ciphertext e lo decifra; il plaintext deve coincidere. ──
    let r = client.get(&format!("/v1/items/{item_id_str}"), Some(&token))?;
    expect_status(&r, 200, "GET /items/{id}")?;
    let got = r.json()?;
    let ct2 = unb64(field_str(&got, "ciphertext")?)?;
    let wcek2 = unb64(field_str(&got, "wrapped_cek")?)?;
    if ct2 != ciphertext || wcek2 != wrapped_cek {
        return Err("il server ha alterato il ciphertext (atteso byte-identico, SR-21)".into());
    }
    let decrypted = vk
        .decrypt_item(&vault_id, &item_id, &ct2, &wcek2)
        .map_err(ce)?;
    let recovered = decode_content(&decrypted).map_err(ce)?;
    if recovered != plaintext {
        return Err("il contenuto decifrato non coincide con l'originale".into());
    }
    log("5/8 decifratura → plaintext identico all'originale (zero-knowledge)");

    // ── 6) Verifica del manifest firmato restituito dal server (anti-rollback). ────────────
    let r = client.get("/v1/vault", Some(&token))?;
    expect_status(&r, 200, "GET /vault")?;
    let vault = r.json()?;
    let server_pubkey = unb64(field_str(&vault, "manifest_pubkey")?)?;
    if server_pubkey != signing_pubkey {
        return Err(
            "manifest_pubkey del server diversa da quella pinned alla registrazione".into(),
        );
    }
    let mut signed = unb64(field_str(&vault, "manifest")?)?;
    signed.extend_from_slice(&unb64(field_str(&vault, "signature")?)?);
    let pubkey: [u8; 32] = signing_pubkey;
    let view = manifest::verify_manifest_with_pubkey(&pubkey, &signed, &vault_id, 1).map_err(ce)?;
    if view.version != 1 {
        return Err(format!("versione manifest inattesa: {}", view.version));
    }
    log("6/8 manifest → firma valida, versione 1, pubkey pinned coincide");
    vk.lock();

    // ── 7) Dispositivo VERGINE (task 0.11): senza stato locale, ricostruisce gli id dal server. ─
    verify_virgin_device(
        &client,
        cfg,
        &secret_key[..],
        &account_id,
        &vault_id,
        &plaintext,
        log,
    )?;

    // ── 8) Sync CRDT (task 1.2): due dispositivi convergono sulla stessa directory. ────────
    verify_two_device_sync(&client, cfg, &secret_key[..], &account_id, &vault_id, log)?;
    Ok(())
}

/// Simula un **dispositivo vergine** (task 0.11): un secondo dispositivo che possiede solo
/// email + password + Secret Key (Emergency Kit) e NESSUN `account_id`/`vault_id` locale. Li
/// recupera dal server — `account_id` da `login/start` (reale, indistinguibile dal decoy
/// anti-enum SR-26), `vault_id` da `GET /vault` (autenticato) — poi sblocca e ridecifra l'item.
/// Prova che la lacuna multi-dispositivo del 0.10 è colmata (ADR-0020).
#[allow(clippy::too_many_arguments)]
fn verify_virgin_device(
    client: &Client,
    cfg: &GateConfig,
    secret_key: &[u8],
    expected_account_id: &[u8; 16],
    expected_vault_id: &[u8; 16],
    expected_plaintext: &ItemContent,
    log: &mut dyn FnMut(&str),
) -> Result<(), String> {
    // login/start espone account_id (reale): il device vergine non lo aveva. Deve coincidere
    // con quello scelto in registrazione (persistito dal server, ADR-0020).
    let r = client.post_json(
        "/v1/auth/login/start",
        None,
        &serde_json::json!({ "email": cfg.email }),
    )?;
    expect_status(&r, 200, "login/start (vergine)")?;
    let ls = r.json()?;
    let server_account_id = field_str(&ls, "account_id")?;
    if server_account_id != uuid_to_string(expected_account_id) {
        return Err("account_id da login/start ≠ registrazione (non persistito?)".into());
    }
    let account_id = uuid_from_string(server_account_id)?;

    // Stesso sblocco di un dispositivo qualunque, una volta noto l'account_id (condiviso con
    // verify_two_device_sync): deriva kdf_params/AV, fa login, apre la busta password.
    let (vk, token) = unlock_fresh_device(client, cfg, secret_key, &account_id)?;

    // vault_id dal server (autenticato): deve coincidere con quello di registrazione.
    let r = client.get("/v1/vault", Some(&token))?;
    expect_status(&r, 200, "GET /vault (vergine)")?;
    let vault = r.json()?;
    let server_vault_id = field_str(&vault, "vault_id")?;
    if server_vault_id != uuid_to_string(expected_vault_id) {
        return Err("vault_id da GET /vault ≠ registrazione (non persistito?)".into());
    }
    let vault_id = uuid_from_string(server_vault_id)?;

    // Elenca gli item, prende il primo e lo ridecifra con gli id recuperati dal server.
    let r = client.get("/v1/items", Some(&token))?;
    expect_status(&r, 200, "GET /items (vergine)")?;
    let items = r.json()?;
    let first = items
        .get("items")
        .and_then(|a| a.as_array())
        .and_then(|a| a.first())
        .ok_or("GET /items: nessun item da ridecifrare")?;
    let item_id = uuid_from_string(field_str(first, "id")?)?;
    let ciphertext = unb64(field_str(first, "ciphertext")?)?;
    let wrapped_cek = unb64(field_str(first, "wrapped_cek")?)?;
    let decrypted = vk
        .decrypt_item(&vault_id, &item_id, &ciphertext, &wrapped_cek)
        .map_err(ce)?;
    if decode_content(&decrypted).map_err(ce)? != *expected_plaintext {
        return Err("device vergine: plaintext ridecifrato ≠ originale".into());
    }
    vk.lock();
    log("7/8 device vergine → account_id/vault_id ricostruiti dal server, item ridecifrato");
    Ok(())
}

/// Sblocca un dispositivo "fresco" indipendente: login via password (deriva l'AV) + apertura
/// della busta password ricevuta dal server. Ogni chiamata produce una sessione e una
/// `VaultKey` proprie, come farebbero due dispositivi reali che condividono solo
/// email/password/Secret Key (mai un segreto di un dispositivo trasferito all'altro).
fn unlock_fresh_device(
    client: &Client,
    cfg: &GateConfig,
    secret_key: &[u8],
    account_id: &[u8; 16],
) -> Result<(VaultKey, String), String> {
    let password = cfg.password.as_bytes();
    let r = client.post_json(
        "/v1/auth/login/start",
        None,
        &serde_json::json!({ "email": cfg.email }),
    )?;
    expect_status(&r, 200, "login/start (sync)")?;
    let ls = r.json()?;
    let kdf = ls
        .get("kdf_params")
        .ok_or("login/start: kdf_params mancante")?;
    let salt: [u8; 16] = unb64(field_str(kdf, "salt")?)?
        .try_into()
        .map_err(|_| "salt kdf_params di lunghezza errata".to_string())?;
    let kdf_cbor = kdf_params::encode(&KdfParams::v1(salt)).map_err(ce)?;

    let av = derive_auth_verifier(password, secret_key, &kdf_cbor, account_id).map_err(ce)?;
    let r = client.post_json(
        "/v1/auth/login/finish",
        None,
        &serde_json::json!({ "email": cfg.email, "password_verifier": b64(&av[..]) }),
    )?;
    expect_status(&r, 200, "login/finish (sync)")?;
    let token = field_str(&r.json()?, "session_token")?.to_string();

    let r = client.get("/v1/envelopes", Some(&token))?;
    expect_status(&r, 200, "GET /envelopes (sync)")?;
    let password_envelope = find_password_envelope(&r.json()?)?;
    let vk = unlock_with_password(
        password,
        secret_key,
        &password_envelope,
        &kdf_cbor,
        account_id,
    )
    .map_err(ce)?;
    Ok((vk, token))
}

/// Cifra l'item di prova e lo carica con l'id dato (id scelto dal client, AAD legata).
fn upload_dummy_item(
    client: &Client,
    vk: &VaultKey,
    token: &str,
    vault_id: &[u8; 16],
    item_id: &[u8; 16],
) -> Result<(), String> {
    let cbor = encode_content(&sample_item()).map_err(ce)?;
    let (ciphertext, wrapped_cek) = vk.encrypt_item(vault_id, item_id, &cbor).map_err(ce)?;
    let r = client.post_json(
        "/v1/items",
        Some(token),
        &serde_json::json!({
            "id": uuid_to_string(item_id),
            "ciphertext": b64(&ciphertext),
            "wrapped_cek": b64(&wrapped_cek),
        }),
    )?;
    expect_status(&r, 201, "POST /items (sync)")?;
    Ok(())
}

/// Estrae i cambiamenti locali non ancora condivisi di `doc`, li cifra con la VK e li pubblica
/// (doc 20 §8, ADR-0022). Il server li conserva e li inoltra senza leggerli.
fn push_delta(
    client: &Client,
    vk: &VaultKey,
    token: &str,
    vault_id: &[u8; 16],
    doc: &mut SyncDoc,
) -> Result<(), String> {
    let encrypted = vk
        .encode_sync_delta(vault_id, &doc.take_pending_changes())
        .map_err(ce)?;
    let r = client.post_json(
        "/v1/sync/changes",
        Some(token),
        &serde_json::json!({ "changes": [{ "ciphertext": b64(&encrypted), "clock": "" }] }),
    )?;
    expect_status(&r, 202, "POST /sync/changes")?;
    Ok(())
}

/// Scarica tutti i delta del vault (una sola pagina: bastano per la dimostrazione del gate,
/// non è un loop di paginazione generico) e li applica a `doc`, restituendo la directory
/// convergente. Riapplicare un delta già noto (es. il proprio, scaricato dal server dopo
/// averlo pubblicato) è un no-op sicuro: Automerge deduplica per hash del change.
fn pull_all_deltas(
    client: &Client,
    vk: &VaultKey,
    token: &str,
    vault_id: &[u8; 16],
    doc: &mut SyncDoc,
) -> Result<MergeResult, String> {
    let r = client.get("/v1/sync/changes", Some(token))?;
    expect_status(&r, 200, "GET /sync/changes")?;
    let page = r.json()?;
    let items = page
        .get("items")
        .and_then(|v| v.as_array())
        .ok_or("GET /sync/changes: items mancante")?;
    let mut encrypted_deltas = Vec::with_capacity(items.len());
    for it in items {
        encrypted_deltas.push(unb64(field_str(it, "ciphertext")?)?);
    }
    vk.apply_sync_deltas(doc, vault_id, &encrypted_deltas)
        .map_err(ce)
}

/// Simula due dispositivi che editano **offline** voci diverse dello stesso vault, poi
/// convergono attraverso il server (che si limita a conservare e inoltrare i delta cifrati,
/// ADR-0022): ciascuno carica un item, registra la modifica nel proprio documento CRDT
/// locale, pubblica il delta e scarica quello dell'altro. Prova che la directory
/// (`item_id → versione`) converge identica su entrambi, indipendentemente dall'ordine di
/// applicazione (proprietà CRDT, non simulata: è la libreria Automerge reale).
fn verify_two_device_sync(
    client: &Client,
    cfg: &GateConfig,
    secret_key: &[u8],
    account_id: &[u8; 16],
    vault_id: &[u8; 16],
    log: &mut dyn FnMut(&str),
) -> Result<(), String> {
    let (vk_a, token_a) = unlock_fresh_device(client, cfg, secret_key, account_id)?;
    let (vk_b, token_b) = unlock_fresh_device(client, cfg, secret_key, account_id)?;

    let item_a = rand_id()?;
    upload_dummy_item(client, &vk_a, &token_a, vault_id, &item_a)?;
    let mut doc_a = SyncDoc::new();
    doc_a.record_item_change(&item_a, 1, false).map_err(ce)?;
    push_delta(client, &vk_a, &token_a, vault_id, &mut doc_a)?;

    let item_b = rand_id()?;
    upload_dummy_item(client, &vk_b, &token_b, vault_id, &item_b)?;
    let mut doc_b = SyncDoc::new();
    doc_b.record_item_change(&item_b, 1, false).map_err(ce)?;
    push_delta(client, &vk_b, &token_b, vault_id, &mut doc_b)?;

    let merged_a = pull_all_deltas(client, &vk_a, &token_a, vault_id, &mut doc_a)?;
    let merged_b = pull_all_deltas(client, &vk_b, &token_b, vault_id, &mut doc_b)?;
    if merged_a.items != merged_b.items {
        return Err(format!(
            "i due dispositivi non convergono: A={:?} B={:?}",
            merged_a.items, merged_b.items
        ));
    }
    if merged_a.items.len() != 2 {
        return Err(format!(
            "attese 2 voci nella directory convergente, trovate {}",
            merged_a.items.len()
        ));
    }
    vk_a.lock();
    vk_b.lock();
    log("8/8 sync CRDT → due dispositivi convergono sulla stessa directory (item_id→versione)");
    Ok(())
}

/// Estrae un campo stringa da un oggetto JSON, con errore esplicito se assente/non stringa.
fn field_str<'a>(v: &'a serde_json::Value, key: &str) -> Result<&'a str, String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("campo '{key}' mancante o non stringa nella risposta"))
}

/// Trova la busta di tipo "password" nella lista di `GET /envelopes` e ne decodifica i byte.
fn find_password_envelope(envelopes: &serde_json::Value) -> Result<Vec<u8>, String> {
    let arr = envelopes
        .as_array()
        .ok_or("GET /envelopes: attesa una lista")?;
    for e in arr {
        if e.get("type").and_then(|t| t.as_str()) == Some("password") {
            return unb64(field_str(e, "wrapped_vk")?);
        }
    }
    Err("busta 'password' assente fra le buste restituite".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &[u8] = b"tromba-cavallo-graffetta-corretta";

    // Self-check locale (senza server): prova che il giro crittografico su cui poggia il gate
    // funziona attraverso la superficie pubblica del core consumata dalla CLI —
    // registrazione → sblocco → cifratura item → decifratura — col plaintext identico.
    #[test]
    fn self_check_crittografico_locale() {
        let mut account_id = [0u8; 16];
        rng::fill(&mut account_id).unwrap();
        let mut bundle = register(PASSWORD, None, &account_id).unwrap();
        let vault_id = bundle.vault_id;
        let secret_key = bundle.emergency_kit.reveal_secret_key().unwrap();

        // Sblocco dalla busta password del bundle (come farebbe la CLI con la busta del server).
        let vk = unlock_with_password(
            PASSWORD,
            &secret_key[..],
            &bundle.password_envelope,
            &bundle.kdf_params_cbor,
            &account_id,
        )
        .unwrap();

        let item = sample_item();
        let cbor = encode_content(&item).unwrap();
        let mut item_id = [0u8; 16];
        rng::fill(&mut item_id).unwrap();
        let (ct, wcek) = vk.encrypt_item(&vault_id, &item_id, &cbor).unwrap();
        let got = vk.decrypt_item(&vault_id, &item_id, &ct, &wcek).unwrap();
        assert_eq!(decode_content(&got).unwrap(), item);

        // Il verificatore ri-derivato coincide con quello del bundle (parità register/login).
        let av = derive_auth_verifier(
            PASSWORD,
            &secret_key[..],
            &bundle.kdf_params_cbor,
            &account_id,
        )
        .unwrap();
        assert_eq!(av[..], bundle.auth_verifier[..]);
    }

    #[test]
    fn register_body_ha_i_campi_attesi() {
        let mut account_id = [0u8; 16];
        rng::fill(&mut account_id).unwrap();
        let bundle = register(PASSWORD, None, &account_id).unwrap();
        let body = register_body("e2e@example.com", &bundle, &account_id).unwrap();

        // Campi richiesti dal contratto register/finish (doc 12).
        for k in [
            "email",
            "account_id",
            "vault_id",
            "password_verifier",
            "kdf_params",
            "recovery_pubkey",
            "password_envelope",
            "recovery_envelope",
            "manifest",
            "manifest_pubkey",
            "signature",
            "wrapped_signing_key",
            "version",
        ] {
            assert!(body.get(k).is_some(), "manca il campo {k}");
        }
        // kdf_params è un oggetto coi parametri Argon2id + salt.
        let kp = &body["kdf_params"];
        assert!(kp.get("memory_kib").is_some());
        assert!(kp.get("salt").and_then(|s| s.as_str()).is_some());
        // La passkey è assente nel gate solo-password.
        assert!(body.get("passkey_envelope").is_none());
    }
}
