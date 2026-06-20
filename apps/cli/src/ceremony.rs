//! Cerimonia end-to-end del gate Fase 0 (task 0.10).
//!
//! Concatena i flussi della fondamenta con crittografia **vera** prodotta dal crypto-core e
//! storage **opaco** sul backend: registrazione → login → sblocco → upload di un item cifrato
//! → rilettura e decifratura → verifica del manifest firmato. Prova end-to-end lo
//! zero-knowledge (SR-21/25): il server conserva e restituisce ciphertext byte-identico, mai
//! plaintext né chiavi.
//!
//! `account_id` e `vault_id` sono scelti/tenuti dal client in memoria per l'intera cerimonia
//! (opzione del gate; la lacuna multi-dispositivo è registrata nel doc 22).

use kunuk_crypto_core::crypto::{kdf_params, rng};
use kunuk_crypto_core::vault::item::{decode_content, encode_content, ItemContent};
use kunuk_crypto_core::vault::manifest;
use kunuk_crypto_core::{derive_auth_verifier, register, unlock_with_password, RegistrationBundle};

use crate::api::{Client, Resp};
use crate::codec::{b64, unb64, uuid_to_string};

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
    ItemContent::Login {
        username: "alice@example.com".into(),
        password: "tromba-cavallo-graffetta-7".into(),
        uris: vec!["https://example.com/login".into()],
        notes: "creata dal gate 0.10".into(),
    }
}

/// Corpo di `POST /v1/auth/register/finish` dal bundle (campi piatti, doc 12). La passkey è
/// assente (gate solo-password). `manifest`/`signature` sono lo `signed_empty_manifest` scisso.
fn register_body(email: &str, bundle: &RegistrationBundle) -> Result<serde_json::Value, String> {
    let (manifest_body, signature) =
        manifest::split_signed_manifest(&bundle.signed_empty_manifest).map_err(ce)?;
    Ok(serde_json::json!({
        "email": email,
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

    let body = register_body(&cfg.email, &bundle)?;
    let r = client.post_json("/v1/auth/register/finish", None, &body)?;
    expect_status(&r, 201, "registrazione")?;
    log("1/6 registrazione → 201 (bundle opaco caricato)");

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
    log("2/6 login → token di sessione ottenuto");

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
    log("3/6 sblocco → VaultKey aperta dalla busta restituita dal server");

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
    log("4/6 upload → item cifrato caricato (id scelto dal client)");

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
    log("5/6 decifratura → plaintext identico all'originale (zero-knowledge)");

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
    log("6/6 manifest → firma valida, versione 1, pubkey pinned coincide");

    vk.lock();
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
        let body = register_body("e2e@example.com", &bundle).unwrap();

        // Campi richiesti dal contratto register/finish (doc 12).
        for k in [
            "email",
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
