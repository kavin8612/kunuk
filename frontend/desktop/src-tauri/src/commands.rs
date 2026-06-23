//! Comandi Tauri di autenticazione (doc 20 §1): la VK e la Secret Key non attraversano mai
//! questo confine come byte di chiave riutilizzabili — solo conferme, o per la Secret Key
//! l'esposizione one-shot prevista da `EmergencyKit` (l'utente deve poterla copiare per
//! conservarla offline). Il CRUD voci è in `items.rs`.

use kunuk_crypto_core::crypto::kdf_params::{self, KdfParams};
use kunuk_crypto_core::sync::SyncDoc;
use kunuk_crypto_core::vault::manifest;
use kunuk_crypto_core::{derive_auth_verifier, register as core_register, unlock_with_password};
use serde::Serialize;
use tauri::State;

use crate::config::AppConfig;
use crate::session::{Session, UnlockedVault};
use crate::util::{
    b64, ce, client, expect_status, field_str, rand_id, unb64, uuid_from_string, uuid_to_string,
};

fn kdf_params_json(kdf_params_cbor: &[u8]) -> Result<serde_json::Value, String> {
    let kp = kdf_params::decode(kdf_params_cbor).map_err(ce)?;
    Ok(serde_json::json!({
        "memory_kib": kp.argon2.memory_kib,
        "iterations": kp.argon2.iterations,
        "parallelism": kp.argon2.parallelism,
        "salt": b64(&kp.salt[..]),
    }))
}

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

#[derive(Serialize)]
pub struct RegisterResult {
    /// Secret Key in chiaro: esposizione **one-shot** (`EmergencyKit::reveal_secret_key`).
    /// L'utente deve copiarla e conservarla offline; il comando non la persiste.
    pub secret_key: String,
}

/// Registra un nuovo account (email + master password) e sblocca subito il vault appena
/// creato (il comando ha già la busta password in memoria, niente round-trip aggiuntivo).
#[tauri::command]
pub fn register(
    config: State<AppConfig>,
    session: State<Session>,
    email: String,
    password: String,
) -> Result<RegisterResult, String> {
    let http = client(&config)?;
    let account_id = rand_id()?;
    let mut bundle = core_register(password.as_bytes(), None, &account_id).map_err(ce)?;
    let vault_id = bundle.vault_id;
    let secret_key = bundle.emergency_kit.reveal_secret_key().map_err(ce)?;

    let (manifest_body, signature) =
        manifest::split_signed_manifest(&bundle.signed_empty_manifest).map_err(ce)?;
    let body = serde_json::json!({
        "email": email,
        "account_id": uuid_to_string(&account_id),
        "vault_id": uuid_to_string(&vault_id),
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
    });
    let r = http.post_json("/v1/auth/register/finish", None, &body)?;
    expect_status(&r, 201, "registrazione")?;

    // Sblocco immediato dalla busta già in memoria (stesso processo di registrazione: non è
    // una persistenza locale della Secret Key, vive solo per questa sessione).
    let vk = unlock_with_password(
        password.as_bytes(),
        &secret_key[..],
        &bundle.password_envelope,
        &bundle.kdf_params_cbor,
        &account_id,
    )
    .map_err(ce)?;

    // register/finish non restituisce un token: serve un login esplicito (come la CLI, task
    // 0.10) per ottenere la sessione che autentica il CRUD voci (task 1.3/C2).
    let r = http.post_json(
        "/v1/auth/login/start",
        None,
        &serde_json::json!({ "email": email }),
    )?;
    expect_status(&r, 200, "login/start (post-registrazione)")?;
    let av = derive_auth_verifier(
        password.as_bytes(),
        &secret_key[..],
        &bundle.kdf_params_cbor,
        &account_id,
    )
    .map_err(ce)?;
    let r = http.post_json(
        "/v1/auth/login/finish",
        None,
        &serde_json::json!({ "email": email, "password_verifier": b64(&av[..]) }),
    )?;
    expect_status(&r, 200, "login/finish (post-registrazione)")?;
    let token = field_str(&r.json()?, "session_token")?.to_string();

    *session
        .unlocked
        .lock()
        .map_err(|_| "stato sessione corrotto")? = Some(UnlockedVault {
        vault_id,
        vk,
        token,
        wrapped_signing_key: bundle.wrapped_signing_key,
        sync_doc: SyncDoc::new(),
        manifest_version: 1, // il manifest vuoto della registrazione è già alla versione 1
        sync_cursor: None,
    });
    session.touch();

    Ok(RegisterResult {
        secret_key: b64(&secret_key[..]),
    })
}

/// Accede con email + master password + Secret Key (2SKD, doc 16 §3) e sblocca il vault.
/// In questo taglio (C1) la Secret Key va fornita ad ogni login: nessuna persistenza locale
/// (device-key/OS keychain è un sotto-passo successivo).
#[tauri::command]
pub fn login(
    config: State<AppConfig>,
    session: State<Session>,
    email: String,
    password: String,
    secret_key: String,
) -> Result<(), String> {
    let http = client(&config)?;
    let secret_key = unb64(&secret_key)?;

    let r = http.post_json(
        "/v1/auth/login/start",
        None,
        &serde_json::json!({ "email": email }),
    )?;
    expect_status(&r, 200, "login/start")?;
    let ls = r.json()?;
    let account_id = uuid_from_string(field_str(&ls, "account_id")?)?;
    let kdf = ls
        .get("kdf_params")
        .ok_or("login/start: kdf_params mancante")?;
    let salt: [u8; 16] = unb64(field_str(kdf, "salt")?)?
        .try_into()
        .map_err(|_| "salt kdf_params di lunghezza errata".to_string())?;
    let kdf_cbor = kdf_params::encode(&KdfParams::v1(salt)).map_err(ce)?;

    let av = derive_auth_verifier(password.as_bytes(), &secret_key, &kdf_cbor, &account_id)
        .map_err(ce)?;
    let r = http.post_json(
        "/v1/auth/login/finish",
        None,
        &serde_json::json!({ "email": email, "password_verifier": b64(&av[..]) }),
    )?;
    expect_status(&r, 200, "login/finish")?;
    let token = field_str(&r.json()?, "session_token")?.to_string();

    let r = http.get("/v1/envelopes", Some(&token))?;
    expect_status(&r, 200, "GET /envelopes")?;
    let password_envelope = find_password_envelope(&r.json()?)?;
    let vk = unlock_with_password(
        password.as_bytes(),
        &secret_key,
        &password_envelope,
        &kdf_cbor,
        &account_id,
    )
    .map_err(ce)?;

    // GET /vault: vault_id (ADR-0020) + manifest firmato + wrapped_signing_key (task 1.3/C2,
    // stesso principio di ADR-0020). Il manifest si verifica subito (fail-closed, doc 16 §6):
    // un login non deve fidarsi di un manifest con firma non valida o vault_id inatteso.
    let r = http.get("/v1/vault", Some(&token))?;
    expect_status(&r, 200, "GET /vault")?;
    let vault = r.json()?;
    let vault_id = uuid_from_string(field_str(&vault, "vault_id")?)?;
    let manifest_pubkey: [u8; 32] = unb64(field_str(&vault, "manifest_pubkey")?)?
        .try_into()
        .map_err(|_| "manifest_pubkey di lunghezza errata".to_string())?;
    let mut signed = unb64(field_str(&vault, "manifest")?)?;
    signed.extend_from_slice(&unb64(field_str(&vault, "signature")?)?);
    let view = manifest::verify_manifest_with_pubkey(&manifest_pubkey, &signed, &vault_id, 0)
        .map_err(ce)?;
    let wrapped_signing_key = unb64(field_str(&vault, "wrapped_signing_key")?)?;

    *session
        .unlocked
        .lock()
        .map_err(|_| "stato sessione corrotto")? = Some(UnlockedVault {
        vault_id,
        vk,
        token,
        wrapped_signing_key,
        sync_doc: SyncDoc::new(),
        manifest_version: view.version,
        sync_cursor: None,
    });
    session.touch();
    Ok(())
}

/// Blocca il vault: azzera la VK (consumata da `VaultKey::lock`) e svuota lo stato sessione.
#[tauri::command]
pub fn lock(session: State<Session>) -> Result<(), String> {
    let mut guard = session
        .unlocked
        .lock()
        .map_err(|_| "stato sessione corrotto")?;
    if let Some(unlocked) = guard.take() {
        unlocked.vk.lock();
    }
    Ok(())
}

/// Vero se il vault è sbloccato in questa sessione (per la UI React al primo render).
#[tauri::command]
pub fn is_unlocked(session: State<Session>) -> Result<bool, String> {
    Ok(session
        .unlocked
        .lock()
        .map_err(|_| "stato sessione corrotto")?
        .is_some())
}
