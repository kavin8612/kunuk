//! Recupero della master password (ADR-0010, doc 05 §5).
//!
//! Due operazioni indipendenti, entrambe basate sulla sola **Secret Key** (Emergency Kit):
//! la **prova di possesso** — il client firma la richiesta di recupero con la chiave
//! privata `RKa` derivata dalla Secret Key, il server verifica con la pubblica registrata
//! (senza questa firma il ritardo anti-abuso non parte nemmeno) — e l'**apertura della
//! busta di recupero** (`recover_unlock`), che dopo il ritardo libera la VK. La Secret Key
//! non viaggia mai: viaggiano solo la firma e, alla fine, la VK in memoria locale.
//!
//! La firma copre un **prefisso di dominio** (`"kunuk/v1/recovery-request"`) così che `RKa`
//! non possa mai produrre una firma confondibile con un altro tipo di oggetto
//! (domain separation, come il manifest in doc 16 §6).

use ed25519_dalek::VerifyingKey;

use crate::account::VaultKey;
use crate::crypto::signature::{self, SIGNATURE_LEN};
use crate::envelope::{self, EnvelopeType, ACCOUNT_ID_LEN, EMPTY_KDF_PARAMS_CBOR};
use crate::error::{CoreError, CoreResult};
use crate::keys;

/// Prefisso di dominio dell'input firmato della richiesta di recupero (doc 16 §6,
/// sotto-formato "richiesta di recupero"). La chiave `RKa` firma solo sotto questa
/// etichetta: il `/v1/` lega la versione (anti-downgrade) e impedisce la confusione di
/// firme se in futuro `RKa` dovesse firmare altro.
const RECOVERY_REQUEST_LABEL: &[u8] = b"kunuk/v1/recovery-request";

/// Input firmato: `"kunuk/v1/recovery-request" ‖ request_bytes`. L'anti-replay (nonce,
/// timestamp) vive **dentro** `request_bytes`, costruito dal chiamante e controllato dal
/// server: non è compito della primitiva di firma.
fn signing_input(request_bytes: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(RECOVERY_REQUEST_LABEL.len() + request_bytes.len());
    input.extend_from_slice(RECOVERY_REQUEST_LABEL);
    input.extend_from_slice(request_bytes);
    input
}

/// Firma la richiesta di recupero come prova di possesso della Secret Key (doc 05 §5). La
/// chiave privata `RKa` è derivata dalla sola Secret Key (doc 16 §3) e non lascia il
/// client: viaggia solo la firma a 64 byte.
pub fn recovery_sign_request(
    secret_key: &[u8],
    request_bytes: &[u8],
) -> CoreResult<[u8; SIGNATURE_LEN]> {
    let (signing_key, _) = keys::rk_auth_keypair(secret_key)?;
    Ok(signature::sign(&signing_key, &signing_input(request_bytes)))
}

/// Verifica la firma della richiesta di recupero con la pubblica `RKa` registrata alla
/// creazione dell'account (doc 05 §5). Pubblica malformata → `InvalidInput`; firma non
/// valida o richiesta alterata → `AuthFailed`. È la verifica che il backend (o un suo
/// binding) applica prima di avviare il ritardo.
pub fn recovery_verify_request(
    recovery_pubkey: &[u8; 32],
    request_bytes: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> CoreResult<()> {
    let verifying_key =
        VerifyingKey::from_bytes(recovery_pubkey).map_err(|_| CoreError::InvalidInput)?;
    signature::verify(&verifying_key, &signing_input(request_bytes), signature)
}

/// Apre la busta di recupero con la sola Secret Key (doc 05 §5) e restituisce il
/// [`VaultKey`]. È il passo finale del recupero, dopo che il server ha consumato il ritardo
/// senza annullamento. Secret Key errata, account diverso o busta manomessa →
/// `DecryptFailed` (fail-closed, doc 16 §7).
pub fn recover_unlock(
    secret_key: &[u8],
    recovery_envelope: &[u8],
    account_id: &[u8; ACCOUNT_ID_LEN],
) -> CoreResult<VaultKey> {
    let rk_wrap = keys::rk_wrap_key(secret_key)?;
    let vk = envelope::unwrap(
        &rk_wrap,
        recovery_envelope,
        account_id,
        EnvelopeType::Recovery,
        EMPTY_KDF_PARAMS_CBOR,
    )?;
    Ok(VaultKey::new(vk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::registration::{register_with, RegistrationRandomness};
    use crate::crypto::aead::NONCE_LEN;
    use crate::crypto::params::{ARGON2_SALT_LEN, KEY_LEN, SECRET_KEY_LEN};
    use crate::vault::item::ID_LEN;

    const PASSWORD: &[u8] = b"correct horse battery staple";
    const SECRET_KEY: [u8; SECRET_KEY_LEN] = [0xA1; SECRET_KEY_LEN];
    const VAULT_ID: [u8; ID_LEN] = [0x66; ID_LEN];
    const VK: [u8; KEY_LEN] = [0x22; KEY_LEN];
    const SIGNING_SEED: [u8; KEY_LEN] = [0x44; KEY_LEN];
    const SALT_PK: [u8; ARGON2_SALT_LEN] = [0x07; ARGON2_SALT_LEN];
    const ACCOUNT: [u8; ACCOUNT_ID_LEN] = [0x10; ACCOUNT_ID_LEN];
    const REQUEST: &[u8] = b"account=10;ts=1700000000;nonce=deadbeef";
    const N_PW: [u8; NONCE_LEN] = [0x01; NONCE_LEN];
    const N_PK: [u8; NONCE_LEN] = [0x02; NONCE_LEN];
    const N_RK: [u8; NONCE_LEN] = [0x03; NONCE_LEN];
    const N_SK: [u8; NONCE_LEN] = [0x04; NONCE_LEN];

    fn recovery_envelope() -> Vec<u8> {
        let rnd = RegistrationRandomness {
            secret_key: &SECRET_KEY,
            vault_id: &VAULT_ID,
            vk: &VK,
            signing_seed: &SIGNING_SEED,
            salt_pk: &SALT_PK,
            password_nonce: &N_PW,
            passkey_nonce: &N_PK,
            recovery_nonce: &N_RK,
            signing_key_nonce: &N_SK,
        };
        register_with(PASSWORD, None, &ACCOUNT, &rnd)
            .unwrap()
            .recovery_envelope
    }

    #[test]
    fn recover_unlock_restituisce_la_vk() {
        let env = recovery_envelope();
        let vk = recover_unlock(&SECRET_KEY, &env, &ACCOUNT).unwrap();
        assert_eq!(vk.expose(), &VK);
    }

    #[test]
    fn recover_unlock_secret_key_errata_decrypt_failed() {
        let env = recovery_envelope();
        assert!(matches!(
            recover_unlock(&[0xFF; SECRET_KEY_LEN], &env, &ACCOUNT),
            Err(CoreError::DecryptFailed)
        ));
    }

    #[test]
    fn recover_unlock_altro_account_decrypt_failed() {
        let env = recovery_envelope();
        assert!(matches!(
            recover_unlock(&SECRET_KEY, &env, &[0x99; ACCOUNT_ID_LEN]),
            Err(CoreError::DecryptFailed)
        ));
    }

    #[test]
    fn firma_e_verifica_round_trip() {
        let sig = recovery_sign_request(&SECRET_KEY, REQUEST).unwrap();
        let (_, pubkey) = keys::rk_auth_keypair(&SECRET_KEY).unwrap();
        assert!(recovery_verify_request(&pubkey.to_bytes(), REQUEST, &sig).is_ok());
    }

    #[test]
    fn firma_deterministica() {
        // Ed25519 è deterministico (RFC 8032): stessa Secret Key e richiesta → stessa firma.
        let a = recovery_sign_request(&SECRET_KEY, REQUEST).unwrap();
        let b = recovery_sign_request(&SECRET_KEY, REQUEST).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn verifica_richiesta_alterata_auth_failed() {
        let sig = recovery_sign_request(&SECRET_KEY, REQUEST).unwrap();
        let (_, pubkey) = keys::rk_auth_keypair(&SECRET_KEY).unwrap();
        // La firma copre prefisso ‖ richiesta: cambiando la richiesta la verifica fallisce.
        assert!(matches!(
            recovery_verify_request(
                &pubkey.to_bytes(),
                b"account=10;ts=1700000000;nonce=00000000",
                &sig
            ),
            Err(CoreError::AuthFailed)
        ));
    }

    #[test]
    fn verifica_con_altra_secret_key_auth_failed() {
        let sig = recovery_sign_request(&SECRET_KEY, REQUEST).unwrap();
        // Pubblica derivata da una Secret Key diversa: la prova di possesso non regge.
        let (_, altra_pub) = keys::rk_auth_keypair(&[0xB2; SECRET_KEY_LEN]).unwrap();
        assert!(matches!(
            recovery_verify_request(&altra_pub.to_bytes(), REQUEST, &sig),
            Err(CoreError::AuthFailed)
        ));
    }
}
