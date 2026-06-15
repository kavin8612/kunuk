//! Derivazioni di chiave con domain separation (doc 16 §3).
//!
//! A partire da `password ‖ Secret Key` / Secret Key / DK si ottengono le chiavi di
//! wrapping e il seme di firma del recupero, ciascuno legato a un'etichetta distinta:
//! così la stessa radice non produce mai due chiavi confondibili. La generazione della
//! VK/CEK (CSPRNG) e l'uso delle buste arrivano ai task 0.5–0.6.

use ed25519_dalek::{SigningKey, VerifyingKey};
use zeroize::Zeroizing;

use crate::crypto::params::{
    ARGON2_V1, KEY_LEN, LABEL_AUTH_VERIFIER, LABEL_DK_WRAP, LABEL_PK_WRAP, LABEL_PRF_WRAP,
    LABEL_RK_AUTH, LABEL_RK_WRAP, PRF_OUTPUT_LEN, SECRET_KEY_LEN,
};
use crate::crypto::{argon2id, kdf, signature};
use crate::envelope::ACCOUNT_ID_LEN;
use crate::error::{CoreError, CoreResult};

/// Stretching 2SKD condiviso da PK e dal verificatore AV (doc 16 §3):
/// `Argon2id(password ‖ Secret Key, salt)`. L'input è la master password concatenata
/// alla Secret Key, mai la sola password; la Secret Key deve essere lunga
/// `SECRET_KEY_LEN` (ADR-0006), così la concatenazione è non ambigua (un confine
/// variabile permetterebbe a split diversi di produrre la stessa radice).
fn stretch_2skd(
    password: &[u8],
    secret_key: &[u8],
    salt: &[u8],
) -> CoreResult<Zeroizing<[u8; KEY_LEN]>> {
    if secret_key.len() != SECRET_KEY_LEN {
        return Err(CoreError::InvalidInput);
    }
    let mut input = Zeroizing::new(Vec::with_capacity(password.len() + secret_key.len()));
    input.extend_from_slice(password);
    input.extend_from_slice(secret_key);
    argon2id::derive(input.as_slice(), salt, &ARGON2_V1)
}

/// Chiave-password PK: `HKDF(stretched, "kunuk/v1/pk/wrap")`, con
/// `stretched = Argon2id(password ‖ Secret Key, salt_pk)` (2SKD, doc 16 §3).
pub fn pk_from_password(
    password: &[u8],
    secret_key: &[u8],
    salt_pk: &[u8],
) -> CoreResult<Zeroizing<[u8; KEY_LEN]>> {
    let stretched = stretch_2skd(password, secret_key, salt_pk)?;
    kdf::hkdf_sha256(stretched.as_slice(), LABEL_PK_WRAP)
}

/// Verificatore di autenticazione AV della via password (doc 16 §3):
/// `HKDF(stretched, "kunuk/v1/auth/verifier" ‖ account_id)`. Stessa radice `stretched`
/// di PK ma etichetta distinta (domain separation) **legata all'account**: viene inviato
/// al server (che ne memorizza un hash), è distinto da PK e non reversibile a
/// password/Secret Key.
pub fn auth_verifier(
    password: &[u8],
    secret_key: &[u8],
    salt: &[u8],
    account_id: &[u8; ACCOUNT_ID_LEN],
) -> CoreResult<Zeroizing<[u8; KEY_LEN]>> {
    let stretched = stretch_2skd(password, secret_key, salt)?;
    let mut info = Vec::with_capacity(LABEL_AUTH_VERIFIER.len() + ACCOUNT_ID_LEN);
    info.extend_from_slice(LABEL_AUTH_VERIFIER);
    info.extend_from_slice(account_id);
    kdf::hkdf_sha256(stretched.as_slice(), &info)
}

/// Chiave di wrapping della busta passkey PRFw: `HKDF(prf_output, "kunuk/v1/prf/wrap")`
/// (doc 16 §3). L'`prf_output` arriva dall'estensione WebAuthn PRF dell'autenticatore
/// (mai fuori da esso) ed è già ad alta entropia: nessuno stretching Argon2id. Deve
/// essere lungo `PRF_OUTPUT_LEN`: un input vuoto/troncato deriverebbe una chiave di
/// wrapping a bassa entropia, quindi è rifiutato al confine del core.
pub fn prf_wrap_key(prf_output: &[u8]) -> CoreResult<Zeroizing<[u8; KEY_LEN]>> {
    if prf_output.len() != PRF_OUTPUT_LEN {
        return Err(CoreError::InvalidInput);
    }
    kdf::hkdf_sha256(prf_output, LABEL_PRF_WRAP)
}

/// Chiave di wrapping del recupero RKw: `HKDF(RK, "kunuk/v1/rk/wrap")` (doc 16 §3).
pub fn rk_wrap_key(rk: &[u8]) -> CoreResult<Zeroizing<[u8; KEY_LEN]>> {
    kdf::hkdf_sha256(rk, LABEL_RK_WRAP)
}

/// Chiave di wrapping della device key DKw: `HKDF(DK, "kunuk/v1/dk/wrap")`
/// (doc 16 §3).
pub fn dk_wrap_key(dk: &[u8]) -> CoreResult<Zeroizing<[u8; KEY_LEN]>> {
    kdf::hkdf_sha256(dk, LABEL_DK_WRAP)
}

/// Coppia Ed25519 di prova-di-possesso del recupero, dal seme
/// `RKa = HKDF(RK, "kunuk/v1/rk/auth")` (doc 16 §3). La privata non lascia il
/// client; la pubblica si registra alla creazione dell'account.
pub fn rk_auth_keypair(rk: &[u8]) -> CoreResult<(SigningKey, VerifyingKey)> {
    let seed = kdf::hkdf_sha256(rk, LABEL_RK_AUTH)?;
    Ok(signature::keypair_from_seed(&seed))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Secret Key di test, lunghezza fissa SECRET_KEY_LEN (ADR-0006).
    const SK_A: [u8; SECRET_KEY_LEN] = [0xA1; SECRET_KEY_LEN];
    const SK_B: [u8; SECRET_KEY_LEN] = [0xB2; SECRET_KEY_LEN];
    // Radice a 32 byte (lunghezza dell'output WebAuthn PRF), riusabile anche per RKw/DKw.
    const ROOT32: [u8; PRF_OUTPUT_LEN] = [0x5A; PRF_OUTPUT_LEN];

    #[test]
    fn pk_deterministica() {
        let a = pk_from_password(b"password", &SK_A, &[0x07; 16]).unwrap();
        let b = pk_from_password(b"password", &SK_A, &[0x07; 16]).unwrap();
        assert_eq!(*a, *b);
    }

    #[test]
    fn pk_dipende_dalla_secret_key() {
        // 2SKD: stessa password, Secret Key diversa ⇒ PK diversa.
        let a = pk_from_password(b"password", &SK_A, &[0x07; 16]).unwrap();
        let b = pk_from_password(b"password", &SK_B, &[0x07; 16]).unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn pk_rifiuta_secret_key_di_lunghezza_errata() {
        // Concatenazione non ambigua solo con Secret Key di lunghezza fissa (ADR-0006).
        assert!(matches!(
            pk_from_password(b"password", &[0x01; SECRET_KEY_LEN - 1], &[0x07; 16]),
            Err(CoreError::InvalidInput)
        ));
        assert!(matches!(
            pk_from_password(b"password", &[0x01; SECRET_KEY_LEN + 1], &[0x07; 16]),
            Err(CoreError::InvalidInput)
        ));
    }

    const ACCOUNT_A: [u8; ACCOUNT_ID_LEN] = [0x10; ACCOUNT_ID_LEN];
    const ACCOUNT_B: [u8; ACCOUNT_ID_LEN] = [0x20; ACCOUNT_ID_LEN];

    #[test]
    fn av_deterministico() {
        let a = auth_verifier(b"password", &SK_A, &[0x07; 16], &ACCOUNT_A).unwrap();
        let b = auth_verifier(b"password", &SK_A, &[0x07; 16], &ACCOUNT_A).unwrap();
        assert_eq!(*a, *b);
    }

    #[test]
    fn av_dipende_dalla_secret_key() {
        let a = auth_verifier(b"password", &SK_A, &[0x07; 16], &ACCOUNT_A).unwrap();
        let b = auth_verifier(b"password", &SK_B, &[0x07; 16], &ACCOUNT_A).unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn av_dipende_dall_account() {
        // Binding all'account: stessi password/SK/salt, account diverso ⇒ AV diverso.
        let a = auth_verifier(b"password", &SK_A, &[0x07; 16], &ACCOUNT_A).unwrap();
        let b = auth_verifier(b"password", &SK_A, &[0x07; 16], &ACCOUNT_B).unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn av_diverso_da_pk() {
        // Stessa radice (stessi password/SK/salt) ma etichette diverse ⇒ AV ≠ PK.
        let pk = pk_from_password(b"password", &SK_A, &[0x07; 16]).unwrap();
        let av = auth_verifier(b"password", &SK_A, &[0x07; 16], &ACCOUNT_A).unwrap();
        assert_ne!(*pk, *av);
    }

    #[test]
    fn av_rifiuta_secret_key_di_lunghezza_errata() {
        assert!(matches!(
            auth_verifier(
                b"password",
                &[0x01; SECRET_KEY_LEN - 1],
                &[0x07; 16],
                &ACCOUNT_A
            ),
            Err(CoreError::InvalidInput)
        ));
    }

    #[test]
    fn radice_uguale_etichette_diverse_chiavi_diverse() {
        // PRFw, RKw e DKw dalla stessa radice devono differire (domain separation).
        let prfw = prf_wrap_key(&ROOT32).unwrap();
        let rkw = rk_wrap_key(&ROOT32).unwrap();
        let dkw = dk_wrap_key(&ROOT32).unwrap();
        assert_ne!(*prfw, *rkw);
        assert_ne!(*prfw, *dkw);
        assert_ne!(*rkw, *dkw);
    }

    #[test]
    fn prf_wrap_key_deterministica() {
        let a = prf_wrap_key(&ROOT32).unwrap();
        let b = prf_wrap_key(&ROOT32).unwrap();
        assert_eq!(*a, *b);
    }

    #[test]
    fn prf_wrap_key_rifiuta_lunghezza_errata() {
        // Un output PRF vuoto/troncato deriverebbe una chiave a bassa entropia.
        assert!(matches!(prf_wrap_key(&[]), Err(CoreError::InvalidInput)));
        assert!(matches!(
            prf_wrap_key(&[0x5A; PRF_OUTPUT_LEN - 1]),
            Err(CoreError::InvalidInput)
        ));
    }

    #[test]
    fn rk_auth_keypair_deterministica() {
        let (_, pub_a) = rk_auth_keypair(b"recovery-key").unwrap();
        let (_, pub_b) = rk_auth_keypair(b"recovery-key").unwrap();
        assert_eq!(pub_a.to_bytes(), pub_b.to_bytes());
    }
}
