//! Derivazioni di chiave con domain separation (doc 16 §3).
//!
//! A partire da `export_key`/RK/DK si ottengono le chiavi di wrapping e il seme di
//! firma del recupero, ciascuno legato a un'etichetta distinta: così la stessa
//! radice non produce mai due chiavi confondibili. La generazione della VK/CEK
//! (CSPRNG) e l'uso delle buste arrivano ai task 0.5–0.6.

use ed25519_dalek::{SigningKey, VerifyingKey};
use zeroize::Zeroizing;

use crate::crypto::params::{
    ARGON2_V1, KEY_LEN, LABEL_DK_WRAP, LABEL_PK_WRAP, LABEL_RK_AUTH, LABEL_RK_WRAP,
};
use crate::crypto::{argon2id, kdf, signature};
use crate::error::CoreResult;

/// Chiave-password PK: `HKDF(Argon2id(export_key, salt_pk), "kunuk/v1/pk/wrap")`
/// (doc 16 §3).
pub fn pk_from_export_key(
    export_key: &[u8],
    salt_pk: &[u8],
) -> CoreResult<Zeroizing<[u8; KEY_LEN]>> {
    let stretched = argon2id::derive(export_key, salt_pk, &ARGON2_V1)?;
    kdf::hkdf_sha256(stretched.as_slice(), LABEL_PK_WRAP)
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

    #[test]
    fn pk_deterministica() {
        let a = pk_from_export_key(b"export-key", &[0x07; 16]).unwrap();
        let b = pk_from_export_key(b"export-key", &[0x07; 16]).unwrap();
        assert_eq!(*a, *b);
    }

    #[test]
    fn radice_uguale_etichette_diverse_chiavi_diverse() {
        // RKw e DKw dalla stessa radice devono differire (domain separation).
        let rkw = rk_wrap_key(b"stessa-radice").unwrap();
        let dkw = dk_wrap_key(b"stessa-radice").unwrap();
        assert_ne!(*rkw, *dkw);
    }

    #[test]
    fn rk_auth_keypair_deterministica() {
        let (_, pub_a) = rk_auth_keypair(b"recovery-key").unwrap();
        let (_, pub_b) = rk_auth_keypair(b"recovery-key").unwrap();
        assert_eq!(pub_a.to_bytes(), pub_b.to_bytes());
    }
}
