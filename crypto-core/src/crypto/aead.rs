//! AEAD XChaCha20-Poly1305 (doc 16 §1, §7).
//!
//! Nonce a 24 byte forniti dal chiamante (mai derivati né riusati: la generazione
//! CSPRNG vive al task 0.5). Un tag o un'AAD non validi danno sempre `DecryptFailed`,
//! senza distinguere la causa (anti-oracolo, doc 16 §7).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

use crate::crypto::params::KEY_LEN;
use crate::error::{CoreError, CoreResult};

/// Lunghezza del nonce XChaCha20 in byte (doc 16 §4).
pub const NONCE_LEN: usize = 24;

/// Cifra `plaintext` legandolo crittograficamente all'`aad`. Ritorna
/// `ciphertext || tag`.
pub fn encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> CoreResult<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CoreError::Internal)
}

/// Decifra e verifica `ciphertext || tag` con l'`aad`. Fallisce con `DecryptFailed`
/// se tag, AAD o formato non verificano (doc 16 §7).
pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> CoreResult<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CoreError::DecryptFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CoreError;

    const KEY: [u8; KEY_LEN] = [0x42; KEY_LEN];
    const NONCE: [u8; NONCE_LEN] = [0x24; NONCE_LEN];

    #[test]
    fn round_trip() {
        let ct = encrypt(&KEY, &NONCE, b"aad", b"messaggio segreto").unwrap();
        let pt = decrypt(&KEY, &NONCE, b"aad", &ct).unwrap();
        assert_eq!(pt, b"messaggio segreto");
    }

    #[test]
    fn tag_manomesso_decrypt_failed() {
        let mut ct = encrypt(&KEY, &NONCE, b"aad", b"messaggio segreto").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(matches!(
            decrypt(&KEY, &NONCE, b"aad", &ct),
            Err(CoreError::DecryptFailed)
        ));
    }

    #[test]
    fn aad_diversa_decrypt_failed() {
        let ct = encrypt(&KEY, &NONCE, b"aad", b"messaggio segreto").unwrap();
        assert!(matches!(
            decrypt(&KEY, &NONCE, b"aad-diversa", &ct),
            Err(CoreError::DecryptFailed)
        ));
    }
}
