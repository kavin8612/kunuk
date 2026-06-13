//! Firma Ed25519 (doc 16 §1, §6).
//!
//! Deterministica (RFC 8032). Usata per il manifest del vault e per la
//! prova-di-possesso del recupero (doc 16 §3). La conformità all'RFC 8032 è
//! verificata dal test vettoriale qui sotto (Test 1).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::error::{CoreError, CoreResult};

/// Lunghezza di una firma Ed25519 in byte.
pub const SIGNATURE_LEN: usize = 64;

/// Costruisce la coppia di chiavi dal seme a 32 byte (deterministico).
pub fn keypair_from_seed(seed: &[u8; 32]) -> (SigningKey, VerifyingKey) {
    let signing = SigningKey::from_bytes(seed);
    let verifying = signing.verifying_key();
    (signing, verifying)
}

/// Firma `msg` con la chiave privata. Output a 64 byte.
pub fn sign(signing_key: &SigningKey, msg: &[u8]) -> [u8; SIGNATURE_LEN] {
    signing_key.sign(msg).to_bytes()
}

/// Verifica la firma `sig` di `msg` con la chiave pubblica. Fallisce con
/// `AuthFailed` se la firma non è valida.
pub fn verify(
    verifying_key: &VerifyingKey,
    msg: &[u8],
    sig: &[u8; SIGNATURE_LEN],
) -> CoreResult<()> {
    let signature = Signature::from_bytes(sig);
    verifying_key
        .verify_strict(msg, &signature)
        .map_err(|_| CoreError::AuthFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8032 §7.1, Test 1 (Ed25519): ancora di correttezza indipendente.
    const SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    const PUBKEY: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];
    const SIG: [u8; 64] = [
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82,
        0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49,
        0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c,
        0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43,
        0x8e, 0x7a, 0x10, 0x0b,
    ];

    #[test]
    fn rfc8032_test1() {
        let (signing, verifying) = keypair_from_seed(&SEED);
        assert_eq!(verifying.to_bytes(), PUBKEY);
        assert_eq!(sign(&signing, b""), SIG);
        assert!(verify(&verifying, b"", &SIG).is_ok());
    }

    #[test]
    fn firma_su_messaggio_diverso_fallisce() {
        let (_, verifying) = keypair_from_seed(&SEED);
        assert!(matches!(
            verify(&verifying, b"altro messaggio", &SIG),
            Err(CoreError::AuthFailed)
        ));
    }
}
