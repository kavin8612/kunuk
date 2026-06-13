//! Header comune dei formati serializzati (doc 16 §2).
//!
//! Quattro byte all'inizio di ogni oggetto cifrato o firmato: magic, version, suite.
//! L'header è sempre incluso nell'AAD, così manometterlo invalida il tag. Regole
//! fail-closed (anti-downgrade): magic errato o version/suite sconosciute → rifiuto,
//! senza alcun fallback.

use crate::error::{CoreError, CoreResult};

/// Magic dei formati Kunuk: ASCII "KN".
pub const MAGIC: [u8; 2] = [0x4B, 0x4E];

/// Versione di formato corrente.
pub const VERSION_V1: u8 = 0x01;

/// Suite crittografica corrente (0x01: Argon2id, HKDF-SHA-256, XChaCha20-Poly1305,
/// Ed25519).
pub const SUITE_V1: u8 = 0x01;

/// Lunghezza dell'header comune in byte.
pub const HEADER_LEN: usize = 4;

/// Header comune v1 (suite 0x01).
pub fn header_v1() -> [u8; HEADER_LEN] {
    [MAGIC[0], MAGIC[1], VERSION_V1, SUITE_V1]
}

/// Verifica i primi `HEADER_LEN` byte di `data` (doc 16 §2). Fail-closed: dati troppo
/// corti o magic diverso → `InvalidInput`; version o suite sconosciute →
/// `UnsupportedVersion` (anti-downgrade, nessun fallback).
pub fn verify(data: &[u8]) -> CoreResult<()> {
    if data.len() < HEADER_LEN || data[0..2] != MAGIC {
        return Err(CoreError::InvalidInput);
    }
    if data[2] != VERSION_V1 || data[3] != SUITE_V1 {
        return Err(CoreError::UnsupportedVersion);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_valido_verifica_ok() {
        assert!(verify(&header_v1()).is_ok());
    }

    #[test]
    fn magic_errato_invalid_input() {
        let mut h = header_v1();
        h[0] = 0x00;
        assert!(matches!(verify(&h), Err(CoreError::InvalidInput)));
    }

    #[test]
    fn version_ignota_unsupported_version() {
        let mut h = header_v1();
        h[2] = 0x02;
        assert!(matches!(verify(&h), Err(CoreError::UnsupportedVersion)));
    }

    #[test]
    fn suite_ignota_unsupported_version() {
        let mut h = header_v1();
        h[3] = 0x02;
        assert!(matches!(verify(&h), Err(CoreError::UnsupportedVersion)));
    }

    #[test]
    fn troppo_corto_invalid_input() {
        assert!(matches!(
            verify(&[0x4b, 0x4e]),
            Err(CoreError::InvalidInput)
        ));
    }
}
