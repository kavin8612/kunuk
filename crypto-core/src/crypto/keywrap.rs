//! Layout comune delle buste "chiave avvolta" (doc 16 §5-6).
//!
//! Formato condiviso: `header(4) ‖ nonce(24) ‖ ct`, dove `ct = ciphertext ‖ tag` di
//! XChaCha20-Poly1305. È usato da `wrapped_cek` (doc 16 §5) e dalla busta della chiave
//! di firma (doc 16 §6); l'AAD (il binding al contesto) è responsabilità del chiamante,
//! che la costruisce con l'etichetta di dominio giusta. La busta della VK (`envelope`)
//! ha un byte di tipo in più e non passa di qui.

use crate::crypto::aead::NONCE_LEN;
use crate::crypto::header::{self, HEADER_LEN};
use crate::error::{CoreError, CoreResult};

/// Lunghezza del tag Poly1305 (proprietà dell'AEAD, doc 16 §1).
pub const TAG_LEN: usize = 16;

/// Offset del nonce nella busta: subito dopo l'header comune.
const NONCE_OFFSET: usize = HEADER_LEN;
/// Offset del ciphertext: dopo header e nonce.
const CT_OFFSET: usize = HEADER_LEN + NONCE_LEN;

/// Assembla una busta `header ‖ nonce ‖ ct`.
pub fn pack(nonce: &[u8; NONCE_LEN], ct: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(CT_OFFSET + ct.len());
    out.extend_from_slice(&header::header_v1());
    out.extend_from_slice(nonce);
    out.extend_from_slice(ct);
    out
}

/// Scompone una busta verificando l'header (fail-closed) e restituendo `(nonce, ct)`.
/// Header non valido → `UnsupportedVersion`/`InvalidInput`; busta priva di un ct con
/// almeno il tag → `InvalidInput`. La lunghezza esatta del plaintext la verifica il
/// chiamante (di norma con un `try_into` che dà `DecryptFailed`).
pub fn split(blob: &[u8]) -> CoreResult<(&[u8; NONCE_LEN], &[u8])> {
    header::verify(blob)?;
    if blob.len() < CT_OFFSET + TAG_LEN {
        return Err(CoreError::InvalidInput);
    }
    let nonce: &[u8; NONCE_LEN] = (&blob[NONCE_OFFSET..CT_OFFSET])
        .try_into()
        .map_err(|_| CoreError::InvalidInput)?;
    Ok((nonce, &blob[CT_OFFSET..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_split_round_trip() {
        let nonce = [0x11; NONCE_LEN];
        let ct = [0x22u8; TAG_LEN + 8];
        let blob = pack(&nonce, &ct);
        assert_eq!(blob.len(), HEADER_LEN + NONCE_LEN + ct.len());
        let (n, c) = split(&blob).unwrap();
        assert_eq!(n, &nonce);
        assert_eq!(c, &ct);
    }

    #[test]
    fn split_rifiuta_busta_troppo_corta() {
        // header + nonce ma ct più corto del solo tag → InvalidInput.
        let blob = pack(&[0x11; NONCE_LEN], &[0x22; TAG_LEN - 1]);
        assert!(matches!(split(&blob), Err(CoreError::InvalidInput)));
    }

    #[test]
    fn split_rifiuta_header_non_valido() {
        let mut blob = pack(&[0x11; NONCE_LEN], &[0x22; TAG_LEN]);
        blob[0] ^= 0xFF; // magic corrotto
        assert!(split(&blob).is_err());
    }
}
