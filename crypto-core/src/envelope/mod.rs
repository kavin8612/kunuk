//! Buste della VK e wrapping (doc 16 §4).
//!
//! Una busta contiene la VK avvolta da una chiave di wrapping (PK/RKw/DKw). Tutto il
//! contesto è legato nell'AAD — header, etichetta, account, tipo, parametri KDF — così
//! una busta non può essere spostata su un altro account, ri-etichettata, né
//! accompagnata da parametri KDF indeboliti: qualunque ricombinazione invalida il tag
//! (anti-trapianto, anti-downgrade). Decrittazione fail-closed (doc 16 §7).
//!
//! `kdf_params_cbor` è trattato come byte opachi (la sua codifica CBOR deterministica
//! è definita ai task 0.6/0.7): qui conta solo che sia legato nell'AAD.

use zeroize::Zeroizing;

use crate::crypto::aead::{self, NONCE_LEN};
use crate::crypto::header::{self, HEADER_LEN};
use crate::crypto::params::KEY_LEN;
use crate::crypto::rng;
use crate::error::{CoreError, CoreResult};

/// Etichetta di dominio dell'AAD delle buste (doc 16 §4).
const AAD_LABEL: &[u8] = b"kunuk/v1/envelope";

/// Lunghezza dell'account id nei formati binari (UUID raw, 16 byte).
pub const ACCOUNT_ID_LEN: usize = 16;

/// Lunghezza del tag Poly1305.
const TAG_LEN: usize = 16;

/// Offset del nonce nella busta: dopo header (4) e byte del tipo (1).
const NONCE_OFFSET: usize = HEADER_LEN + 1;

/// Offset del ciphertext (VK cifrata + tag): dopo il nonce.
const CIPHERTEXT_OFFSET: usize = NONCE_OFFSET + NONCE_LEN;

/// Tipo di busta (doc 16 §4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EnvelopeType {
    /// Busta password: `wrap_PK(VK)`.
    Password,
    /// Busta recupero: `wrap_RK(VK)`.
    Recovery,
    /// Busta biometria, per dispositivo: `wrap_DK(VK)`.
    Biometric,
}

impl EnvelopeType {
    /// Codice del tipo nel formato binario (doc 16 §4).
    fn as_byte(self) -> u8 {
        match self {
            EnvelopeType::Password => 0x01,
            EnvelopeType::Recovery => 0x02,
            EnvelopeType::Biometric => 0x03,
        }
    }
}

/// AAD della busta (doc 16 §4):
/// `header ‖ "kunuk/v1/envelope" ‖ account_id ‖ type ‖ kdf_params_cbor`.
fn build_aad(
    account_id: &[u8; ACCOUNT_ID_LEN],
    envelope_type: EnvelopeType,
    kdf_params_cbor: &[u8],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        HEADER_LEN + AAD_LABEL.len() + ACCOUNT_ID_LEN + 1 + kdf_params_cbor.len(),
    );
    aad.extend_from_slice(&header::header_v1());
    aad.extend_from_slice(AAD_LABEL);
    aad.extend_from_slice(account_id);
    aad.push(envelope_type.as_byte());
    aad.extend_from_slice(kdf_params_cbor);
    aad
}

/// Avvolge la VK con `wrapping_key` usando un `nonce` esplicito (deterministico, per
/// i test vettoriali). In produzione usare [`wrap`], che genera il nonce dal CSPRNG.
pub fn wrap_with_nonce(
    wrapping_key: &[u8; KEY_LEN],
    vk: &[u8; KEY_LEN],
    account_id: &[u8; ACCOUNT_ID_LEN],
    envelope_type: EnvelopeType,
    kdf_params_cbor: &[u8],
    nonce: &[u8; NONCE_LEN],
) -> CoreResult<Vec<u8>> {
    let aad = build_aad(account_id, envelope_type, kdf_params_cbor);
    let ciphertext = aead::encrypt(wrapping_key, nonce, &aad, vk)?;
    let mut envelope = Vec::with_capacity(CIPHERTEXT_OFFSET + ciphertext.len());
    envelope.extend_from_slice(&header::header_v1());
    envelope.push(envelope_type.as_byte());
    envelope.extend_from_slice(nonce);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

/// Avvolge la VK generando un nonce fresco dal CSPRNG (mai riusato, doc 16 §7).
pub fn wrap(
    wrapping_key: &[u8; KEY_LEN],
    vk: &[u8; KEY_LEN],
    account_id: &[u8; ACCOUNT_ID_LEN],
    envelope_type: EnvelopeType,
    kdf_params_cbor: &[u8],
) -> CoreResult<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    rng::fill(&mut nonce)?;
    wrap_with_nonce(
        wrapping_key,
        vk,
        account_id,
        envelope_type,
        kdf_params_cbor,
        &nonce,
    )
}

/// Apre una busta e restituisce la VK. Fail-closed: header non valido →
/// `UnsupportedVersion`/`InvalidInput`; busta troppo corta o tipo diverso
/// dall'atteso → `InvalidInput`; tag/AAD non verificano (incluso il trapianto su
/// altro account o con parametri diversi) → `DecryptFailed`.
pub fn unwrap(
    wrapping_key: &[u8; KEY_LEN],
    envelope: &[u8],
    account_id: &[u8; ACCOUNT_ID_LEN],
    expected_type: EnvelopeType,
    kdf_params_cbor: &[u8],
) -> CoreResult<Zeroizing<[u8; KEY_LEN]>> {
    header::verify(envelope)?;
    if envelope.len() < CIPHERTEXT_OFFSET + TAG_LEN {
        return Err(CoreError::InvalidInput);
    }
    if envelope[HEADER_LEN] != expected_type.as_byte() {
        return Err(CoreError::InvalidInput);
    }
    let nonce: &[u8; NONCE_LEN] = (&envelope[NONCE_OFFSET..CIPHERTEXT_OFFSET])
        .try_into()
        .map_err(|_| CoreError::InvalidInput)?;
    let ciphertext = &envelope[CIPHERTEXT_OFFSET..];
    let aad = build_aad(account_id, expected_type, kdf_params_cbor);
    let plaintext = Zeroizing::new(aead::decrypt(wrapping_key, nonce, &aad, ciphertext)?);
    let vk: [u8; KEY_LEN] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::DecryptFailed)?;
    Ok(Zeroizing::new(vk))
}

#[cfg(test)]
mod tests {
    use super::*;

    const WRAP_KEY: [u8; KEY_LEN] = [0x11; KEY_LEN];
    const VK: [u8; KEY_LEN] = [0x22; KEY_LEN];
    const ACCOUNT: [u8; ACCOUNT_ID_LEN] = [0x33; ACCOUNT_ID_LEN];
    const NONCE: [u8; NONCE_LEN] = [0x44; NONCE_LEN];
    const PARAMS: &[u8] = b"params-opachi";

    #[test]
    fn round_trip() {
        let env = wrap_with_nonce(
            &WRAP_KEY,
            &VK,
            &ACCOUNT,
            EnvelopeType::Password,
            PARAMS,
            &NONCE,
        )
        .unwrap();
        // header(4) + tipo(1) + nonce(24) + VK(32) + tag(16) = 77 byte.
        assert_eq!(env.len(), 77);
        let vk = unwrap(&WRAP_KEY, &env, &ACCOUNT, EnvelopeType::Password, PARAMS).unwrap();
        assert_eq!(*vk, VK);
    }

    #[test]
    fn trapianto_su_altro_account_decrypt_failed() {
        let env = wrap_with_nonce(
            &WRAP_KEY,
            &VK,
            &ACCOUNT,
            EnvelopeType::Password,
            PARAMS,
            &NONCE,
        )
        .unwrap();
        let altro = [0x99; ACCOUNT_ID_LEN];
        assert!(matches!(
            unwrap(&WRAP_KEY, &env, &altro, EnvelopeType::Password, PARAMS),
            Err(CoreError::DecryptFailed)
        ));
    }

    #[test]
    fn parametri_diversi_decrypt_failed() {
        let env = wrap_with_nonce(
            &WRAP_KEY,
            &VK,
            &ACCOUNT,
            EnvelopeType::Password,
            PARAMS,
            &NONCE,
        )
        .unwrap();
        assert!(matches!(
            unwrap(
                &WRAP_KEY,
                &env,
                &ACCOUNT,
                EnvelopeType::Password,
                b"params-indeboliti"
            ),
            Err(CoreError::DecryptFailed)
        ));
    }

    #[test]
    fn tipo_atteso_diverso_invalid_input() {
        let env = wrap_with_nonce(
            &WRAP_KEY,
            &VK,
            &ACCOUNT,
            EnvelopeType::Password,
            PARAMS,
            &NONCE,
        )
        .unwrap();
        assert!(matches!(
            unwrap(&WRAP_KEY, &env, &ACCOUNT, EnvelopeType::Recovery, PARAMS),
            Err(CoreError::InvalidInput)
        ));
    }

    #[test]
    fn wrap_genera_nonce_diversi() {
        let a = wrap(&WRAP_KEY, &VK, &ACCOUNT, EnvelopeType::Password, PARAMS).unwrap();
        let b = wrap(&WRAP_KEY, &VK, &ACCOUNT, EnvelopeType::Password, PARAMS).unwrap();
        // Nonce freschi → buste diverse, ma entrambe si aprono sulla stessa VK.
        assert_ne!(a, b);
        assert_eq!(
            *unwrap(&WRAP_KEY, &a, &ACCOUNT, EnvelopeType::Password, PARAMS).unwrap(),
            VK
        );
    }
}
