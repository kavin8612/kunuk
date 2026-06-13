//! Item del vault (doc 16 §5).
//!
//! Due oggetti per voce: la CEK avvolta dalla VK (`wrapped_cek`) e l'item cifrato con
//! la CEK. Il contenuto è CBOR deterministico (incluso il tipo della voce, SR-25). Le
//! AAD legano entrambi a `vault_id ‖ item_id`: il server non può trapiantare un
//! ciphertext su un altro item/vault né scambiare le CEK (doc 16 §5).

use minicbor::{Decode, Encode};
use zeroize::Zeroizing;

use crate::crypto::aead::{self, NONCE_LEN};
use crate::crypto::header::{self, HEADER_LEN};
use crate::crypto::params::KEY_LEN;
use crate::crypto::rng;
use crate::error::{CoreError, CoreResult};

/// Lunghezza degli identificatori binari (UUID raw).
pub const ID_LEN: usize = 16;

const CEK_LABEL: &[u8] = b"kunuk/v1/cek";
const ITEM_LABEL: &[u8] = b"kunuk/v1/item";
const TAG_LEN: usize = 16;
const NONCE_OFFSET: usize = HEADER_LEN;
const CT_OFFSET: usize = HEADER_LEN + NONCE_LEN;

/// Contenuto tipizzato di una voce (doc 17 §2). Schema essenziale: cartelle,
/// preferiti e campi aggiuntivi arrivano al task 1.1. Codificato in CBOR
/// deterministico (chiavi intere, definite-length): il tipo è parte del contenuto
/// cifrato (SR-25).
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub enum ItemContent {
    /// Credenziali di accesso.
    #[n(0)]
    Login {
        #[n(0)]
        username: String,
        #[n(1)]
        password: String,
        #[n(2)]
        uris: Vec<String>,
        #[n(3)]
        notes: String,
    },
    /// Nota sicura.
    #[n(1)]
    SecureNote {
        #[n(0)]
        text: String,
    },
    /// Carta di pagamento.
    #[n(2)]
    Card {
        #[n(0)]
        cardholder_name: String,
        #[n(1)]
        number: String,
        #[n(2)]
        exp_month: u8,
        #[n(3)]
        exp_year: u16,
        #[n(4)]
        security_code: String,
    },
    /// Identità.
    #[n(3)]
    Identity {
        #[n(0)]
        full_name: String,
        #[n(1)]
        email: String,
        #[n(2)]
        phone: String,
    },
}

/// Serializza il contenuto in CBOR deterministico.
pub fn encode_content(content: &ItemContent) -> CoreResult<Vec<u8>> {
    minicbor::to_vec(content).map_err(|_| CoreError::Internal)
}

/// Deserializza il contenuto CBOR. Input non valido → `InvalidInput`.
pub fn decode_content(bytes: &[u8]) -> CoreResult<ItemContent> {
    minicbor::decode(bytes).map_err(|_| CoreError::InvalidInput)
}

fn aad(label: &[u8], vault_id: &[u8; ID_LEN], item_id: &[u8; ID_LEN]) -> Vec<u8> {
    let mut a = Vec::with_capacity(HEADER_LEN + label.len() + ID_LEN * 2);
    a.extend_from_slice(&header::header_v1());
    a.extend_from_slice(label);
    a.extend_from_slice(vault_id);
    a.extend_from_slice(item_id);
    a
}

/// Cifra l'item con CEK e nonce espliciti (deterministico, per i test vettoriali).
/// Ritorna `(item_ciphertext, wrapped_cek)`. In produzione usare [`encrypt_item`].
#[allow(clippy::too_many_arguments)]
pub fn encrypt_item_with(
    vk: &[u8; KEY_LEN],
    vault_id: &[u8; ID_LEN],
    item_id: &[u8; ID_LEN],
    content_cbor: &[u8],
    cek: &[u8; KEY_LEN],
    cek_nonce: &[u8; NONCE_LEN],
    item_nonce: &[u8; NONCE_LEN],
) -> CoreResult<(Vec<u8>, Vec<u8>)> {
    // wrapped_cek: CEK avvolta dalla VK, legata a vault_id‖item_id.
    let cek_ct = aead::encrypt(vk, cek_nonce, &aad(CEK_LABEL, vault_id, item_id), cek)?;
    let mut wrapped_cek = Vec::with_capacity(CT_OFFSET + cek_ct.len());
    wrapped_cek.extend_from_slice(&header::header_v1());
    wrapped_cek.extend_from_slice(cek_nonce);
    wrapped_cek.extend_from_slice(&cek_ct);

    // item ciphertext: contenuto cifrato con la CEK, legato a vault_id‖item_id.
    let item_ct = aead::encrypt(
        cek,
        item_nonce,
        &aad(ITEM_LABEL, vault_id, item_id),
        content_cbor,
    )?;
    let mut ciphertext = Vec::with_capacity(CT_OFFSET + item_ct.len());
    ciphertext.extend_from_slice(&header::header_v1());
    ciphertext.extend_from_slice(item_nonce);
    ciphertext.extend_from_slice(&item_ct);

    Ok((ciphertext, wrapped_cek))
}

/// Cifra l'item generando CEK e nonce freschi dal CSPRNG (doc 16 §7).
pub fn encrypt_item(
    vk: &[u8; KEY_LEN],
    vault_id: &[u8; ID_LEN],
    item_id: &[u8; ID_LEN],
    content_cbor: &[u8],
) -> CoreResult<(Vec<u8>, Vec<u8>)> {
    let mut cek = Zeroizing::new([0u8; KEY_LEN]);
    rng::fill(cek.as_mut_slice())?;
    let mut cek_nonce = [0u8; NONCE_LEN];
    rng::fill(&mut cek_nonce)?;
    let mut item_nonce = [0u8; NONCE_LEN];
    rng::fill(&mut item_nonce)?;
    encrypt_item_with(
        vk,
        vault_id,
        item_id,
        content_cbor,
        &cek,
        &cek_nonce,
        &item_nonce,
    )
}

fn split_object(object: &[u8]) -> CoreResult<(&[u8; NONCE_LEN], &[u8])> {
    header::verify(object)?;
    if object.len() < CT_OFFSET + TAG_LEN {
        return Err(CoreError::InvalidInput);
    }
    let nonce: &[u8; NONCE_LEN] = (&object[NONCE_OFFSET..CT_OFFSET])
        .try_into()
        .map_err(|_| CoreError::InvalidInput)?;
    Ok((nonce, &object[CT_OFFSET..]))
}

/// Decifra un item: scarta la CEK con la VK, poi decifra il contenuto con la CEK.
/// Trapianto su altro item/vault o ciphertext manomesso → `DecryptFailed`. Ritorna il
/// CBOR del contenuto (azzerato al drop).
pub fn decrypt_item(
    vk: &[u8; KEY_LEN],
    vault_id: &[u8; ID_LEN],
    item_id: &[u8; ID_LEN],
    ciphertext: &[u8],
    wrapped_cek: &[u8],
) -> CoreResult<Zeroizing<Vec<u8>>> {
    let (cek_nonce, cek_ct) = split_object(wrapped_cek)?;
    let cek_bytes = Zeroizing::new(aead::decrypt(
        vk,
        cek_nonce,
        &aad(CEK_LABEL, vault_id, item_id),
        cek_ct,
    )?);
    let cek: [u8; KEY_LEN] = cek_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::DecryptFailed)?;

    let (item_nonce, item_ct) = split_object(ciphertext)?;
    let content = aead::decrypt(
        &cek,
        item_nonce,
        &aad(ITEM_LABEL, vault_id, item_id),
        item_ct,
    )?;
    Ok(Zeroizing::new(content))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VK: [u8; KEY_LEN] = [0x55; KEY_LEN];
    const VAULT: [u8; ID_LEN] = [0x66; ID_LEN];
    const ITEM: [u8; ID_LEN] = [0x77; ID_LEN];
    const CEK: [u8; KEY_LEN] = [0x88; KEY_LEN];
    const CEK_NONCE: [u8; NONCE_LEN] = [0x99; NONCE_LEN];
    const ITEM_NONCE: [u8; NONCE_LEN] = [0xAA; NONCE_LEN];

    fn login() -> ItemContent {
        ItemContent::Login {
            username: "alice".into(),
            password: "s3gr3t0".into(),
            uris: vec!["https://example.com".into()],
            notes: "nota".into(),
        }
    }

    #[test]
    fn cbor_deterministico_e_round_trip() {
        let c = login();
        let a = encode_content(&c).unwrap();
        let b = encode_content(&c).unwrap();
        assert_eq!(a, b, "encoding deterministico");
        assert_eq!(decode_content(&a).unwrap(), c, "round-trip");
    }

    #[test]
    fn item_round_trip() {
        let cbor = encode_content(&login()).unwrap();
        let (ct, wcek) =
            encrypt_item_with(&VK, &VAULT, &ITEM, &cbor, &CEK, &CEK_NONCE, &ITEM_NONCE).unwrap();
        let got = decrypt_item(&VK, &VAULT, &ITEM, &ct, &wcek).unwrap();
        assert_eq!(&*got, &cbor);
        assert_eq!(decode_content(&got).unwrap(), login());
    }

    #[test]
    fn trapianto_su_altro_item_decrypt_failed() {
        let cbor = encode_content(&login()).unwrap();
        let (ct, wcek) =
            encrypt_item_with(&VK, &VAULT, &ITEM, &cbor, &CEK, &CEK_NONCE, &ITEM_NONCE).unwrap();
        let altro_item = [0x00; ID_LEN];
        assert!(matches!(
            decrypt_item(&VK, &VAULT, &altro_item, &ct, &wcek),
            Err(CoreError::DecryptFailed)
        ));
    }

    #[test]
    fn encrypt_item_genera_valori_freschi() {
        let cbor = encode_content(&login()).unwrap();
        let (ct1, _) = encrypt_item(&VK, &VAULT, &ITEM, &cbor).unwrap();
        let (ct2, _) = encrypt_item(&VK, &VAULT, &ITEM, &cbor).unwrap();
        assert_ne!(ct1, ct2, "nonce/CEK freschi → ciphertext diversi");
    }
}
