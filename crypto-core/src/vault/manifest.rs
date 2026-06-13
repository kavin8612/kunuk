//! Manifest del vault (doc 16 §6).
//!
//! Inventario firmato Ed25519: anti-tampering e anti-rollback. Il contenuto è CBOR
//! deterministico; la firma copre `"kunuk/v1/manifest" ‖ header ‖ cbor` (prefisso di
//! dominio: la stessa chiave non firma altri oggetti in modo confondibile). La
//! verifica è fail-closed: firma valida, `vault_id` atteso, `version` non regredita.

use ed25519_dalek::{SigningKey, VerifyingKey};
use minicbor::bytes::ByteArray;
use minicbor::{Decode, Encode};

use crate::crypto::header::{self, HEADER_LEN};
use crate::crypto::signature::{self, SIGNATURE_LEN};
use crate::error::{CoreError, CoreResult};
use crate::vault::item::ID_LEN;

const MANIFEST_LABEL: &[u8] = b"kunuk/v1/manifest";

/// Riferimento a una voce nel manifest: id e versione della voce.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct ItemRef {
    #[n(0)]
    pub item_id: ByteArray<ID_LEN>,
    #[n(1)]
    pub item_version: u64,
}

/// Contenuto del manifest (doc 16 §6): vault, versione monotona, elenco delle voci e
/// clock CRDT (byte opachi finché il formato non è definito al task 1.2).
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct ManifestContent {
    #[n(0)]
    pub vault_id: ByteArray<ID_LEN>,
    #[n(1)]
    pub version: u64,
    #[n(2)]
    pub items: Vec<ItemRef>,
    #[cbor(n(3), with = "minicbor::bytes")]
    pub crdt_clock: Vec<u8>,
}

/// Vista verificata del manifest restituita da [`verify_manifest`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestView {
    /// Versione (monotona) del manifest verificato.
    pub version: u64,
    /// Voci inventariate.
    pub items: Vec<ItemRef>,
}

/// Codifica canonica e deterministica del contenuto: le voci sono ordinate per
/// `item_id` così che lo stesso stato logico produca sempre gli stessi byte.
fn encode_canonical(content: &ManifestContent) -> CoreResult<Vec<u8>> {
    let mut normalizzato = content.clone();
    normalizzato
        .items
        .sort_by(|a, b| a.item_id[..].cmp(&b.item_id[..]));
    minicbor::to_vec(&normalizzato).map_err(|_| CoreError::Internal)
}

fn signing_input(cbor: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(MANIFEST_LABEL.len() + HEADER_LEN + cbor.len());
    input.extend_from_slice(MANIFEST_LABEL);
    input.extend_from_slice(&header::header_v1());
    input.extend_from_slice(cbor);
    input
}

/// Firma il manifest. Formato del risultato: `header ‖ cbor ‖ signature(64)`.
pub fn sign_manifest(signing_key: &SigningKey, content: &ManifestContent) -> CoreResult<Vec<u8>> {
    let cbor = encode_canonical(content)?;
    let sig = signature::sign(signing_key, &signing_input(&cbor));
    let mut out = Vec::with_capacity(HEADER_LEN + cbor.len() + SIGNATURE_LEN);
    out.extend_from_slice(&header::header_v1());
    out.extend_from_slice(&cbor);
    out.extend_from_slice(&sig);
    Ok(out)
}

/// Verifica un manifest firmato (fail-closed, doc 16 §6): header valido; firma valida;
/// `vault_id` atteso; `version >= min_version` (anti-rollback). Qualunque controllo
/// fallito → `AuthFailed` (header malformato → `UnsupportedVersion`/`InvalidInput`).
pub fn verify_manifest(
    verifying_key: &VerifyingKey,
    signed_manifest: &[u8],
    expected_vault_id: &[u8; ID_LEN],
    min_version: u64,
) -> CoreResult<ManifestView> {
    header::verify(signed_manifest)?;
    if signed_manifest.len() < HEADER_LEN + SIGNATURE_LEN {
        return Err(CoreError::InvalidInput);
    }
    let sig_start = signed_manifest.len() - SIGNATURE_LEN;
    let cbor = &signed_manifest[HEADER_LEN..sig_start];
    let sig: &[u8; SIGNATURE_LEN] = (&signed_manifest[sig_start..])
        .try_into()
        .map_err(|_| CoreError::InvalidInput)?;

    signature::verify(verifying_key, &signing_input(cbor), sig)?;

    let content: ManifestContent = minicbor::decode(cbor).map_err(|_| CoreError::InvalidInput)?;
    if content.vault_id[..] != expected_vault_id[..] {
        return Err(CoreError::AuthFailed);
    }
    if content.version < min_version {
        return Err(CoreError::AuthFailed);
    }
    Ok(ManifestView {
        version: content.version,
        items: content.items,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signature::keypair_from_seed;

    fn content() -> ManifestContent {
        ManifestContent {
            vault_id: ByteArray::from([0x66; ID_LEN]),
            version: 3,
            items: vec![
                ItemRef {
                    item_id: ByteArray::from([0x02; ID_LEN]),
                    item_version: 1,
                },
                ItemRef {
                    item_id: ByteArray::from([0x01; ID_LEN]),
                    item_version: 5,
                },
            ],
            crdt_clock: vec![0xDE, 0xAD],
        }
    }

    #[test]
    fn sign_verify_round_trip() {
        let (sk, vk) = keypair_from_seed(&[0x11; 32]);
        let signed = sign_manifest(&sk, &content()).unwrap();
        let view = verify_manifest(&vk, &signed, &[0x66; ID_LEN], 3).unwrap();
        assert_eq!(view.version, 3);
        assert_eq!(view.items.len(), 2);
    }

    #[test]
    fn ordinamento_canonico_deterministico() {
        // Le voci in ordine diverso producono lo stesso manifest firmato.
        let (sk, _) = keypair_from_seed(&[0x11; 32]);
        let mut altro = content();
        altro.items.reverse();
        assert_eq!(
            sign_manifest(&sk, &content()).unwrap(),
            sign_manifest(&sk, &altro).unwrap()
        );
    }

    #[test]
    fn rollback_auth_failed() {
        let (sk, vk) = keypair_from_seed(&[0x11; 32]);
        let signed = sign_manifest(&sk, &content()).unwrap();
        // min_version 4 > version 3 → rollback rifiutato.
        assert!(matches!(
            verify_manifest(&vk, &signed, &[0x66; ID_LEN], 4),
            Err(CoreError::AuthFailed)
        ));
    }

    #[test]
    fn vault_id_diverso_auth_failed() {
        let (sk, vk) = keypair_from_seed(&[0x11; 32]);
        let signed = sign_manifest(&sk, &content()).unwrap();
        assert!(matches!(
            verify_manifest(&vk, &signed, &[0x00; ID_LEN], 3),
            Err(CoreError::AuthFailed)
        ));
    }

    #[test]
    fn firma_manomessa_auth_failed() {
        let (sk, vk) = keypair_from_seed(&[0x11; 32]);
        let mut signed = sign_manifest(&sk, &content()).unwrap();
        let last = signed.len() - 1;
        signed[last] ^= 0x01;
        assert!(matches!(
            verify_manifest(&vk, &signed, &[0x66; ID_LEN], 3),
            Err(CoreError::AuthFailed)
        ));
    }
}
