//! Manifest del vault (doc 16 §6).
//!
//! Inventario firmato Ed25519: anti-tampering e anti-rollback. Il contenuto è CBOR
//! deterministico; la firma copre `"kunuk/v1/manifest" ‖ header ‖ cbor` (prefisso di
//! dominio: la stessa chiave non firma altri oggetti in modo confondibile). La
//! verifica è fail-closed: firma valida, `vault_id` atteso, `version` non regredita.

use ed25519_dalek::{SigningKey, VerifyingKey};
use minicbor::bytes::ByteArray;
use minicbor::{Decode, Encode};
use zeroize::Zeroizing;

use crate::crypto::aead::{self, NONCE_LEN};
use crate::crypto::cbor;
use crate::crypto::header::{self, HEADER_LEN};
use crate::crypto::keywrap;
use crate::crypto::params::KEY_LEN;
use crate::crypto::rng;
use crate::crypto::signature::{self, SIGNATURE_LEN};
use crate::error::{CoreError, CoreResult};
use crate::vault::item::ID_LEN;

const MANIFEST_LABEL: &[u8] = b"kunuk/v1/manifest";

/// Etichetta di dominio dell'AAD della busta chiave di firma (doc 16 §6).
const SIGNING_KEY_LABEL: &[u8] = b"kunuk/v1/signing-key";

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
/// clock CRDT. `items`/`crdt_clock` sono lo snapshot firmato della directory risolta dal
/// modulo `sync` ([`crate::sync::MergeResult`], task 1.2, ADR-0022): qui restano byte/voci
/// opachi, il merge vive nel modulo `sync`.
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
    cbor::encode(&normalizzato)
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
    let cbor_bytes = &signed_manifest[HEADER_LEN..sig_start];
    let sig: &[u8; SIGNATURE_LEN] = (&signed_manifest[sig_start..])
        .try_into()
        .map_err(|_| CoreError::InvalidInput)?;

    signature::verify(verifying_key, &signing_input(cbor_bytes), sig)?;

    let content: ManifestContent = cbor::decode(cbor_bytes)?;
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

/// Come [`verify_manifest`] ma accetta la chiave pubblica come **byte grezzi** (32B): comoda
/// per i client (CLI, binding) che ricevono la `manifest_pubkey` dal server senza dipendere
/// da `ed25519-dalek`. Pubkey malformata (punto non valido) → `InvalidInput`; la crittografia
/// resta confinata nel core (SR-1).
pub fn verify_manifest_with_pubkey(
    pubkey: &[u8; 32],
    signed_manifest: &[u8],
    expected_vault_id: &[u8; ID_LEN],
    min_version: u64,
) -> CoreResult<ManifestView> {
    let vk = VerifyingKey::from_bytes(pubkey).map_err(|_| CoreError::InvalidInput)?;
    verify_manifest(&vk, signed_manifest, expected_vault_id, min_version)
}

/// Scinde un manifest firmato da [`sign_manifest`] (`header ‖ cbor ‖ signature`) nei due
/// campi che l'API espone separatamente (doc 12): il corpo `manifest = header ‖ cbor` e la
/// `signature` (64 byte). Il server li conserva opachi e li restituisce distinti su
/// `GET /vault`; il client li **ricompone** (`manifest ‖ signature`) per [`verify_manifest`].
/// Busta più corta del minimo (header + firma) → `InvalidInput`.
pub fn split_signed_manifest(signed: &[u8]) -> CoreResult<(&[u8], &[u8])> {
    if signed.len() < HEADER_LEN + SIGNATURE_LEN {
        return Err(CoreError::InvalidInput);
    }
    let sig_start = signed.len() - SIGNATURE_LEN;
    Ok((&signed[..sig_start], &signed[sig_start..]))
}

/// AAD della busta chiave di firma (doc 16 §6):
/// `header ‖ "kunuk/v1/signing-key" ‖ vault_id`.
fn signing_key_aad(vault_id: &[u8; ID_LEN]) -> Vec<u8> {
    let mut a = Vec::with_capacity(HEADER_LEN + SIGNING_KEY_LABEL.len() + ID_LEN);
    a.extend_from_slice(&header::header_v1());
    a.extend_from_slice(SIGNING_KEY_LABEL);
    a.extend_from_slice(vault_id);
    a
}

/// Avvolge il seme Ed25519 della chiave di firma con la VK, usando un `nonce` esplicito
/// (deterministico, per i test vettoriali). In produzione usare [`wrap_signing_key`].
/// Formato: `header ‖ nonce ‖ seed_cifrato ‖ tag`, AAD legata a `vault_id` (doc 16 §6).
pub fn wrap_signing_key_with_nonce(
    vk: &[u8; KEY_LEN],
    signing_seed: &[u8; KEY_LEN],
    vault_id: &[u8; ID_LEN],
    nonce: &[u8; NONCE_LEN],
) -> CoreResult<Vec<u8>> {
    let ct = aead::encrypt(vk, nonce, &signing_key_aad(vault_id), signing_seed)?;
    Ok(keywrap::pack(nonce, &ct))
}

/// Avvolge il seme della chiave di firma generando un nonce fresco dal CSPRNG
/// (mai riusato, doc 16 §7).
pub fn wrap_signing_key(
    vk: &[u8; KEY_LEN],
    signing_seed: &[u8; KEY_LEN],
    vault_id: &[u8; ID_LEN],
) -> CoreResult<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    rng::fill(&mut nonce)?;
    wrap_signing_key_with_nonce(vk, signing_seed, vault_id, &nonce)
}

/// Apre la busta chiave di firma e ricostruisce la `SigningKey` Ed25519. Fail-closed:
/// header non valido → `UnsupportedVersion`/`InvalidInput`; busta troppo corta →
/// `InvalidInput`; tag/AAD non verificano (incluso il trapianto su un altro vault) →
/// `DecryptFailed`. Il seme decifrato vive in `Zeroizing` e non lascia la funzione.
pub fn unwrap_signing_key(
    vk: &[u8; KEY_LEN],
    wrapped: &[u8],
    vault_id: &[u8; ID_LEN],
) -> CoreResult<SigningKey> {
    let (nonce, ct) = keywrap::split(wrapped)?;
    let plaintext = Zeroizing::new(aead::decrypt(vk, nonce, &signing_key_aad(vault_id), ct)?);
    let seed: Zeroizing<[u8; KEY_LEN]> = Zeroizing::new(
        plaintext
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::DecryptFailed)?,
    );
    Ok(SigningKey::from_bytes(&seed))
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
    fn split_signed_manifest_ricompone_e_verifica() {
        let (sk, vk) = keypair_from_seed(&[0x11; 32]);
        let signed = sign_manifest(&sk, &content()).unwrap();
        let (body, sig) = split_signed_manifest(&signed).unwrap();
        assert_eq!(sig.len(), SIGNATURE_LEN);
        // Ricomposizione body ‖ signature == manifest firmato originale.
        let mut recombined = Vec::new();
        recombined.extend_from_slice(body);
        recombined.extend_from_slice(sig);
        assert_eq!(recombined, signed);
        // Il ricomposto verifica con la pubkey pinned (round-trip API → core).
        assert!(verify_manifest(&vk, &recombined, &[0x66; ID_LEN], 3).is_ok());
    }

    #[test]
    fn split_signed_manifest_busta_corta_invalid_input() {
        assert!(matches!(
            split_signed_manifest(&[0x00; HEADER_LEN + SIGNATURE_LEN - 1]),
            Err(CoreError::InvalidInput)
        ));
    }

    #[test]
    fn verify_manifest_with_pubkey_bytes() {
        let (sk, vk) = keypair_from_seed(&[0x11; 32]);
        let signed = sign_manifest(&sk, &content()).unwrap();
        let view =
            verify_manifest_with_pubkey(&vk.to_bytes(), &signed, &[0x66; ID_LEN], 3).unwrap();
        assert_eq!(view.version, 3);
        // Pubkey malformata → InvalidInput (non un panico).
        assert!(matches!(
            verify_manifest_with_pubkey(&[0xFF; 32], &signed, &[0x66; ID_LEN], 3),
            Err(CoreError::InvalidInput) | Err(CoreError::AuthFailed)
        ));
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

    const WRAP_VK: [u8; KEY_LEN] = [0x33; KEY_LEN];
    const SK_SEED: [u8; KEY_LEN] = [0x44; KEY_LEN];
    const SK_VAULT: [u8; ID_LEN] = [0x66; ID_LEN];
    const SK_NONCE: [u8; NONCE_LEN] = [0x55; NONCE_LEN];

    #[test]
    fn wrapped_signing_key_round_trip() {
        let wrapped =
            wrap_signing_key_with_nonce(&WRAP_VK, &SK_SEED, &SK_VAULT, &SK_NONCE).unwrap();
        // header(4) + nonce(24) + seed(32) + tag(16) = 76 byte.
        assert_eq!(wrapped.len(), 76);
        let recovered = unwrap_signing_key(&WRAP_VK, &wrapped, &SK_VAULT).unwrap();
        // La chiave ricostruita coincide con quella derivata dal seme.
        let (_, expected_pub) = keypair_from_seed(&SK_SEED);
        assert_eq!(
            recovered.verifying_key().to_bytes(),
            expected_pub.to_bytes()
        );
    }

    #[test]
    fn wrapped_signing_key_firma_un_manifest_verificabile() {
        // La chiave estratta dalla busta firma un manifest che verifica con la pubblica.
        let wrapped =
            wrap_signing_key_with_nonce(&WRAP_VK, &SK_SEED, &SK_VAULT, &SK_NONCE).unwrap();
        let sk = unwrap_signing_key(&WRAP_VK, &wrapped, &SK_VAULT).unwrap();
        let pubkey = sk.verifying_key();
        let signed = sign_manifest(&sk, &content()).unwrap();
        assert!(verify_manifest(&pubkey, &signed, &[0x66; ID_LEN], 3).is_ok());
    }

    #[test]
    fn wrapped_signing_key_trapianto_vault_decrypt_failed() {
        let wrapped =
            wrap_signing_key_with_nonce(&WRAP_VK, &SK_SEED, &SK_VAULT, &SK_NONCE).unwrap();
        let altro_vault = [0x99; ID_LEN];
        assert!(matches!(
            unwrap_signing_key(&WRAP_VK, &wrapped, &altro_vault),
            Err(CoreError::DecryptFailed)
        ));
    }

    #[test]
    fn wrap_signing_key_genera_nonce_diversi() {
        let a = wrap_signing_key(&WRAP_VK, &SK_SEED, &SK_VAULT).unwrap();
        let b = wrap_signing_key(&WRAP_VK, &SK_SEED, &SK_VAULT).unwrap();
        assert_ne!(a, b, "nonce freschi → buste diverse");
        let ka = unwrap_signing_key(&WRAP_VK, &a, &SK_VAULT).unwrap();
        let kb = unwrap_signing_key(&WRAP_VK, &b, &SK_VAULT).unwrap();
        assert_eq!(ka.to_bytes(), kb.to_bytes());
    }
}
