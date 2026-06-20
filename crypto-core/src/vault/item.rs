//! Item del vault (doc 16 §5).
//!
//! Due oggetti per voce: la CEK avvolta dalla VK (`wrapped_cek`) e l'item cifrato con
//! la CEK. Il contenuto è CBOR deterministico (incluso il tipo della voce, SR-25). Le
//! AAD legano entrambi a `vault_id ‖ item_id`: il server non può trapiantare un
//! ciphertext su un altro item/vault né scambiare le CEK (doc 16 §5).

use minicbor::bytes::ByteArray;
use minicbor::{Decode, Encode};
use zeroize::Zeroizing;

use crate::crypto::aead::{self, NONCE_LEN};
use crate::crypto::cbor;
use crate::crypto::header::{self, HEADER_LEN};
use crate::crypto::keywrap;
use crate::crypto::params::KEY_LEN;
use crate::crypto::rng;
use crate::error::{CoreError, CoreResult};

/// Lunghezza degli identificatori binari (UUID raw).
pub const ID_LEN: usize = 16;

const CEK_LABEL: &[u8] = b"kunuk/v1/cek";
const ITEM_LABEL: &[u8] = b"kunuk/v1/item";

/// Contenuto in chiaro di una voce del vault (doc 16 §5, doc 17 §2, ADR-0021).
///
/// Wrapper comune con i metadati condivisi da ogni voce — titolo, cartella di
/// appartenenza, preferito, campi personalizzati — più il payload tipizzato (`data`).
/// **Tutto** sta nel CBOR cifrato con la CEK (SR-25): il server non vede né il tipo, né
/// il titolo, né l'appartenenza a una cartella, né il flag preferito.
///
/// Le cartelle sono a loro volta voci ([`ItemData::Folder`]): il loro nome è il `title`;
/// una voce vi appartiene mettendo l'`item_id` della voce-cartella in `folder` (ADR-0021).
/// Così "il server non deve sapere che esiste 'Banche'" (doc 17 §2) e non serve nessuna
/// colonna/tabella in chiaro (doc 11, doc 12 §12).
///
/// Codificato in CBOR deterministico (mappa a chiavi intere, definite-length, doc 16 §1).
/// Le chiavi sono **stabili per sempre** (formato persistito, doc 16): i campi futuri si
/// aggiungono come `Option`/nuove chiavi, mai rinumerando le esistenti.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct ItemContent {
    /// Titolo della voce (segreto come il resto del contenuto). Per una cartella è il nome.
    #[n(0)]
    pub title: String,
    /// Cartella di appartenenza: `item_id` (raw 16B) della voce-cartella (ADR-0021).
    /// `None` = radice del vault.
    #[n(1)]
    pub folder: Option<ByteArray<ID_LEN>>,
    /// Flag preferito (doc 17 §2): vive nel ciphertext, mai in chiaro.
    #[n(2)]
    pub favorite: bool,
    /// Campi personalizzati definiti dall'utente, oltre a quelli tipizzati di `data`.
    #[n(3)]
    pub custom_fields: Vec<CustomField>,
    /// Payload tipizzato della voce (il tipo è parte del contenuto cifrato, SR-25).
    #[n(4)]
    pub data: ItemData,
}

/// Campo personalizzato di una voce (doc 17 §2). `hidden` segnala un valore sensibile da
/// mascherare nell'UI (stile password).
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct CustomField {
    #[n(0)]
    pub label: String,
    #[n(1)]
    pub value: String,
    #[n(2)]
    pub hidden: bool,
}

/// Payload tipizzato della voce (doc 17 §2). Le chiavi 0-3 sono storiche
/// (Login/SecureNote/Card/Identity): non si rinumerano mai (formato "supportato per
/// sempre", doc 16). `Folder` (4) rende la cartella una voce cifrata (ADR-0021).
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub enum ItemData {
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
    /// Cartella: contenitore cifrato; il nome è in [`ItemContent::title`], nessun campo
    /// proprio. Le voci vi puntano via [`ItemContent::folder`] (ADR-0021).
    #[n(4)]
    Folder {},
}

/// Serializza il contenuto in CBOR deterministico.
pub fn encode_content(content: &ItemContent) -> CoreResult<Vec<u8>> {
    cbor::encode(content)
}

/// Deserializza il contenuto CBOR. Input non valido → `InvalidInput`. Il contenuto è il
/// plaintext autenticato dalla CEK, quindi non si esige qui la forma canonica.
pub fn decode_content(bytes: &[u8]) -> CoreResult<ItemContent> {
    cbor::decode(bytes)
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
    let wrapped_cek = keywrap::pack(cek_nonce, &cek_ct);

    // item ciphertext: contenuto cifrato con la CEK, legato a vault_id‖item_id.
    let item_ct = aead::encrypt(
        cek,
        item_nonce,
        &aad(ITEM_LABEL, vault_id, item_id),
        content_cbor,
    )?;
    let ciphertext = keywrap::pack(item_nonce, &item_ct);

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
    let (cek_nonce, cek_ct) = keywrap::split(wrapped_cek)?;
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

    let (item_nonce, item_ct) = keywrap::split(ciphertext)?;
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

    /// Login "nudo" (radice, non preferito, niente campi extra): payload tipico.
    fn login() -> ItemContent {
        ItemContent {
            title: "Example".into(),
            folder: None,
            favorite: false,
            custom_fields: vec![],
            data: ItemData::Login {
                username: "alice".into(),
                password: "s3gr3t0".into(),
                uris: vec!["https://example.com".into()],
                notes: "nota".into(),
            },
        }
    }

    /// Login completo del wrapper: in cartella, preferito, con un campo personalizzato.
    fn login_in_folder() -> ItemContent {
        ItemContent {
            title: "Email".into(),
            folder: Some(ByteArray::from([0x11; ID_LEN])),
            favorite: true,
            custom_fields: vec![CustomField {
                label: "PIN".into(),
                value: "1234".into(),
                hidden: true,
            }],
            data: ItemData::Login {
                username: "alice".into(),
                password: "s3gr3t0".into(),
                uris: vec!["https://example.com".into()],
                notes: "nota".into(),
            },
        }
    }

    /// Una cartella: il nome è il `title`, il payload è `Folder` senza campi (ADR-0021).
    fn folder() -> ItemContent {
        ItemContent {
            title: "Banche".into(),
            folder: None,
            favorite: false,
            custom_fields: vec![],
            data: ItemData::Folder {},
        }
    }

    /// Le fixture che coprono lo spettro dello schema: login nudo, login completo
    /// (cartella+preferito+campo personalizzato), cartella.
    fn fixtures() -> [ItemContent; 3] {
        [login(), login_in_folder(), folder()]
    }

    #[test]
    fn cbor_deterministico_e_round_trip() {
        for c in fixtures() {
            let a = encode_content(&c).unwrap();
            let b = encode_content(&c).unwrap();
            assert_eq!(a, b, "encoding deterministico");
            assert_eq!(decode_content(&a).unwrap(), c, "round-trip");
        }
    }

    /// Schema CBOR byte-esatto del wrapper (formato "supportato per sempre", doc 16): blocca
    /// chiavi e layout. Il wrapper ha chiavi 0-4 (`folder` opzionale: se `None` la chiave 1 è
    /// omessa); `data` (chiave 4) porta l'enum `ItemData` come `[indice, {campi}]`.
    #[test]
    fn schema_cbor_byte_esatto() {
        // folder() → mappa CBOR di 4 chiavi (folder=None → chiave 1 assente):
        //   a4                  mappa di 4
        //   00 66 42616e636865  0: title = "Banche" (tstr, 6 byte)
        //   02 f4               2: favorite = false
        //   03 80               3: custom_fields = []
        //   04 82 04 a0         4: data = ItemData::Folder → [4, {}]
        let expected = "a4 00 66 42616e636865 02 f4 03 80 04 82 04 a0".replace(' ', "");
        assert_eq!(hex::encode(encode_content(&folder()).unwrap()), expected);
    }

    #[test]
    fn item_round_trip() {
        for c in fixtures() {
            let cbor = encode_content(&c).unwrap();
            let (ct, wcek) =
                encrypt_item_with(&VK, &VAULT, &ITEM, &cbor, &CEK, &CEK_NONCE, &ITEM_NONCE)
                    .unwrap();
            let got = decrypt_item(&VK, &VAULT, &ITEM, &ct, &wcek).unwrap();
            assert_eq!(&*got, &cbor);
            assert_eq!(decode_content(&got).unwrap(), c);
        }
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
