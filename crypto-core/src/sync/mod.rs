//! Merge offline-first via CRDT (Automerge, ADR-0018/ADR-0022); il core cifra e fonde,
//! il trasporto è del client/backend (doc 20 §8).
//!
//! **Cosa fonde la CRDT (ADR-0022):** solo la *directory* del vault — per ogni item,
//! `{version, deleted}` — non il contenuto. Il contenuto di un item resta cifrato con
//! una CEK propria avvolta dalla VK (SR-4, invariato da doc 16 §5): il delta CRDT è un
//! oggetto separato, cifrato direttamente con la VK (niente CEK, vedi `sync_change` in
//! doc 11). La directory risolta alimenta `ManifestContent::items`/`crdt_clock`
//! (doc 16 §6), così il manifest firmato resta lo snapshot autorevole e firmato dello
//! stato CRDT convergente.

use automerge::transaction::Transactable;
use automerge::{ActorId, AutoCommit, ReadDoc, ScalarValue, Value, ROOT};

use crate::crypto::aead::{self, NONCE_LEN};
use crate::crypto::header;
use crate::crypto::keywrap;
use crate::crypto::params::KEY_LEN;
use crate::crypto::rng;
use crate::error::{CoreError, CoreResult};
use crate::vault::item::ID_LEN;
use crate::vault::manifest::ItemRef;

/// Etichetta di dominio dell'AAD del delta di sync (doc 16 §8).
const SYNC_LABEL: &[u8] = b"kunuk/v1/sync";

/// Vista convergente della directory dopo l'applicazione di uno o più delta
/// (doc 20 §8): le voci risultanti e il clock CRDT da riportare nel prossimo manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeResult {
    /// Voci non eliminate, ordinate per `item_id` (stesso ordine canonico del manifest).
    pub items: Vec<ItemRef>,
    /// Clock CRDT opaco (i "heads" di Automerge) da riportare in `ManifestContent`.
    pub crdt_clock: Vec<u8>,
}

/// Documento CRDT locale della directory di un vault (handle con stato esplicito, doc 20
/// §1: niente stato globale). Ogni dispositivo ne mantiene una copia persistita tra le
/// esecuzioni; non contiene mai il contenuto degli item, solo `{item_id -> version,
/// deleted}`.
pub struct SyncDoc {
    doc: AutoCommit,
}

impl Default for SyncDoc {
    fn default() -> Self {
        Self::new()
    }
}

impl SyncDoc {
    /// Nuovo documento vuoto con un actor id casuale (CSPRNG).
    pub fn new() -> Self {
        Self {
            doc: AutoCommit::new(),
        }
    }

    /// Nuovo documento vuoto con un actor id esplicito (deterministico: solo per test e
    /// vettori, doc 20 §1).
    pub fn new_with_actor(actor: &[u8]) -> Self {
        Self {
            doc: AutoCommit::new().with_actor(ActorId::from(actor)),
        }
    }

    /// Ricostruisce un documento dai byte di un changeset completo precedentemente
    /// ottenuto da [`SyncDoc::save`] (es. al riavvio di un dispositivo che persiste lo
    /// stato locale). Byte malformati → `InvalidInput`.
    pub fn load(bytes: &[u8]) -> CoreResult<Self> {
        let doc = AutoCommit::load(bytes).map_err(|_| CoreError::InvalidInput)?;
        Ok(Self { doc })
    }

    /// Serializza l'intero documento (per la persistenza locale tra esecuzioni). Non è
    /// il formato che viaggia in rete (quello è il delta incrementale cifrato, vedi
    /// [`sync_encode_delta`]).
    pub fn save(&mut self) -> Vec<u8> {
        self.doc.save()
    }

    /// Registra una modifica locale a un item: versione (monotona per il dispositivo
    /// che scrive) e flag di eliminazione (tombstone). Operazione locale, non tocca la
    /// rete: i cambiamenti non ancora inviati si raccolgono con
    /// [`SyncDoc::take_pending_changes`].
    ///
    /// Scrive direttamente sotto la radice del documento (`ROOT`), non in una mappa
    /// annidata: `ROOT` esiste sempre e per costruzione, mentre una mappa creata con
    /// `put_object` da due dispositivi offline che non si sono ancora mai sincronizzati
    /// produrrebbe due oggetti concorrenti distinti (la creazione stessa è un'operazione
    /// che può divergere), perdendo le voci dell'uno o dell'altro al merge.
    pub fn record_item_change(
        &mut self,
        item_id: &[u8; ID_LEN],
        version: u64,
        deleted: bool,
    ) -> CoreResult<()> {
        let encoded = pack(version, deleted).ok_or(CoreError::InvalidInput)?;
        self.doc
            .put(ROOT, item_key(item_id), encoded)
            .map_err(|_| CoreError::Internal)
    }

    /// Estrae (e segna come inviati) i cambiamenti locali non ancora condivisi, in
    /// formato Automerge nativo. È l'input di [`sync_encode_delta`]; chiamate
    /// successive senza nuove modifiche restituiscono un buffer vuoto.
    ///
    /// **Contratto per il chiamante:** questa chiamata avanza irreversibilmente il marcatore
    /// "già condiviso" del documento, indipendentemente dal fatto che i byte restituiti
    /// arrivino davvero al server. Se l'invio fallisce (rete, errore HTTP), il chiamante
    /// **deve** conservare i byte già estratti e ritentare con quegli stessi byte: richiamare
    /// di nuovo `take_pending_changes` dopo un fallimento restituisce un buffer vuoto, non gli
    /// stessi cambiamenti, e la modifica locale andrebbe persa silenziosamente.
    pub fn take_pending_changes(&mut self) -> Vec<u8> {
        self.doc.save_incremental()
    }

    /// Applica un changeset Automerge ricevuto da un altro dispositivo (già decifrato).
    /// Byte malformati o incompatibili → `InvalidInput` (il server può solo inoltrare,
    /// non leggere: un changeset corrotto è un errore di formato, non un oracolo, doc
    /// 16 §7).
    pub fn apply_changes(&mut self, raw_changes: &[u8]) -> CoreResult<()> {
        self.doc
            .load_incremental(raw_changes)
            .map(|_| ())
            .map_err(|_| CoreError::InvalidInput)
    }

    /// Risolve la directory convergente: per ogni item, tra i candidati concorrenti
    /// prende quello con il valore più alto (la codifica fa vincere "eliminato" a parità
    /// di versione, vedi [`pack`]) — funzione deterministica e commutativa, stesso
    /// risultato su ogni dispositivo indipendentemente dall'ordine di merge (proprietà
    /// CRDT). Le voci eliminate non compaiono nel risultato.
    pub fn snapshot(&mut self) -> CoreResult<MergeResult> {
        let crdt_clock = encode_heads(&mut self.doc);
        let keys: Vec<String> = self.doc.keys(ROOT).collect();

        let mut items = Vec::new();
        for key in keys {
            let Some(id_hex) = key.strip_prefix(ITEM_KEY_PREFIX) else {
                continue;
            };
            let candidates = self
                .doc
                .get_all(ROOT, key.as_str())
                .map_err(|_| CoreError::Internal)?;
            // Solo interi non negativi sono candidati validi (è la sola forma che `pack`
            // produce): un changeset corrotto o estraneo che scrivesse un altro tipo o un
            // intero negativo viene scartato qui, non propagato come versione assurda.
            let best = candidates
                .into_iter()
                .filter_map(|(value, _)| match value {
                    Value::Scalar(s) => match s.as_ref() {
                        ScalarValue::Int(n) if *n >= 0 => Some(*n),
                        _ => None,
                    },
                    _ => None,
                })
                .max();
            let Some(encoded) = best else { continue };
            let (version, deleted) = unpack(encoded);
            if deleted {
                continue;
            }
            let item_id = unhex_key(id_hex)?;
            items.push(ItemRef {
                item_id: item_id.into(),
                item_version: version,
            });
        }
        items.sort_by(|a, b| a.item_id[..].cmp(&b.item_id[..]));
        Ok(MergeResult { items, crdt_clock })
    }
}

/// Codifica `(version, deleted)` in un solo registro CRDT: il bit basso porta il flag di
/// eliminazione, così a parità di versione un tombstone vince sempre su un edit
/// (`(v<<1)|1 > (v<<1)|0`) — risoluzione dei conflitti deterministica con un solo
/// confronto numerico, senza dover correlare due chiavi separate. `None` se `version` non
/// rientra nell'intervallo rappresentabile (fail-closed anche su input fuori specifica, doc
/// 16 §7): in pratica `version` è un contatore di modifiche per item, mai vicino al limite.
fn pack(version: u64, deleted: bool) -> Option<i64> {
    if version > (i64::MAX as u64) >> 1 {
        return None;
    }
    Some(((version << 1) | u64::from(deleted)) as i64)
}

fn unpack(encoded: i64) -> (u64, bool) {
    let raw = encoded as u64;
    (raw >> 1, raw & 1 == 1)
}

/// Prefisso delle chiavi `ROOT` che portano lo stato `{version, deleted}` di un item
/// (le altre chiavi sotto `ROOT`, se in futuro ce ne fossero, non vengono toccate).
const ITEM_KEY_PREFIX: &str = "item:";

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

/// Chiave `ROOT` (testuale) per un item: prefisso fisso + esadecimale minuscolo dell'id
/// raw. Automerge ammette solo chiavi `&str`, da cui la codifica.
fn item_key(id: &[u8; ID_LEN]) -> String {
    let mut s = String::with_capacity(ITEM_KEY_PREFIX.len() + ID_LEN * 2);
    s.push_str(ITEM_KEY_PREFIX);
    s.push_str(&hex_key(id));
    s
}

fn hex_key(id: &[u8; ID_LEN]) -> String {
    let mut s = String::with_capacity(ID_LEN * 2);
    for b in id {
        s.push(HEX_CHARS[(b >> 4) as usize] as char);
        s.push(HEX_CHARS[(b & 0x0f) as usize] as char);
    }
    s
}

/// Inversa di [`hex_key`]. Chiave malformata (lunghezza o cifre non hex) → `InvalidInput`:
/// può capitare solo con un changeset CRDT corrotto o estraneo.
fn unhex_key(s: &str) -> CoreResult<[u8; ID_LEN]> {
    let bytes = hex_decode(s).ok_or(CoreError::InvalidInput)?;
    bytes.try_into().map_err(|_| CoreError::InvalidInput)
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.as_bytes();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.chunks_exact(2) {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Concatenazione canonica (ordinata) degli heads Automerge correnti: rappresentazione
/// opaca del clock CRDT (doc 16 §6), stessi byte su ogni dispositivo allo stesso stato.
fn encode_heads(doc: &mut AutoCommit) -> Vec<u8> {
    let mut heads: Vec<[u8; 32]> = doc.get_heads().iter().map(|h| h.0).collect();
    heads.sort_unstable();
    heads.into_iter().flatten().collect()
}

fn aad(vault_id: &[u8; ID_LEN]) -> Vec<u8> {
    let mut a = Vec::with_capacity(header::HEADER_LEN + SYNC_LABEL.len() + ID_LEN);
    a.extend_from_slice(&header::header_v1());
    a.extend_from_slice(SYNC_LABEL);
    a.extend_from_slice(vault_id);
    a
}

/// Cifra un delta CRDT con un nonce esplicito (deterministico, per i test vettoriali). In
/// produzione usare [`sync_encode_delta`]. Formato: `header ‖ nonce ‖ delta_cifrato ‖ tag`,
/// AAD legata a `vault_id` (anti-trapianto tra vault, come la busta della chiave di firma).
pub fn sync_encode_delta_with_nonce(
    vk: &[u8; KEY_LEN],
    vault_id: &[u8; ID_LEN],
    local_changes: &[u8],
    nonce: &[u8; NONCE_LEN],
) -> CoreResult<Vec<u8>> {
    let ct = aead::encrypt(vk, nonce, &aad(vault_id), local_changes)?;
    Ok(keywrap::pack(nonce, &ct))
}

/// Cifra un delta CRDT (`local_changes` da [`SyncDoc::take_pending_changes`]) generando un
/// nonce fresco dal CSPRNG (doc 16 §7). È l'oggetto che il client invia a `POST
/// /v1/sync/changes` (doc 20 §8).
pub fn sync_encode_delta(
    vk: &[u8; KEY_LEN],
    vault_id: &[u8; ID_LEN],
    local_changes: &[u8],
) -> CoreResult<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    rng::fill(&mut nonce)?;
    sync_encode_delta_with_nonce(vk, vault_id, local_changes, &nonce)
}

/// Decifra un singolo delta CRDT cifrato con [`sync_encode_delta`]. Tag/AAD non
/// verificano (incluso il trapianto su un altro vault) → `DecryptFailed`.
fn decrypt_delta(
    vk: &[u8; KEY_LEN],
    vault_id: &[u8; ID_LEN],
    encrypted: &[u8],
) -> CoreResult<Vec<u8>> {
    let (nonce, ct) = keywrap::split(encrypted)?;
    aead::decrypt(vk, nonce, &aad(vault_id), ct)
}

/// Decifra e applica una sequenza di delta CRDT ricevuti da `GET /v1/sync/changes`
/// (doc 20 §8) al documento locale `doc`, poi ne risolve la directory convergente.
/// Un delta che non decifra o non si applica interrompe l'operazione (fail-closed): il
/// chiamante riprova dal cursore dell'ultimo delta applicato con successo.
pub fn sync_apply_deltas(
    doc: &mut SyncDoc,
    vk: &[u8; KEY_LEN],
    vault_id: &[u8; ID_LEN],
    encrypted_deltas: &[Vec<u8>],
) -> CoreResult<MergeResult> {
    for encrypted in encrypted_deltas {
        let raw = decrypt_delta(vk, vault_id, encrypted)?;
        doc.apply_changes(&raw)?;
    }
    doc.snapshot()
}

#[cfg(test)]
mod tests {
    use super::*;

    const VK: [u8; KEY_LEN] = [0x11; KEY_LEN];
    const VAULT: [u8; ID_LEN] = [0x22; ID_LEN];
    const ITEM_A: [u8; ID_LEN] = [0x01; ID_LEN];
    const ITEM_B: [u8; ID_LEN] = [0x02; ID_LEN];

    #[test]
    fn delta_round_trip() {
        let mut a = SyncDoc::new_with_actor(&[0xAA]);
        a.record_item_change(&ITEM_A, 1, false).unwrap();
        let changes = a.take_pending_changes();
        let encrypted = sync_encode_delta(&VK, &VAULT, &changes).unwrap();

        let mut b = SyncDoc::new_with_actor(&[0xBB]);
        let merged = sync_apply_deltas(&mut b, &VK, &VAULT, &[encrypted]).unwrap();
        assert_eq!(merged.items.len(), 1);
        assert_eq!(merged.items[0].item_version, 1);
        assert!(!merged.crdt_clock.is_empty());
    }

    #[test]
    fn pending_changes_si_svuota_dopo_take() {
        let mut a = SyncDoc::new_with_actor(&[0xAA]);
        a.record_item_change(&ITEM_A, 1, false).unwrap();
        assert!(!a.take_pending_changes().is_empty());
        assert!(
            a.take_pending_changes().is_empty(),
            "nessuna modifica nuova"
        );
    }

    #[test]
    fn convergenza_indipendente_dall_ordine_di_merge() {
        // Due dispositivi editano item diversi offline, poi si scambiano i delta in
        // ordine opposto: la proprietà CRDT garantisce lo stesso stato finale.
        let mut dev_a = SyncDoc::new_with_actor(&[0xAA]);
        dev_a.record_item_change(&ITEM_A, 1, false).unwrap();
        let delta_a = sync_encode_delta(&VK, &VAULT, &dev_a.take_pending_changes()).unwrap();

        let mut dev_b = SyncDoc::new_with_actor(&[0xBB]);
        dev_b.record_item_change(&ITEM_B, 1, false).unwrap();
        let delta_b = sync_encode_delta(&VK, &VAULT, &dev_b.take_pending_changes()).unwrap();

        let mut peer_1 = SyncDoc::new_with_actor(&[0xCC]);
        let merged_1 = sync_apply_deltas(
            &mut peer_1,
            &VK,
            &VAULT,
            &[delta_a.clone(), delta_b.clone()],
        )
        .unwrap();

        let mut peer_2 = SyncDoc::new_with_actor(&[0xDD]);
        let merged_2 = sync_apply_deltas(&mut peer_2, &VK, &VAULT, &[delta_b, delta_a]).unwrap();

        assert_eq!(merged_1.items, merged_2.items);
        assert_eq!(merged_1.crdt_clock, merged_2.crdt_clock);
        assert_eq!(merged_1.items.len(), 2);
    }

    #[test]
    fn edit_concorrente_stesso_item_converge_su_versione_massima() {
        let mut dev_a = SyncDoc::new_with_actor(&[0xAA]);
        dev_a.record_item_change(&ITEM_A, 5, false).unwrap();
        let delta_a = sync_encode_delta(&VK, &VAULT, &dev_a.take_pending_changes()).unwrap();

        let mut dev_b = SyncDoc::new_with_actor(&[0xBB]);
        dev_b.record_item_change(&ITEM_A, 9, false).unwrap();
        let delta_b = sync_encode_delta(&VK, &VAULT, &dev_b.take_pending_changes()).unwrap();

        let mut peer = SyncDoc::new_with_actor(&[0xCC]);
        let merged = sync_apply_deltas(&mut peer, &VK, &VAULT, &[delta_a, delta_b]).unwrap();
        assert_eq!(merged.items.len(), 1);
        assert_eq!(
            merged.items[0].item_version, 9,
            "vince la versione più alta"
        );
    }

    #[test]
    fn delete_vince_a_parita_di_versione() {
        let mut dev_a = SyncDoc::new_with_actor(&[0xAA]);
        dev_a.record_item_change(&ITEM_A, 3, false).unwrap();
        let delta_a = sync_encode_delta(&VK, &VAULT, &dev_a.take_pending_changes()).unwrap();

        let mut dev_b = SyncDoc::new_with_actor(&[0xBB]);
        dev_b.record_item_change(&ITEM_A, 3, true).unwrap();
        let delta_b = sync_encode_delta(&VK, &VAULT, &dev_b.take_pending_changes()).unwrap();

        let mut peer = SyncDoc::new_with_actor(&[0xCC]);
        let merged = sync_apply_deltas(&mut peer, &VK, &VAULT, &[delta_a, delta_b]).unwrap();
        assert!(
            merged.items.is_empty(),
            "il tombstone esclude l'item dalla directory"
        );
    }

    #[test]
    fn version_fuori_intervallo_invalid_input() {
        let mut doc = SyncDoc::new_with_actor(&[0xAA]);
        assert!(matches!(
            doc.record_item_change(&ITEM_A, u64::MAX, false),
            Err(CoreError::InvalidInput)
        ));
    }

    #[test]
    fn trapianto_su_altro_vault_decrypt_failed() {
        let mut a = SyncDoc::new_with_actor(&[0xAA]);
        a.record_item_change(&ITEM_A, 1, false).unwrap();
        let encrypted = sync_encode_delta(&VK, &VAULT, &a.take_pending_changes()).unwrap();

        let mut b = SyncDoc::new_with_actor(&[0xBB]);
        let altro_vault = [0x99; ID_LEN];
        assert!(matches!(
            sync_apply_deltas(&mut b, &VK, &altro_vault, &[encrypted]),
            Err(CoreError::DecryptFailed)
        ));
    }

    #[test]
    fn changeset_corrotto_invalid_input() {
        let encrypted = sync_encode_delta(&VK, &VAULT, b"non e' un changeset automerge").unwrap();
        let mut b = SyncDoc::new_with_actor(&[0xBB]);
        assert!(matches!(
            sync_apply_deltas(&mut b, &VK, &VAULT, &[encrypted]),
            Err(CoreError::InvalidInput)
        ));
    }

    #[test]
    fn save_load_round_trip() {
        let mut a = SyncDoc::new_with_actor(&[0xAA]);
        a.record_item_change(&ITEM_A, 1, false).unwrap();
        let bytes = a.save();
        let mut restored = SyncDoc::load(&bytes).unwrap();
        assert_eq!(restored.snapshot().unwrap(), a.snapshot().unwrap());
    }

    #[test]
    fn load_bytes_malformati_invalid_input() {
        assert!(matches!(
            SyncDoc::load(b"non automerge"),
            Err(CoreError::InvalidInput)
        ));
    }
}
