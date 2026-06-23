//! Stato della sessione gestito da Tauri (doc 20 §1): la VK vive **solo qui**, lato Rust.
//! I comandi (`commands.rs`, `items.rs`) la consumano come handle opaco; il frontend React
//! non riceve mai byte di chiave, solo contenuto già decifrato o conferme.

use std::sync::Mutex;
use std::time::Instant;

use kunuk_crypto_core::sync::SyncDoc;
use kunuk_crypto_core::VaultKey;

/// Vault sbloccato in questa sessione. `None` finché non si fa login/registrazione, azzerato
/// dal `lock()` di [`VaultKey`].
///
/// `sync_doc` è il documento CRDT locale della directory (item_id → versione/eliminato,
/// ADR-0022): non persiste tra esecuzioni (stessa scelta del task 1.2 per la CLI), si
/// ricostruisce scaricando la storia dei delta dal cursore 0. `wrapped_signing_key` è la
/// busta della chiave di firma (doc 16 §6, da `GET /vault`): la `SigningKey` vera e propria
/// non esce mai dal core (`VaultKey::sign_manifest` la scarta e firma in un'unica chiamata,
/// SR-1) — qui restano solo i byte della busta, da ri-aprire ad ogni firma.
/// `manifest_version` è l'ultima versione vista in questa sessione (anti-rollback locale, doc
/// 16 §6); `sync_cursor` è l'ultimo cursore opaco di `/v1/sync/changes` (mai ricostruito a
/// mano, doc 21).
pub struct UnlockedVault {
    pub vault_id: [u8; 16],
    pub vk: VaultKey,
    /// Token di sessione (Bearer) ottenuto al login/registrazione: senza, nessuna chiamata
    /// autenticata (CRUD voci, sync, manifest) è possibile.
    pub token: String,
    pub wrapped_signing_key: Vec<u8>,
    pub sync_doc: SyncDoc,
    pub manifest_version: u64,
    pub sync_cursor: Option<String>,
}

/// Stato globale dell'app, gestito da Tauri (`app.manage(Session::default())`). Un solo
/// vault sbloccato per processo (coerente con "un vault personale per account", doc 11).
///
/// `last_activity` è l'argine di auto-lock indipendente da React (doc 17 §9, scoperto in
/// code review): l'auto-lock "vero" — quello che reagisce a mouse/tastiera/finestra nascosta
/// — resta lato JS (Rust non ha visibilità sugli eventi DOM), ma se nessun comando
/// autenticato arriva per l'intero timeout configurato (renderer bloccato, compromesso, o che
/// ha semplicemente smesso di chiamare `lock()`), il watchdog di `lib.rs` blocca comunque.
/// `touch()` si chiama dai comandi che operano sul vault sbloccato (CRUD voci, login,
/// registrazione); `lock()`/`is_unlocked` non contano come attività.
pub struct Session {
    pub unlocked: Mutex<Option<UnlockedVault>>,
    pub last_activity: Mutex<Instant>,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            unlocked: Mutex::new(None),
            last_activity: Mutex::new(Instant::now()),
        }
    }
}

impl Session {
    pub fn touch(&self) {
        if let Ok(mut last) = self.last_activity.lock() {
            *last = Instant::now();
        }
    }
}
