// Limiti delle impostazioni di sicurezza (doc 17 §9: timeout di auto-lock e durata di
// pulizia della clipboard, entrambi "configurabili"). Sono parametri di *policy* di
// sicurezza, non semplici preferenze UI: il valore vero e lo storage vivono lato Rust
// (`src-tauri/src/settings.rs`), dietro un comando Tauri, per lo stesso motivo per cui VK e
// token non escono mai da Rust — qui restano solo i limiti, condivisi per validare/clampare
// l'input lato UI prima del round-trip (scoperto in code review: prima erano in
// `localStorage`, scrivibile da qualunque script nel renderer).

export const DEFAULT_AUTO_LOCK_MINUTES = 15;
export const DEFAULT_CLIPBOARD_CLEAR_SECONDS = 30;

export const MIN_AUTO_LOCK_MINUTES = 1;
export const MAX_AUTO_LOCK_MINUTES = 120;
export const MIN_CLIPBOARD_CLEAR_SECONDS = 5;
export const MAX_CLIPBOARD_CLEAR_SECONDS = 300;
