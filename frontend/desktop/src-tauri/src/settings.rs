//! Impostazioni di sicurezza (doc 17 §9: auto-lock/clipboard-clear configurabili) —
//! possedute da Rust, non dal renderer (scoperto in code review: vivevano in `localStorage`,
//! scrivibile da qualunque script nel webview, diversamente da tutto il resto che conta per
//! la sicurezza — VK, token, chiave di firma — che vive solo qui apposta). React le legge e
//! le scrive solo tramite i comandi qui sotto, mai direttamente.

use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tauri::State;

const DEFAULT_AUTO_LOCK_MINUTES: u32 = 15;
const DEFAULT_CLIPBOARD_CLEAR_SECONDS: u32 = 30;
const MIN_AUTO_LOCK_MINUTES: u32 = 1;
const MAX_AUTO_LOCK_MINUTES: u32 = 120;
const MIN_CLIPBOARD_CLEAR_SECONDS: u32 = 5;
const MAX_CLIPBOARD_CLEAR_SECONDS: u32 = 300;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AppSettings {
    pub auto_lock_minutes: u32,
    pub clipboard_clear_seconds: u32,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            auto_lock_minutes: DEFAULT_AUTO_LOCK_MINUTES,
            clipboard_clear_seconds: DEFAULT_CLIPBOARD_CLEAR_SECONDS,
        }
    }
}

impl AppSettings {
    fn clamped(self) -> Self {
        Self {
            auto_lock_minutes: self
                .auto_lock_minutes
                .clamp(MIN_AUTO_LOCK_MINUTES, MAX_AUTO_LOCK_MINUTES),
            clipboard_clear_seconds: self
                .clipboard_clear_seconds
                .clamp(MIN_CLIPBOARD_CLEAR_SECONDS, MAX_CLIPBOARD_CLEAR_SECONDS),
        }
    }
}

/// Stato gestito da Tauri: legge il file delle impostazioni una volta all'avvio (`load`), poi
/// serve dalla cache in memoria; `save` scrive il file e SOLO se riesce aggiorna la cache —
/// niente disallineamento fra ciò che è su disco e ciò che l'app crede di avere salvato.
pub struct SettingsStore {
    path: PathBuf,
    current: Mutex<AppSettings>,
}

impl SettingsStore {
    pub fn load(path: PathBuf) -> Self {
        let current = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<AppSettings>(&bytes).ok())
            .unwrap_or_default()
            .clamped();
        Self {
            path,
            current: Mutex::new(current),
        }
    }

    /// Non può fallire in modo osservabile: un mutex avvelenato (panic altrove mentre lo si
    /// teneva — non dovrebbe mai accadere, niente unwrap/panic in questo modulo) ricade sui
    /// default piuttosto che propagare un errore a un chiamante (il watchdog di `lib.rs`) che
    /// non saprebbe come reagire diversamente.
    pub fn get(&self) -> AppSettings {
        match self.current.lock() {
            Ok(current) => *current,
            Err(_) => AppSettings::default(),
        }
    }

    fn save(&self, next: AppSettings) -> Result<AppSettings, String> {
        let next = next.clamped();
        let bytes = serde_json::to_vec_pretty(&next).map_err(|e| e.to_string())?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(&self.path, bytes).map_err(|e| e.to_string())?;
        if let Ok(mut current) = self.current.lock() {
            *current = next;
        }
        Ok(next)
    }
}

#[tauri::command]
pub fn get_settings(store: State<SettingsStore>) -> AppSettings {
    store.get()
}

#[tauri::command]
pub fn save_settings(
    store: State<SettingsStore>,
    settings: AppSettings,
) -> Result<AppSettings, String> {
    store.save(settings)
}
