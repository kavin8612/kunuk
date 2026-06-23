//! Guscio Tauri del client desktop Kunuk (task 1.3). Linka il crypto-core **nativamente**
//! (ADR-0004): nessun binding FFI/WASM, a differenza di estensione (WASM) e mobile (UniFFI).
//! La VK vive nello stato gestito da Tauri (`session::Session`), mai esposta a React.

mod api;
mod commands;
mod config;
mod generator;
mod items;
mod session;
mod settings;
mod util;
mod vault_sync;

use std::time::Duration;

use tauri::Manager;

use config::AppConfig;
use session::Session;
use settings::SettingsStore;

const WATCHDOG_POLL_INTERVAL: Duration = Duration::from_secs(30);

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let config = AppConfig::from_env().expect("configurazione di processo");
    tauri::Builder::default()
        .manage(config)
        .manage(Session::default())
        .setup(|app| {
            let settings_path = app
                .path()
                .app_config_dir()
                .expect("percorso di configurazione dell'app")
                .join("settings.json");
            app.manage(SettingsStore::load(settings_path));

            let handle = app.handle().clone();
            std::thread::spawn(move || loop {
                std::thread::sleep(WATCHDOG_POLL_INTERVAL);
                watchdog_tick(&handle);
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::register,
            commands::login,
            commands::lock,
            commands::is_unlocked,
            settings::get_settings,
            settings::save_settings,
            items::list_items,
            items::create_item,
            items::update_item,
            items::delete_item,
            generator::generate_password,
            generator::generate_passphrase,
        ])
        .run(tauri::generate_context!())
        .expect("avvio dell'app Tauri");
}

/// Argine di auto-lock indipendente da React (doc 17 §9, scoperto in code review): se nessun
/// comando autenticato arriva per l'intero timeout configurato, blocca comunque — anche se il
/// renderer si è bloccato, è stato compromesso, o ha semplicemente smesso di chiamare `lock()`
/// da solo. Si basa sul traffico IPC come proxy di attività (Rust non ha visibilità sugli
/// eventi DOM, quello fine resta lato JS in `useAutoLock.ts`): nell'uso legittimo coincide con
/// l'idle-timer di React, che chiama `lock()` per primo — qui scatta solo come backstop.
fn watchdog_tick(handle: &tauri::AppHandle) {
    let session = handle.state::<Session>();
    let settings = handle.state::<SettingsStore>();
    let timeout = Duration::from_secs(u64::from(settings.get().auto_lock_minutes) * 60);

    let idle_for = match session.last_activity.lock() {
        Ok(last) => last.elapsed(),
        Err(_) => return,
    };
    if idle_for < timeout {
        return;
    }
    if let Ok(mut guard) = session.unlocked.lock() {
        if let Some(unlocked) = guard.take() {
            unlocked.vk.lock();
        }
    };
}
