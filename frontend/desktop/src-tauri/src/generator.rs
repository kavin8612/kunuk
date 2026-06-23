//! Comandi Tauri del generatore di password/passphrase (task 1.3/C3, doc 17 §3).
//! Pura selezione del CSPRNG del core: nessuna chiave, nessuna sessione — funziona
//! anche a vault bloccato (coerente con `kunuk_crypto_core::generator`, doc 20 §9).

use kunuk_crypto_core::{
    generate_passphrase as core_generate_passphrase, generate_password as core_generate_password,
    PassphraseLang, PasswordPolicy,
};
use serde::Deserialize;

use crate::util::ce;

/// Mirror JSON di [`PasswordPolicy`] (snake_case: confine interno app↔webview, non
/// l'API REST di doc 12).
#[derive(Deserialize)]
pub struct PasswordPolicyDto {
    pub length: usize,
    pub uppercase: bool,
    pub lowercase: bool,
    pub numbers: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
}

impl From<PasswordPolicyDto> for PasswordPolicy {
    fn from(dto: PasswordPolicyDto) -> Self {
        PasswordPolicy {
            length: dto.length,
            uppercase: dto.uppercase,
            lowercase: dto.lowercase,
            numbers: dto.numbers,
            symbols: dto.symbols,
            exclude_ambiguous: dto.exclude_ambiguous,
        }
    }
}

#[tauri::command]
pub fn generate_password(policy: PasswordPolicyDto) -> Result<String, String> {
    core_generate_password(&policy.into()).map_err(ce)
}

#[tauri::command]
pub fn generate_passphrase(
    lang: String,
    words: usize,
    separator: String,
) -> Result<String, String> {
    let lang = match lang.as_str() {
        "it" => PassphraseLang::It,
        "en" => PassphraseLang::En,
        _ => return Err("lingua non valida".into()),
    };
    core_generate_passphrase(lang, words, &separator).map_err(ce)
}
