//! Errori del crypto-core.
//!
//! Un solo tipo per tutta la superficie pubblica (doc 20 §2). Gli errori sono
//! *grossolani* per costruzione: non rivelano dettagli sfruttabili come oracoli
//! (doc 16 §7). In particolare `DecryptFailed` non distingue se a fallire sia il tag
//! AEAD, l'AAD o il formato.
//!
//! Implementazione a mano di `Display`/`Error` (scheletro 0.3, zero dipendenze):
//! `thiserror` (doc 19 §4) entra al task 0.4 con le prime dipendenze, quando il
//! toolchain locale potrà bloccare il lockfile (doc 19 §5.4).

use std::fmt;

/// Errore unico del crypto-core (doc 20 §2). Varianti poche e generiche: la UX la
/// decide il chiamante, il core non spiega *perché* un'operazione è fallita.
#[derive(Debug)]
pub enum CoreError {
    /// Input non valido o malformato, rilevato prima di qualunque operazione.
    InvalidInput,

    /// Autenticazione fallita (es. prova di possesso o login OPAQUE non validi).
    AuthFailed,

    /// Decifratura fallita: tag AEAD, AAD o formato non verificano. Nessun dettaglio
    /// ulteriore, per non offrire oracoli (doc 16 §7).
    DecryptFailed,

    /// Header con `version`/`suite` sconosciute: rifiuto senza fallback
    /// (anti-downgrade, doc 16 §2).
    UnsupportedVersion,

    /// Errore interno non riconducibile alle altre varianti (invariante violata).
    Internal,
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let messaggio = match self {
            CoreError::InvalidInput => "input non valido",
            CoreError::AuthFailed => "autenticazione fallita",
            CoreError::DecryptFailed => "decifratura fallita",
            CoreError::UnsupportedVersion => "versione o suite non supportata",
            CoreError::Internal => "errore interno",
        };
        f.write_str(messaggio)
    }
}

impl std::error::Error for CoreError {}

/// Alias di comodo per i risultati del core.
pub type CoreResult<T> = Result<T, CoreError>;
