//! Errori del crypto-core.
//!
//! Un solo tipo per tutta la superficie pubblica (doc 20 §2). Gli errori sono
//! *grossolani* per costruzione: non rivelano dettagli sfruttabili come oracoli
//! (doc 16 §7). In particolare `DecryptFailed` non distingue se a fallire sia il tag
//! AEAD, l'AAD o il formato.

use thiserror::Error;

/// Errore unico del crypto-core (doc 20 §2). Varianti poche e generiche: la UX la
/// decide il chiamante, il core non spiega *perché* un'operazione è fallita.
#[derive(Debug, Error)]
pub enum CoreError {
    /// Input non valido o malformato, rilevato prima di qualunque operazione.
    #[error("input non valido")]
    InvalidInput,

    /// Autenticazione o verifica di firma fallita (es. prova di possesso, manifest,
    /// login OPAQUE).
    #[error("autenticazione fallita")]
    AuthFailed,

    /// Decifratura fallita: tag AEAD, AAD o formato non verificano. Nessun dettaglio
    /// ulteriore, per non offrire oracoli (doc 16 §7).
    #[error("decifratura fallita")]
    DecryptFailed,

    /// Header con `version`/`suite` sconosciute: rifiuto senza fallback
    /// (anti-downgrade, doc 16 §2).
    #[error("versione o suite non supportata")]
    UnsupportedVersion,

    /// Errore interno non riconducibile alle altre varianti (invariante violata).
    #[error("errore interno")]
    Internal,
}

/// Alias di comodo per i risultati del core.
pub type CoreResult<T> = Result<T, CoreError>;
