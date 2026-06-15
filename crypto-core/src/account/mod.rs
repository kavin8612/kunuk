//! Flussi di account del core (doc 20 §3-4).
//!
//! Orchestrazione di alto livello sopra `keys`/`envelope`/`vault`: assembla il bundle
//! di registrazione (B6, `registration`) e apre le buste della VK nello sblocco
//! (B7, `unlock`). Il recupero (B8) vive nel modulo `recovery`. Qui non c'è crittografia
//! nuova: solo composizione delle
//! primitive già coperte dai test vettoriali (doc 16 §8), perciò la copertura è via unit
//! test del flusso, non una nuova categoria di vettori.

pub mod registration;
pub mod unlock;

pub use registration::{
    register, register_with, EmergencyKit, RegistrationBundle, RegistrationRandomness,
};
pub use unlock::{
    derive_auth_verifier, enable_biometric_unlock, enable_passkey_unlock, unlock_with_device_key,
    unlock_with_passkey, unlock_with_password, VaultKey,
};
