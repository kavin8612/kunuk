//! Motore crittografico zero-knowledge di Kunuk (ADR-0004).
//!
//! Superficie unica condivisa da desktop, estensione, mobile e CLI (nativo, WASM,
//! FFI). Implementa i formati del doc 16 e i flussi del doc 05; il contratto pubblico
//! è nel doc 20. Tutta la crittografia del progetto vive qui (SR-1, SR-6): fuori dal
//! core è vietato importare primitive crittografiche.
//!
//! Stato: scheletro (task 0.3). I moduli sono dichiarati ma vuoti; primitive e flussi
//! arrivano dai task 0.4–0.7 e 1.2 (vedi doc 22).

// Il core non usa codice unsafe: l'unsafe dei binding di piattaforma (UniFFI/WASM)
// vivrà in `bindings/`, fuori da questa libreria.
#![forbid(unsafe_code)]

pub mod account;
pub mod crypto;
pub mod envelope;
pub mod error;
pub mod keys;
pub mod recovery;
pub mod sync;
pub mod vault;

pub use account::{
    derive_auth_verifier, enable_biometric_unlock, enable_passkey_unlock, register,
    unlock_with_device_key, unlock_with_passkey, unlock_with_password, EmergencyKit,
    RegistrationBundle, VaultKey,
};
pub use error::{CoreError, CoreResult};
pub use recovery::{recover_unlock, recovery_sign_request, recovery_verify_request};
