//! CLI minima di Kunuk (task 0.10, gate Fase 0).
//!
//! Esercita end-to-end la fondamenta zero-knowledge usando il `crypto-core` per la
//! crittografia (la CLI non implementa primitive, SR-1) e il backend Go via HTTP per lo
//! storage opaco: registrazione → login → sblocco → upload di un item cifrato → rilettura e
//! decifratura → verifica del manifest firmato.
//!
//! `account_id` e `vault_id` sono scelti dal client e **persistiti** dal server (ADR-0020,
//! task 0.11): esposti al login (`login/start`, con decoy anti-enum SR-26) e su `GET /vault`,
//! così un dispositivo "vergine" (solo email + password + Secret Key) li ricostruisce. La
//! cerimonia include un passo finale che lo verifica.

pub mod api;
pub mod ceremony;
pub mod codec;

pub use ceremony::{run_gate, GateConfig};
