//! CLI minima di Kunuk (task 0.10, gate Fase 0).
//!
//! Esercita end-to-end la fondamenta zero-knowledge usando il `crypto-core` per la
//! crittografia (la CLI non implementa primitive, SR-1) e il backend Go via HTTP per lo
//! storage opaco: registrazione → login → sblocco → upload di un item cifrato → rilettura e
//! decifratura → verifica del manifest firmato.
//!
//! Limite noto del gate (lacuna doc↔implementazione registrata nel doc 22): `account_id` e
//! `vault_id` sono scelti/tenuti dal client **in memoria** per l'intera cerimonia. Un
//! dispositivo "vergine" non può ancora ricostruirli (servirebbe esporli al login con decoy
//! anti-enumeration): è materia di un task+ADR dedicato.

pub mod api;
pub mod ceremony;
pub mod codec;

pub use ceremony::{run_gate, GateConfig};
