//! Item cifrati per-item e manifest firmato del vault (doc 16 §5–6).
//!
//! Ogni item è cifrato con una CEK propria, avvolta dalla VK; il contenuto e il tipo
//! della voce stanno nel CBOR cifrato (SR-25), mai in chiaro. Il doppio binding
//! `vault_id ‖ item_id` nell'AAD impedisce trapianto/swap dei ciphertext (doc 16 §5).
//! Il manifest è l'inventario firmato Ed25519 con anti-rollback (doc 16 §6).

pub mod item;
pub mod manifest;
