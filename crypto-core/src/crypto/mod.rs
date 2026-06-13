//! Primitive crittografiche (suite 0x01, doc 16 §1): Argon2id, HKDF-SHA-256,
//! XChaCha20-Poly1305, Ed25519.
//!
//! Funzioni pure e deterministiche: input espliciti, nessuna generazione di
//! chiavi/nonce qui (il CSPRNG entra al task 0.5, doc 20 §1). Tutto ciò che è
//! deterministico è coperto dai test vettoriali (doc 16 §8). I parametri vengono
//! solo dal modulo `params` (doc 16), mai inventati inline (doc 19 §3).

pub mod aead;
pub mod argon2id;
pub mod kdf;
pub mod params;
pub mod signature;
