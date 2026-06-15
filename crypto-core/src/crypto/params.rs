//! Costanti della suite crittografica 0x01 (doc 16 §1, §3).
//!
//! Unica fonte dei parametri crittografici: nessun valore è inventato altrove
//! (doc 19 §3). I valori sono rivedibili **solo al rialzo** (mai al ribasso, doc 16 §3).

/// Lunghezza in byte delle chiavi simmetriche e delle derivazioni (256 bit).
pub const KEY_LEN: usize = 32;

/// Lunghezza del salt Argon2id in byte (doc 16 §3).
pub const ARGON2_SALT_LEN: usize = 16;

/// Lunghezza della Secret Key in byte (128 bit, ADR-0006). È fissa: la concatenazione
/// `password ‖ Secret Key` (2SKD) è non ambigua solo perché la Secret Key ha lunghezza
/// nota.
pub const SECRET_KEY_LEN: usize = 16;

/// Lunghezza attesa dell'output dell'estensione WebAuthn PRF in byte (32 byte).
pub const PRF_OUTPUT_LEN: usize = 32;

/// Parametri Argon2id (doc 16 §3). La memoria è in KiB, come richiesto dal crate
/// `argon2`. Unica dichiarazione dei campi di costo: `KdfParams` lo incorpora.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argon2Params {
    /// Memoria in KiB.
    pub memory_kib: u32,
    /// Iterazioni (time cost).
    pub iterations: u32,
    /// Grado di parallelismo (lanes).
    pub parallelism: u32,
}

/// Parametri Argon2id di riferimento v1: 64 MiB, 3 iterazioni, parallelismo 4
/// (doc 16 §3).
pub const ARGON2_V1: Argon2Params = Argon2Params {
    memory_kib: 64 * 1024,
    iterations: 3,
    parallelism: 4,
};

/// Etichetta HKDF della chiave-password PK (doc 16 §3).
pub const LABEL_PK_WRAP: &[u8] = b"kunuk/v1/pk/wrap";

/// Etichetta HKDF del verificatore di autenticazione AV della via password (doc 16 §3).
/// Nell'`info` HKDF è seguita dall'`account_id` (binding all'account).
pub const LABEL_AUTH_VERIFIER: &[u8] = b"kunuk/v1/auth/verifier";

/// Etichetta HKDF della chiave di wrapping della busta passkey PRFw, dall'output
/// dell'estensione WebAuthn PRF (doc 16 §3).
pub const LABEL_PRF_WRAP: &[u8] = b"kunuk/v1/prf/wrap";

/// Etichetta HKDF della chiave di wrapping del recupero RKw (doc 16 §3).
pub const LABEL_RK_WRAP: &[u8] = b"kunuk/v1/rk/wrap";

/// Etichetta HKDF del seme della coppia Ed25519 di prova-di-possesso RKa (doc 16 §3).
pub const LABEL_RK_AUTH: &[u8] = b"kunuk/v1/rk/auth";

/// Etichetta HKDF della chiave di wrapping della device key DKw (doc 16 §3).
pub const LABEL_DK_WRAP: &[u8] = b"kunuk/v1/dk/wrap";
