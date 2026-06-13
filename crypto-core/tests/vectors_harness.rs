//! Harness dei test vettoriali (doc 16 §8).
//!
//! Carica le fixture JSON sotto `tests/vectors/<categoria>/` ed esegue le primitive
//! corrispondenti, confrontando l'output byte-per-byte con l'atteso. Le categorie
//! ancora vuote (envelope/item/manifest/recovery-auth/negative) si popolano ai task
//! 0.5–0.7. Un vettore atteso che non combacia è un bug, non un test rotto.

use std::path::{Path, PathBuf};

use kunuk_crypto_core::crypto::params::Argon2Params;
use kunuk_crypto_core::crypto::{argon2id, kdf};
use serde::Deserialize;

/// Categorie di vettori previste dal doc 16 §8.
const CATEGORIES: &[&str] = &[
    "kdf",
    "hkdf",
    "envelope",
    "item",
    "manifest",
    "recovery-auth",
    "negative",
];

fn vectors_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

/// Carica e deserializza tutte le fixture `*.json` di una categoria.
fn load_vectors<T: serde::de::DeserializeOwned>(dir: &Path) -> Vec<(PathBuf, T)> {
    let mut vettori = Vec::new();
    for entry in std::fs::read_dir(dir)
        .expect("categoria leggibile")
        .flatten()
    {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let data = std::fs::read_to_string(&path).expect("fixture leggibile");
        let vettore = serde_json::from_str(&data)
            .unwrap_or_else(|e| panic!("fixture {} non valida: {e}", path.display()));
        vettori.push((path, vettore));
    }
    vettori
}

#[derive(Deserialize)]
struct KdfVector {
    password_hex: String,
    salt_hex: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    output_hex: String,
}

#[derive(Deserialize)]
struct HkdfVector {
    ikm_hex: String,
    info: String,
    okm_hex: String,
}

#[test]
fn ogni_categoria_di_vettori_e_presente() {
    let root = vectors_root();
    for categoria in CATEGORIES {
        let dir = root.join(categoria);
        assert!(
            dir.is_dir(),
            "manca la categoria di vettori: {}",
            dir.display()
        );
    }
}

#[test]
fn vettori_kdf_combaciano() {
    let vettori = load_vectors::<KdfVector>(&vectors_root().join("kdf"));
    assert!(!vettori.is_empty(), "nessun vettore kdf");
    for (path, v) in vettori {
        let password = hex::decode(&v.password_hex).expect("password_hex valido");
        let salt = hex::decode(&v.salt_hex).expect("salt_hex valido");
        let params = Argon2Params {
            memory_kib: v.memory_kib,
            iterations: v.iterations,
            parallelism: v.parallelism,
        };
        let out = argon2id::derive(&password, &salt, &params).expect("derivazione kdf");
        assert_eq!(
            hex::encode(out.as_slice()),
            v.output_hex,
            "vettore kdf {}",
            path.display()
        );
    }
}

#[test]
fn vettori_hkdf_combaciano() {
    let vettori = load_vectors::<HkdfVector>(&vectors_root().join("hkdf"));
    assert!(!vettori.is_empty(), "nessun vettore hkdf");
    for (path, v) in vettori {
        let ikm = hex::decode(&v.ikm_hex).expect("ikm_hex valido");
        let okm = kdf::hkdf_sha256(&ikm, v.info.as_bytes()).expect("derivazione hkdf");
        assert_eq!(
            hex::encode(okm.as_slice()),
            v.okm_hex,
            "vettore hkdf {}",
            path.display()
        );
    }
}
