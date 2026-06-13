//! Harness dei test vettoriali (doc 16 §8).
//!
//! Carica le fixture JSON sotto `tests/vectors/<categoria>/` ed esegue le primitive
//! corrispondenti, confrontando l'output byte-per-byte con l'atteso. I positivi
//! devono combaciare; i negativi devono fallire con l'errore atteso (un negativo che
//! "passa" è un bug di sicurezza, non un test rotto). Le categorie ancora vuote
//! (`item`, `manifest`, `recovery-auth`) si popolano ai task 0.6–0.7.

use std::path::{Path, PathBuf};

use kunuk_crypto_core::crypto::params::Argon2Params;
use kunuk_crypto_core::crypto::{argon2id, kdf};
use kunuk_crypto_core::envelope::{self, EnvelopeType};
use kunuk_crypto_core::CoreError;
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

/// Decodifica una stringa hex in un array di lunghezza fissa.
fn to_array<const N: usize>(hexstr: &str) -> [u8; N] {
    let bytes = hex::decode(hexstr).expect("hex valido");
    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("attesi {N} byte"))
}

fn parse_type(s: &str) -> EnvelopeType {
    match s {
        "password" => EnvelopeType::Password,
        "recovery" => EnvelopeType::Recovery,
        "biometric" => EnvelopeType::Biometric,
        other => panic!("tipo busta sconosciuto: {other}"),
    }
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

#[derive(Deserialize)]
struct EnvelopeVector {
    wrapping_key_hex: String,
    vk_hex: String,
    account_id_hex: String,
    envelope_type: String,
    kdf_params_cbor_hex: String,
    nonce_hex: String,
    envelope_hex: String,
}

#[derive(Deserialize)]
struct NegativeVector {
    wrapping_key_hex: String,
    envelope_hex: String,
    account_id_hex: String,
    expected_type: String,
    kdf_params_cbor_hex: String,
    expect_error: String,
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

#[test]
fn vettori_envelope_combaciano() {
    let vettori = load_vectors::<EnvelopeVector>(&vectors_root().join("envelope"));
    assert!(!vettori.is_empty(), "nessun vettore envelope");
    for (path, v) in vettori {
        let wrapping_key: [u8; 32] = to_array(&v.wrapping_key_hex);
        let vk: [u8; 32] = to_array(&v.vk_hex);
        let account: [u8; 16] = to_array(&v.account_id_hex);
        let nonce: [u8; 24] = to_array(&v.nonce_hex);
        let params = hex::decode(&v.kdf_params_cbor_hex).expect("kdf_params_cbor_hex valido");
        let et = parse_type(&v.envelope_type);

        let env = envelope::wrap_with_nonce(&wrapping_key, &vk, &account, et, &params, &nonce)
            .expect("wrap");
        assert_eq!(
            hex::encode(&env),
            v.envelope_hex,
            "vettore envelope {}",
            path.display()
        );

        let aperta = envelope::unwrap(&wrapping_key, &env, &account, et, &params).expect("unwrap");
        assert_eq!(*aperta, vk, "round-trip envelope {}", path.display());
    }
}

#[test]
fn vettori_negative_falliscono_come_atteso() {
    let vettori = load_vectors::<NegativeVector>(&vectors_root().join("negative"));
    assert!(!vettori.is_empty(), "nessun vettore negativo");
    for (path, v) in vettori {
        let wrapping_key: [u8; 32] = to_array(&v.wrapping_key_hex);
        let account: [u8; 16] = to_array(&v.account_id_hex);
        let env = hex::decode(&v.envelope_hex).expect("envelope_hex valido");
        let params = hex::decode(&v.kdf_params_cbor_hex).expect("kdf_params_cbor_hex valido");
        let et = parse_type(&v.expected_type);

        let err = envelope::unwrap(&wrapping_key, &env, &account, et, &params)
            .expect_err("il vettore negativo deve fallire");
        let combacia = matches!(
            (v.expect_error.as_str(), &err),
            ("DecryptFailed", CoreError::DecryptFailed)
                | ("InvalidInput", CoreError::InvalidInput)
                | ("UnsupportedVersion", CoreError::UnsupportedVersion)
        );
        assert!(
            combacia,
            "vettore negativo {}: atteso {}, ottenuto {:?}",
            path.display(),
            v.expect_error,
            err
        );
    }
}
