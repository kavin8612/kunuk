//! Harness dei test vettoriali (doc 16 §8).
//!
//! Carica le fixture JSON sotto `tests/vectors/<categoria>/` ed esegue le primitive,
//! confrontando l'output byte-per-byte con l'atteso. I positivi devono combaciare; i
//! negativi devono fallire con l'errore atteso (un negativo che "passa" è un bug di
//! sicurezza, non un test rotto). La categoria `recovery-auth` si popola al task 0.7.

use std::path::{Path, PathBuf};

use kunuk_crypto_core::crypto::params::Argon2Params;
use kunuk_crypto_core::crypto::signature::keypair_from_seed;
use kunuk_crypto_core::crypto::{argon2id, kdf};
use kunuk_crypto_core::envelope::{self, EnvelopeType};
use kunuk_crypto_core::vault::item;
use kunuk_crypto_core::vault::manifest::{self, ItemRef, ManifestContent};
use kunuk_crypto_core::CoreError;
use minicbor::bytes::ByteArray;
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

/// Verifica che l'errore ottenuto corrisponda al nome atteso nel vettore.
fn errore_atteso(atteso: &str, err: &CoreError) -> bool {
    matches!(
        (atteso, err),
        ("DecryptFailed", CoreError::DecryptFailed)
            | ("InvalidInput", CoreError::InvalidInput)
            | ("UnsupportedVersion", CoreError::UnsupportedVersion)
            | ("AuthFailed", CoreError::AuthFailed)
    )
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
struct ItemVector {
    vk_hex: String,
    vault_id_hex: String,
    item_id_hex: String,
    content_cbor_hex: String,
    cek_hex: String,
    cek_nonce_hex: String,
    item_nonce_hex: String,
    ciphertext_hex: String,
    wrapped_cek_hex: String,
}

#[derive(Deserialize)]
struct ItemRefVector {
    item_id_hex: String,
    item_version: u64,
}

#[derive(Deserialize)]
struct ManifestVector {
    seed_hex: String,
    vault_id_hex: String,
    version: u64,
    crdt_clock_hex: String,
    items: Vec<ItemRefVector>,
    signed_manifest_hex: String,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum NegativeVector {
    Envelope {
        wrapping_key_hex: String,
        envelope_hex: String,
        account_id_hex: String,
        expected_type: String,
        kdf_params_cbor_hex: String,
        expect_error: String,
    },
    Item {
        vk_hex: String,
        vault_id_hex: String,
        item_id_hex: String,
        ciphertext_hex: String,
        wrapped_cek_hex: String,
        expect_error: String,
    },
    Manifest {
        seed_hex: String,
        signed_manifest_hex: String,
        expected_vault_id_hex: String,
        min_version: u64,
        expect_error: String,
    },
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
fn vettori_item_combaciano() {
    let vettori = load_vectors::<ItemVector>(&vectors_root().join("item"));
    assert!(!vettori.is_empty(), "nessun vettore item");
    for (path, v) in vettori {
        let vk: [u8; 32] = to_array(&v.vk_hex);
        let vault: [u8; 16] = to_array(&v.vault_id_hex);
        let id: [u8; 16] = to_array(&v.item_id_hex);
        let cek: [u8; 32] = to_array(&v.cek_hex);
        let cek_nonce: [u8; 24] = to_array(&v.cek_nonce_hex);
        let item_nonce: [u8; 24] = to_array(&v.item_nonce_hex);
        let content = hex::decode(&v.content_cbor_hex).expect("content_cbor_hex valido");

        let (ct, wcek) =
            item::encrypt_item_with(&vk, &vault, &id, &content, &cek, &cek_nonce, &item_nonce)
                .expect("encrypt_item");
        assert_eq!(
            hex::encode(&ct),
            v.ciphertext_hex,
            "ciphertext {}",
            path.display()
        );
        assert_eq!(
            hex::encode(&wcek),
            v.wrapped_cek_hex,
            "wrapped_cek {}",
            path.display()
        );

        let got = item::decrypt_item(&vk, &vault, &id, &ct, &wcek).expect("decrypt_item");
        assert_eq!(&*got, &content, "round-trip item {}", path.display());
    }
}

#[test]
fn vettori_manifest_combaciano() {
    let vettori = load_vectors::<ManifestVector>(&vectors_root().join("manifest"));
    assert!(!vettori.is_empty(), "nessun vettore manifest");
    for (path, v) in vettori {
        let seed: [u8; 32] = to_array(&v.seed_hex);
        let (sk, vk) = keypair_from_seed(&seed);
        let content = ManifestContent {
            vault_id: ByteArray::from(to_array::<16>(&v.vault_id_hex)),
            version: v.version,
            items: v
                .items
                .iter()
                .map(|i| ItemRef {
                    item_id: ByteArray::from(to_array::<16>(&i.item_id_hex)),
                    item_version: i.item_version,
                })
                .collect(),
            crdt_clock: hex::decode(&v.crdt_clock_hex).expect("crdt_clock_hex valido"),
        };
        let signed = manifest::sign_manifest(&sk, &content).expect("sign_manifest");
        assert_eq!(
            hex::encode(&signed),
            v.signed_manifest_hex,
            "manifest {}",
            path.display()
        );
        let view =
            manifest::verify_manifest(&vk, &signed, &to_array::<16>(&v.vault_id_hex), v.version)
                .expect("verify_manifest");
        assert_eq!(
            view.version,
            v.version,
            "manifest version {}",
            path.display()
        );
    }
}

#[test]
fn vettori_negative_falliscono_come_atteso() {
    let vettori = load_vectors::<NegativeVector>(&vectors_root().join("negative"));
    assert!(!vettori.is_empty(), "nessun vettore negativo");
    for (path, v) in vettori {
        let (err, atteso) = match v {
            NegativeVector::Envelope {
                wrapping_key_hex,
                envelope_hex,
                account_id_hex,
                expected_type,
                kdf_params_cbor_hex,
                expect_error,
            } => {
                let wk: [u8; 32] = to_array(&wrapping_key_hex);
                let account: [u8; 16] = to_array(&account_id_hex);
                let env = hex::decode(&envelope_hex).expect("envelope_hex valido");
                let params = hex::decode(&kdf_params_cbor_hex).expect("params valido");
                let et = parse_type(&expected_type);
                let e =
                    envelope::unwrap(&wk, &env, &account, et, &params).expect_err("deve fallire");
                (e, expect_error)
            }
            NegativeVector::Item {
                vk_hex,
                vault_id_hex,
                item_id_hex,
                ciphertext_hex,
                wrapped_cek_hex,
                expect_error,
            } => {
                let vk: [u8; 32] = to_array(&vk_hex);
                let vault: [u8; 16] = to_array(&vault_id_hex);
                let id: [u8; 16] = to_array(&item_id_hex);
                let ct = hex::decode(&ciphertext_hex).expect("ciphertext valido");
                let wcek = hex::decode(&wrapped_cek_hex).expect("wrapped_cek valido");
                let e = item::decrypt_item(&vk, &vault, &id, &ct, &wcek).expect_err("deve fallire");
                (e, expect_error)
            }
            NegativeVector::Manifest {
                seed_hex,
                signed_manifest_hex,
                expected_vault_id_hex,
                min_version,
                expect_error,
            } => {
                let seed: [u8; 32] = to_array(&seed_hex);
                let (_, vk) = keypair_from_seed(&seed);
                let signed = hex::decode(&signed_manifest_hex).expect("signed valido");
                let exp_vault: [u8; 16] = to_array(&expected_vault_id_hex);
                let e = manifest::verify_manifest(&vk, &signed, &exp_vault, min_version)
                    .expect_err("deve fallire");
                (e, expect_error)
            }
        };
        assert!(
            errore_atteso(&atteso, &err),
            "vettore negativo {}: atteso {}, ottenuto {:?}",
            path.display(),
            atteso,
            err
        );
    }
}
