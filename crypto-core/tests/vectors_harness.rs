//! Harness dei test vettoriali (doc 16 §8).
//!
//! Scopre le categorie sotto `tests/vectors/`. Quando le primitive esisteranno
//! (task 0.4+) eseguirà ogni vettore: i positivi devono combaciare byte-per-byte, i
//! negativi DEVONO fallire (un negativo che "passa" è un bug di sicurezza — doc 16 §8).
//!
//! Stato: scheletro (task 0.3). Le categorie sono vuote: l'harness verifica solo che
//! la struttura sia presente; deserializzazione JSON e asserzioni arrivano al 0.4
//! (allora si aggiungono serde/serde_json come dev-dependency, registrate nel registro).

use std::path::PathBuf;

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
fn le_fixture_si_possono_enumerare() {
    // TODO(task-0.4): caricare le fixture JSON (serde), eseguire le primitive e
    // confrontare l'atteso; i negativi devono fallire. Ora solo enumerazione — placeholder (task 0.3).
    let root = vectors_root();
    for categoria in CATEGORIES {
        let dir = root.join(categoria);
        if let Ok(entries) = std::fs::read_dir(&dir) {
            // Enumerazione non distruttiva: nessuna fixture reale è ancora attesa.
            for entry in entries.flatten() {
                let _ = entry.path();
            }
        }
    }
}
