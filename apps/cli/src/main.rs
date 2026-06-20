//! Binario `kunuk` (gate 0.10): esegue la cerimonia end-to-end contro un backend Kunuk vivo.
//!
//! Configurazione via ambiente (niente segreti hardcoded, doc 19 §1):
//!   - `KUNUK_API_URL`   base URL del backend (default `https://localhost`, via Caddy in dev)
//!   - `KUNUK_CA_CERT`   percorso del PEM della CA radice da fidare (CA interna di Caddy in dev)
//!   - `KUNUK_EMAIL`     email da registrare (default: una unica per esecuzione)
//!   - `KUNUK_PASSWORD`  master password (default di sviluppo)
//!
//! Uscita 0 se la cerimonia passa (= gate verde), 1 altrimenti.

use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use kunuk_cli::{run_gate, GateConfig};

fn main() -> ExitCode {
    match real_main() {
        Ok(()) => {
            println!("\n✓ GATE 0.10 OK — fondamenta end-to-end verificata (zero-knowledge).");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("\n✗ GATE 0.10 FALLITO: {e}");
            ExitCode::FAILURE
        }
    }
}

fn real_main() -> Result<(), String> {
    let base_url = std::env::var("KUNUK_API_URL").unwrap_or_else(|_| "https://localhost".into());
    let email = std::env::var("KUNUK_EMAIL").unwrap_or_else(|_| default_email());
    let password =
        std::env::var("KUNUK_PASSWORD").unwrap_or_else(|_| "tromba-cavallo-graffetta-7".into());
    let ca_pem = match std::env::var("KUNUK_CA_CERT") {
        Ok(path) => Some(std::fs::read(&path).map_err(|e| format!("lettura CA '{path}': {e}"))?),
        Err(_) => None,
    };

    println!("Kunuk — gate 0.10 verso {base_url} (email {email})");
    let cfg = GateConfig {
        base_url,
        ca_pem,
        email,
        password,
    };
    run_gate(&cfg, &mut |step| println!("  {step}"))
}

/// Email unica per esecuzione, così il gate è ripetibile (un'email già registrata
/// risponderebbe 201 ma con il verificatore della prima registrazione → login incoerente).
fn default_email() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("gate-0.10-{nanos:x}@example.com")
}
