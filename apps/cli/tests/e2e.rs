//! Test E2E del gate 0.10 contro un backend **vivo**.
//!
//! Gated: gira solo se `KUNUK_API_URL` è impostata (serve lo stack up — vedi
//! `scripts/dev/gate-0.10.sh`). Senza, viene saltato in modo pulito (niente flakiness,
//! niente dipendenza da Docker nella CI unitaria, doc 19 §6). Variabili opzionali:
//! `KUNUK_CA_CERT` (PEM della CA dev di Caddy), `KUNUK_PASSWORD`.

use std::time::{SystemTime, UNIX_EPOCH};

use kunuk_cli::{run_gate, GateConfig};

#[test]
fn gate_e2e_contro_backend_vivo() {
    let Ok(base_url) = std::env::var("KUNUK_API_URL") else {
        eprintln!("KUNUK_API_URL non impostata → test E2E saltato (richiede un backend vivo).");
        return;
    };
    let ca_pem = std::env::var("KUNUK_CA_CERT")
        .ok()
        .map(|p| std::fs::read(&p).unwrap_or_else(|e| panic!("CA '{p}' non leggibile: {e}")));
    let password =
        std::env::var("KUNUK_PASSWORD").unwrap_or_else(|_| "tromba-cavallo-graffetta-7".into());

    // Email unica per run (un'email già registrata romperebbe la coerenza del verificatore).
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let email = format!("gate-it-{nanos:x}@example.com");

    let cfg = GateConfig {
        base_url,
        ca_pem,
        email,
        password,
    };
    let mut steps = Vec::new();
    run_gate(&cfg, &mut |s| steps.push(s.to_string()))
        .unwrap_or_else(|e| panic!("cerimonia gate fallita: {e}\npassi: {steps:#?}"));
    assert_eq!(steps.len(), 6, "attesi 6 passi loggati: {steps:#?}");
}
