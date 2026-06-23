//! Configurazione di processo (doc 19 §1: niente segreti hardcoded). In dev punta allo
//! stack Compose locale via Caddy HTTPS (come la CLI, task 0.10); in produzione (Fase 4)
//! `KUNUK_CA_CERT` non serve più (root di sistema, certificato pubblico).

/// `KUNUK_API_URL`/`KUNUK_CA_CERT`: stesse variabili lette dalla CLI (`apps/cli/src/main.rs`).
pub struct AppConfig {
    pub base_url: String,
    pub ca_pem: Option<Vec<u8>>,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, String> {
        let base_url =
            std::env::var("KUNUK_API_URL").unwrap_or_else(|_| "https://localhost".into());
        let ca_pem = match std::env::var("KUNUK_CA_CERT") {
            Ok(path) => {
                Some(std::fs::read(&path).map_err(|e| format!("lettura CA '{path}': {e}"))?)
            }
            Err(_) => None,
        };
        Ok(Self { base_url, ca_pem })
    }
}
