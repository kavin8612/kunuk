//! Client HTTP del backend Kunuk (doc 12). Sincrono (ureq): i comandi Tauri non
//! marcati `async` girano già su un thread del pool dedicato, niente bisogno di runtime
//! asincrono qui (a differenza della UI React, che resta reattiva).
//!
//! Tratta i corpi come opachi: invia/riceve JSON, non interpreta la crittografia (che vive
//! nel crypto-core, SR-1). Stessa struttura di `apps/cli/src/api.rs` (duplicazione accettata,
//! doc 19 §3: due occorrenze, niente astrazione prematura).

use ureq::tls::{Certificate, PemItem, RootCerts, TlsConfig};
use ureq::Agent;

pub struct Resp {
    pub status: u16,
    pub body: String,
}

impl Resp {
    pub fn json(&self) -> Result<serde_json::Value, String> {
        serde_json::from_str(&self.body)
            .map_err(|e| format!("risposta non-JSON: {e} — {}", self.body))
    }
}

/// Client verso una base URL (es. `https://localhost`, via Caddy in dev).
pub struct Client {
    agent: Agent,
    base: String,
}

impl Client {
    /// `ca_pem`, se presente, aggiunge una CA radice di fiducia (la CA interna di Caddy in
    /// dev): la verifica TLS resta attiva. Senza, usa i root di sistema (produzione).
    pub fn new(base_url: &str, ca_pem: Option<&[u8]>) -> Result<Client, String> {
        let mut builder = Agent::config_builder().http_status_as_error(false);
        if let Some(pem) = ca_pem {
            let certs: Vec<Certificate<'static>> = ureq::tls::parse_pem(pem)
                .filter_map(|item| match item {
                    Ok(PemItem::Certificate(c)) => Some(c),
                    _ => None,
                })
                .collect();
            if certs.is_empty() {
                return Err("nessun certificato nel PEM della CA".into());
            }
            let tls = TlsConfig::builder()
                .root_certs(RootCerts::new_with_certs(&certs))
                .build();
            builder = builder.tls_config(tls);
        }
        let agent: Agent = builder.build().into();
        Ok(Client {
            agent,
            base: base_url.trim_end_matches('/').to_string(),
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    pub fn post_json(
        &self,
        path: &str,
        bearer: Option<&str>,
        body: &serde_json::Value,
    ) -> Result<Resp, String> {
        let mut req = self.agent.post(self.url(path));
        if let Some(token) = bearer {
            req = req.header("Authorization", &format!("Bearer {token}"));
        }
        let mut resp = req
            .send_json(body)
            .map_err(|e| format!("POST {path}: {e}"))?;
        Self::collect(&mut resp)
    }

    pub fn get(&self, path: &str, bearer: Option<&str>) -> Result<Resp, String> {
        let mut req = self.agent.get(self.url(path));
        if let Some(token) = bearer {
            req = req.header("Authorization", &format!("Bearer {token}"));
        }
        let mut resp = req.call().map_err(|e| format!("GET {path}: {e}"))?;
        Self::collect(&mut resp)
    }

    pub fn put_json(
        &self,
        path: &str,
        bearer: Option<&str>,
        body: &serde_json::Value,
    ) -> Result<Resp, String> {
        let mut req = self.agent.put(self.url(path));
        if let Some(token) = bearer {
            req = req.header("Authorization", &format!("Bearer {token}"));
        }
        let mut resp = req
            .send_json(body)
            .map_err(|e| format!("PUT {path}: {e}"))?;
        Self::collect(&mut resp)
    }

    pub fn delete(&self, path: &str, bearer: Option<&str>) -> Result<Resp, String> {
        let mut req = self.agent.delete(self.url(path));
        if let Some(token) = bearer {
            req = req.header("Authorization", &format!("Bearer {token}"));
        }
        let mut resp = req.call().map_err(|e| format!("DELETE {path}: {e}"))?;
        Self::collect(&mut resp)
    }

    fn collect(resp: &mut ureq::http::Response<ureq::Body>) -> Result<Resp, String> {
        let status = resp.status().as_u16();
        let body = resp
            .body_mut()
            .read_to_string()
            .map_err(|e| format!("lettura corpo: {e}"))?;
        Ok(Resp { status, body })
    }
}
