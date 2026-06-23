//! Helper condivisi tra i moduli di comandi (`commands.rs`, `items.rs`, `vault_sync.rs`):
//! codifiche di trasporto e client HTTP. Nessuna crittografia qui (SR-1): solo opachi
//! byte/stringhe verso il backend.

use crate::api::{Client, Resp};
use crate::config::AppConfig;

pub fn ce(e: kunuk_crypto_core::CoreError) -> String {
    format!("crypto-core: {e}")
}

/// 16 byte casuali dal CSPRNG del core (account_id/item_id).
pub fn rand_id() -> Result<[u8; 16], String> {
    let mut id = [0u8; 16];
    kunuk_crypto_core::crypto::rng::fill(&mut id).map_err(ce)?;
    Ok(id)
}

pub fn b64(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn unb64(s: &str) -> Result<Vec<u8>, String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| format!("base64url non valido: {e}"))
}

pub fn uuid_to_string(b: &[u8; 16]) -> String {
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

pub fn uuid_from_string(s: &str) -> Result<[u8; 16], String> {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return Err(format!("uuid di lunghezza errata: {s}"));
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| format!("uuid con cifre non esadecimali: {s}"))?;
    }
    Ok(out)
}

pub fn field_str<'a>(v: &'a serde_json::Value, key: &str) -> Result<&'a str, String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("campo '{key}' mancante o non stringa nella risposta"))
}

pub fn expect_status(r: &Resp, want: u16, step: &str) -> Result<(), String> {
    if r.status != want {
        // Log ricco lato Rust (stesso principio del backend Go: dettaglio interno nei log,
        // messaggio generico verso il chiamante, doc 18 §5).
        eprintln!(
            "kunuk-desktop: {step}: atteso HTTP {want}, ricevuto {}",
            r.status
        );
        return Err(format!("{step}: richiesta al server fallita"));
    }
    Ok(())
}

pub fn client(cfg: &AppConfig) -> Result<Client, String> {
    Client::new(&cfg.base_url, cfg.ca_pem.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_round_trip_e_forma_canonica() {
        let b: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba,
            0xdc, 0xfe,
        ];
        let s = uuid_to_string(&b);
        assert_eq!(s, "01234567-89ab-cdef-1032-547698badcfe");
        assert_eq!(uuid_from_string(&s).unwrap(), b);
    }

    #[test]
    fn uuid_from_string_rifiuta_input_errato() {
        assert!(uuid_from_string("troppo-corto").is_err());
        assert!(uuid_from_string(&"z".repeat(32)).is_err());
    }

    #[test]
    fn b64_round_trip_senza_padding() {
        let raw = [0x00u8, 0x11, 0xAB, 0xFF, 0x10];
        let enc = b64(&raw);
        assert!(!enc.contains('='), "niente padding (doc 21)");
        assert!(
            !enc.contains('+') && !enc.contains('/'),
            "alfabeto url-safe"
        );
        assert_eq!(unb64(&enc).unwrap(), raw);
    }

    #[test]
    fn unb64_rifiuta_input_malformato() {
        assert!(unb64("non base64url valido !!!").is_err());
    }
}
