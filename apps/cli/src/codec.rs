//! Codifiche di trasporto: base64url senza padding (campi binari, doc 16 §1, doc 21) e
//! testo UUID canonico per gli identificatori a 16 byte (item_id sul filo API). Funzioni
//! pure, coperte da unit test: nessuna crittografia qui (vive nel crypto-core, SR-1).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

/// Codifica byte in base64url senza padding (formato dei campi binari dell'API, doc 21).
pub fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodifica una stringa base64url senza padding. Input malformato → errore.
pub fn unb64(s: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| format!("base64url non valido: {e}"))
}

/// Formatta 16 byte come UUID canonico minuscolo (8-4-4-4-12). È la forma che il backend
/// (PostgreSQL) accetta e restituisce per l'id dell'item, che il client lega nell'AAD
/// (doc 16 §5).
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

/// Converte un UUID testuale (con o senza trattini) nei suoi 16 byte. Lunghezza o cifre
/// esadecimali non valide → errore.
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
