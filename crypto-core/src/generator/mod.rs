//! Generatore di password e passphrase (doc 17 §3, doc 20 §9).
//!
//! Pura selezione uniforme dal CSPRNG del core (doc 16 §7): nessuna chiave né segreto
//! del vault coinvolto, è lecito generare anche a vault bloccato. Il risultato è una
//! `String` in chiaro: il chiamante (UI) decide se e quanto a lungo mostrarla, non è
//! materiale che il core debba azzerare (a differenza di VK/CEK, SR-5).

use crate::crypto::rng;
use crate::error::{CoreError, CoreResult};

const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{}|;:,.<>/?";
/// Caratteri facilmente confondibili a video (doc 17 §3 "esclusione caratteri ambigui
/// opzionale"): zero/O, uno/elle/I.
const AMBIGUOUS: &str = "0O1lI";

/// Wordlist diceware inglese (EFF Large Wordlist, 7776 voci, CC-BY 3.0 — fonte e
/// licenza in `docs/contributing/registro-licenze-dipendenze.md`).
const WORDLIST_EN: &str = include_str!("wordlist_en.txt");
/// Wordlist diceware italiana (progetto `ulif/diceware`, 8192 voci, CC-BY 4.0 — fonte e
/// licenza in `docs/contributing/registro-licenze-dipendenze.md`).
const WORDLIST_IT: &str = include_str!("wordlist_it.txt");

/// Politica del generatore di password (doc 17 §3): default 20 caratteri, tutte le
/// classi attive, niente esclusione di ambigui.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswordPolicy {
    pub length: usize,
    pub uppercase: bool,
    pub lowercase: bool,
    pub numbers: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            length: 20,
            uppercase: true,
            lowercase: true,
            numbers: true,
            symbols: true,
            exclude_ambiguous: false,
        }
    }
}

/// Lingua della wordlist diceware (doc 20 §9: `lang: It|En`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PassphraseLang {
    It,
    En,
}

/// Genera una password dal CSPRNG del core secondo `policy`. Nessuna classe abilitata
/// o `length` zero → `InvalidInput`: una politica priva di senso non produce in
/// silenzio una stringa vuota o debole.
pub fn generate_password(policy: &PasswordPolicy) -> CoreResult<String> {
    if policy.length == 0 {
        return Err(CoreError::InvalidInput);
    }
    let mut charset = String::new();
    if policy.lowercase {
        charset.push_str(LOWERCASE);
    }
    if policy.uppercase {
        charset.push_str(UPPERCASE);
    }
    if policy.numbers {
        charset.push_str(DIGITS);
    }
    if policy.symbols {
        charset.push_str(SYMBOLS);
    }
    if policy.exclude_ambiguous {
        charset.retain(|c| !AMBIGUOUS.contains(c));
    }
    let chars: Vec<char> = charset.chars().collect();
    if chars.is_empty() {
        return Err(CoreError::InvalidInput);
    }
    let mut out = String::with_capacity(policy.length);
    for _ in 0..policy.length {
        out.push(chars[random_index(chars.len())?]);
    }
    Ok(out)
}

/// Genera una passphrase diceware: `words` parole della wordlist `lang`, unite da
/// `separator`. `words` zero → `InvalidInput`.
pub fn generate_passphrase(
    lang: PassphraseLang,
    words: usize,
    separator: &str,
) -> CoreResult<String> {
    if words == 0 {
        return Err(CoreError::InvalidInput);
    }
    let list = match lang {
        PassphraseLang::En => WORDLIST_EN,
        PassphraseLang::It => WORDLIST_IT,
    };
    let entries: Vec<&str> = list.lines().collect();
    let mut chosen = Vec::with_capacity(words);
    for _ in 0..words {
        chosen.push(entries[random_index(entries.len())?]);
    }
    Ok(chosen.join(separator))
}

/// Indice uniforme in `[0, bound)` dal CSPRNG, senza bias da modulo: rifiuta gli
/// estremi superiori dello spazio di `u32` che non dividono `bound` esattamente e
/// ritenta, invece di accettare la distribuzione leggermente sbilanciata di un
/// `% bound` diretto.
fn random_index(bound: usize) -> CoreResult<usize> {
    let bound = bound as u32;
    let limit = u32::MAX - (u32::MAX % bound);
    loop {
        let mut buf = [0u8; 4];
        rng::fill(&mut buf)?;
        let val = u32::from_le_bytes(buf);
        if val < limit {
            return Ok((val % bound) as usize);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_lunghezza_e_charset_rispettati() {
        let policy = PasswordPolicy {
            length: 32,
            uppercase: true,
            lowercase: true,
            numbers: true,
            symbols: true,
            exclude_ambiguous: false,
        };
        let pw = generate_password(&policy).unwrap();
        assert_eq!(pw.chars().count(), 32);
        let allowed: Vec<char> = format!("{LOWERCASE}{UPPERCASE}{DIGITS}{SYMBOLS}")
            .chars()
            .collect();
        assert!(pw.chars().all(|c| allowed.contains(&c)));
    }

    #[test]
    fn password_esclude_ambigui_quando_richiesto() {
        let policy = PasswordPolicy {
            length: 500,
            uppercase: true,
            lowercase: true,
            numbers: true,
            symbols: false,
            exclude_ambiguous: true,
        };
        let pw = generate_password(&policy).unwrap();
        assert!(pw.chars().all(|c| !AMBIGUOUS.contains(c)));
    }

    #[test]
    fn password_rispetta_solo_le_classi_abilitate() {
        let policy = PasswordPolicy {
            length: 200,
            uppercase: false,
            lowercase: false,
            numbers: true,
            symbols: false,
            exclude_ambiguous: false,
        };
        let pw = generate_password(&policy).unwrap();
        assert!(pw.chars().all(|c| DIGITS.contains(c)));
    }

    #[test]
    fn password_politica_priva_di_classi_e_rifiutata() {
        let policy = PasswordPolicy {
            length: 10,
            uppercase: false,
            lowercase: false,
            numbers: false,
            symbols: false,
            exclude_ambiguous: false,
        };
        assert!(matches!(
            generate_password(&policy),
            Err(CoreError::InvalidInput)
        ));
    }

    #[test]
    fn password_lunghezza_zero_e_rifiutata() {
        let policy = PasswordPolicy {
            length: 0,
            ..PasswordPolicy::default()
        };
        assert!(matches!(
            generate_password(&policy),
            Err(CoreError::InvalidInput)
        ));
    }

    #[test]
    fn passphrase_conta_le_parole_e_usa_il_separatore() {
        let pp = generate_passphrase(PassphraseLang::En, 5, "-").unwrap();
        let parts: Vec<&str> = pp.split('-').collect();
        assert_eq!(parts.len(), 5);
        for p in &parts {
            assert!(WORDLIST_EN.lines().any(|w| w == *p));
        }
    }

    #[test]
    fn passphrase_lingua_italiana_usa_la_wordlist_italiana() {
        let pp = generate_passphrase(PassphraseLang::It, 5, " ").unwrap();
        for p in pp.split(' ') {
            assert!(WORDLIST_IT.lines().any(|w| w == p));
        }
    }

    #[test]
    fn passphrase_zero_parole_e_rifiutata() {
        assert!(matches!(
            generate_passphrase(PassphraseLang::En, 0, "-"),
            Err(CoreError::InvalidInput)
        ));
    }

    #[test]
    fn wordlist_en_ha_la_dimensione_attesa_e_nessun_duplicato() {
        let entries: Vec<&str> = WORDLIST_EN.lines().collect();
        assert_eq!(entries.len(), 7776);
        let mut sorted = entries.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), entries.len());
    }

    #[test]
    fn wordlist_it_ha_la_dimensione_attesa_e_nessun_duplicato() {
        let entries: Vec<&str> = WORDLIST_IT.lines().collect();
        assert_eq!(entries.len(), 8192);
        let mut sorted = entries.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), entries.len());
    }

    #[test]
    fn random_index_resta_nel_range_e_non_e_costante() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let v = random_index(10).unwrap();
            assert!(v < 10);
            seen.insert(v);
        }
        assert!(
            seen.len() > 1,
            "200 estrazioni su 10 valori non possono essere tutte uguali"
        );
    }
}
