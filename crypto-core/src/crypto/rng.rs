//! CSPRNG di sistema (doc 16 §7).
//!
//! Riempimento di byte casuali per nonce e chiavi. Usato solo dall'API di
//! produzione; i percorsi deterministici (test vettoriali) ricevono nonce e chiavi
//! espliciti, mai generati qui (doc 20 §1).

use crate::error::{CoreError, CoreResult};

/// Riempie `buf` con byte casuali dal CSPRNG del sistema operativo.
pub fn fill(buf: &mut [u8]) -> CoreResult<()> {
    getrandom::fill(buf).map_err(|_| CoreError::Internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn riempie_e_non_e_tutto_zero() {
        // Sanity: due chiamate non danno (quasi mai) lo stesso output né tutti zero.
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill(&mut a).unwrap();
        fill(&mut b).unwrap();
        assert_ne!(a, [0u8; 32]);
        assert_ne!(a, b);
    }
}
