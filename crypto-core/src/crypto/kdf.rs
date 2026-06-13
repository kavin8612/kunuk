//! HKDF-SHA-256 (doc 16 §3): derivazione di sotto-chiavi con domain separation.
//!
//! Salt vuoto, output a `KEY_LEN` byte; la separazione di dominio è data
//! dall'etichetta `info` (le etichette stanno in `params`). La conformità all'RFC
//! 5869 è delegata al crate `hkdf` (RustCrypto, testato sui vettori ufficiali).

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::crypto::params::KEY_LEN;
use crate::error::{CoreError, CoreResult};

/// Deriva `KEY_LEN` byte da `ikm` con l'etichetta di dominio `info`
/// (HKDF-SHA-256, salt vuoto). Output azzerato al drop (SR-5).
pub fn hkdf_sha256(ikm: &[u8], info: &[u8]) -> CoreResult<Zeroizing<[u8; KEY_LEN]>> {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(info, okm.as_mut_slice())
        .map_err(|_| CoreError::Internal)?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministico_stesso_input_stesso_output() {
        let a = hkdf_sha256(b"ikm", b"kunuk/v1/test").unwrap();
        let b = hkdf_sha256(b"ikm", b"kunuk/v1/test").unwrap();
        assert_eq!(*a, *b);
    }

    #[test]
    fn etichette_diverse_chiavi_diverse() {
        // Domain separation: la stessa radice con etichette diverse non deve mai
        // produrre la stessa chiave (doc 16 §3).
        let a = hkdf_sha256(b"stessa-radice", b"kunuk/v1/pk/wrap").unwrap();
        let b = hkdf_sha256(b"stessa-radice", b"kunuk/v1/rk/wrap").unwrap();
        assert_ne!(*a, *b);
    }
}
