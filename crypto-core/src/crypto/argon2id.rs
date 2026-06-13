//! Argon2id (doc 16 §3): stretching della password / dell'`export_key` OPAQUE.
//!
//! La conformità all'RFC 9106 è delegata al crate `argon2` (RustCrypto, testato
//! sui vettori ufficiali); qui si fissano i *nostri* parametri e si bloccano i
//! valori coi vettori di progetto (`tests/vectors/kdf/`).

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::crypto::params::{Argon2Params, KEY_LEN};
use crate::error::{CoreError, CoreResult};

/// Deriva `KEY_LEN` byte da `password` e `salt` con Argon2id e i `params` dati.
/// Output azzerato al drop (SR-5). Deterministico: stesso input → stesso output.
pub fn derive(
    password: &[u8],
    salt: &[u8],
    params: &Argon2Params,
) -> CoreResult<Zeroizing<[u8; KEY_LEN]>> {
    let params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|_| CoreError::InvalidInput)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password, salt, out.as_mut_slice())
        .map_err(|_| CoreError::InvalidInput)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::params::ARGON2_V1;

    #[test]
    fn deterministico_stesso_input_stesso_output() {
        let a = derive(b"password-di-prova", &[0x02; 16], &ARGON2_V1).unwrap();
        let b = derive(b"password-di-prova", &[0x02; 16], &ARGON2_V1).unwrap();
        assert_eq!(*a, *b);
    }

    #[test]
    fn salt_diverso_output_diverso() {
        let a = derive(b"password-di-prova", &[0x02; 16], &ARGON2_V1).unwrap();
        let b = derive(b"password-di-prova", &[0x03; 16], &ARGON2_V1).unwrap();
        assert_ne!(*a, *b);
    }
}
