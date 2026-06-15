//! Parametri KDF serializzati in CBOR deterministico (doc 16 §3-4).
//!
//! `KdfParams` incorpora `Argon2Params` (unica dichiarazione dei campi di costo, da
//! `params.rs`) più il salt. Il suo CBOR deterministico è legato nell'AAD della busta
//! password (doc 16 §4): un server che indebolisse i parametri (meno memoria/iterazioni)
//! invaliderebbe il tag. Layout come `vault/manifest.rs`: mappa a chiavi intere,
//! definite-length (RFC 8949 §4.2). La serializzazione è scritta a mano per restare
//! piatta pur incorporando una struct annidata. L'algoritmo è fissato dalla suite 0x01
//! (Argon2id), quindi non è codificato qui.

use minicbor::bytes::ByteArray;
use minicbor::decode::{Decoder, Error as DecodeError};
use minicbor::encode::{Encoder, Error as EncodeError, Write};
use minicbor::{Decode, Encode};

use crate::crypto::cbor;
use crate::crypto::params::{Argon2Params, ARGON2_SALT_LEN, ARGON2_V1};
use crate::error::CoreResult;

/// Parametri della derivazione password (Argon2id + salt), suite 0x01.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Parametri di costo Argon2id (memoria, iterazioni, parallelismo).
    pub argon2: Argon2Params,
    /// Salt CSPRNG (doc 16 §3).
    pub salt: ByteArray<ARGON2_SALT_LEN>,
}

impl KdfParams {
    /// Parametri di riferimento v1 (`ARGON2_V1`) col salt dato.
    pub fn v1(salt: [u8; ARGON2_SALT_LEN]) -> Self {
        Self {
            argon2: ARGON2_V1,
            salt: ByteArray::from(salt),
        }
    }
}

// CBOR canonico: mappa a 4 chiavi intere `{0: memory_kib, 1: iterations, 2: parallelism,
// 3: salt}`, definite-length, interi in forma minima (doc 16 §3-4). Serializzazione
// manuale per mantenere il layout piatto pur incorporando `Argon2Params`.
impl<C> Encode<C> for KdfParams {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), EncodeError<W::Error>> {
        e.map(4)?
            .u32(0)?
            .u32(self.argon2.memory_kib)?
            .u32(1)?
            .u32(self.argon2.iterations)?
            .u32(2)?
            .u32(self.argon2.parallelism)?
            .u32(3)?
            .bytes(&self.salt[..])?;
        Ok(())
    }
}

impl<'b, C> Decode<'b, C> for KdfParams {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, DecodeError> {
        if d.map()? != Some(4) {
            return Err(DecodeError::message(
                "kdf_params: attesa mappa definite-length a 4 voci",
            ));
        }
        let (mut memory_kib, mut iterations, mut parallelism, mut salt) = (None, None, None, None);
        for _ in 0..4 {
            match d.u32()? {
                0 => memory_kib = Some(d.u32()?),
                1 => iterations = Some(d.u32()?),
                2 => parallelism = Some(d.u32()?),
                3 => {
                    let arr: [u8; ARGON2_SALT_LEN] = d.bytes()?.try_into().map_err(|_| {
                        DecodeError::message("kdf_params: salt di lunghezza errata")
                    })?;
                    salt = Some(ByteArray::from(arr));
                }
                _ => return Err(DecodeError::message("kdf_params: chiave sconosciuta")),
            }
        }
        Ok(Self {
            argon2: Argon2Params {
                memory_kib: memory_kib
                    .ok_or_else(|| DecodeError::message("kdf_params: manca memory_kib"))?,
                iterations: iterations
                    .ok_or_else(|| DecodeError::message("kdf_params: manca iterations"))?,
                parallelism: parallelism
                    .ok_or_else(|| DecodeError::message("kdf_params: manca parallelism"))?,
            },
            salt: salt.ok_or_else(|| DecodeError::message("kdf_params: manca salt"))?,
        })
    }
}

/// Serializza i parametri in CBOR deterministico (doc 16 §3-4).
pub fn encode(params: &KdfParams) -> CoreResult<Vec<u8>> {
    cbor::encode(params)
}

/// Deserializza i parametri **esigendo la forma canonica** (doc 16 §1, §8): interi
/// non-shortest, mappe a lunghezza indefinita, chiavi duplicate/non ordinate e byte di
/// coda → `InvalidInput`. I byte sono legati nell'AAD della busta password
/// (anti-downgrade, doc 16 §4), quindi devono essere univoci.
pub fn decode(bytes: &[u8]) -> CoreResult<KdfParams> {
    cbor::decode_canonical(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CoreError;

    const SALT: [u8; ARGON2_SALT_LEN] = [0x07; ARGON2_SALT_LEN];

    #[test]
    fn round_trip() {
        let p = KdfParams::v1(SALT);
        let cbor = encode(&p).unwrap();
        assert_eq!(decode(&cbor).unwrap(), p);
    }

    #[test]
    fn v1_usa_parametri_di_riferimento() {
        let p = KdfParams::v1(SALT);
        assert_eq!(p.argon2, ARGON2_V1);
        assert_eq!(*p.salt, SALT);
    }

    #[test]
    fn deterministico_stesso_input_stessi_byte() {
        let p = KdfParams::v1(SALT);
        assert_eq!(encode(&p).unwrap(), encode(&p).unwrap());
    }

    #[test]
    fn cbor_byte_esatto_v1() {
        // Vettore byte-esatto: v1 (64 MiB, 3 iter, 4 lanes) + salt 0x07*16.
        // Mappa a 4 chiavi intere, definite-length (doc 16 §3-4).
        let cbor = encode(&KdfParams::v1(SALT)).unwrap();
        assert_eq!(
            hex::encode(&cbor),
            "a4001a0001000001030204035007070707070707070707070707070707"
        );
    }

    #[test]
    fn decode_rifiuta_input_non_valido() {
        assert!(matches!(
            decode(&[0xff, 0xff]),
            Err(CoreError::InvalidInput)
        ));
    }

    #[test]
    fn decode_rifiuta_intero_non_shortest() {
        // memory_kib codificato su 8 byte (0x1b) invece della forma minima: decodifica
        // agli stessi parametri ma non è canonico (doc 16 §1) → InvalidInput.
        let non_shortest =
            hex::decode("a4001b000000000001000001030204035007070707070707070707070707070707")
                .unwrap();
        assert!(matches!(
            decode(&non_shortest),
            Err(CoreError::InvalidInput)
        ));
    }

    #[test]
    fn decode_rifiuta_byte_di_coda() {
        // Encoding canonico valido seguito da byte spuri → InvalidInput.
        let mut trailing = encode(&KdfParams::v1(SALT)).unwrap();
        trailing.extend_from_slice(&[0xde, 0xad]);
        assert!(matches!(decode(&trailing), Err(CoreError::InvalidInput)));
    }
}
