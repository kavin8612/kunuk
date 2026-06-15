//! Helper CBOR condiviso (doc 16 §1).
//!
//! Unico punto per serializzare/deserializzare i contenuti CBOR del core, con il
//! mapping d'errore uniforme: encode → `Internal` (fallimento improbabile lato nostro),
//! decode → `InvalidInput`. `decode_canonical` aggiunge il controllo di **forma
//! canonica** (RFC 8949 §4.2) per i byte legati crittograficamente.

use minicbor::{Decode, Encode};

use crate::error::{CoreError, CoreResult};

/// Serializza in CBOR. Un fallimento di serializzazione è interno → `Internal`.
pub fn encode<T: Encode<()>>(value: &T) -> CoreResult<Vec<u8>> {
    minicbor::to_vec(value).map_err(|_| CoreError::Internal)
}

/// Deserializza CBOR senza esigere la forma canonica. Input non valido → `InvalidInput`.
pub fn decode<'b, T: Decode<'b, ()>>(bytes: &'b [u8]) -> CoreResult<T> {
    minicbor::decode(bytes).map_err(|_| CoreError::InvalidInput)
}

/// Deserializza **esigendo la forma canonica** (doc 16 §1): ri-serializza il risultato e
/// pretende che coincida byte-per-byte con l'input. Rifiuta interi non-shortest, mappe a
/// lunghezza indefinita, chiavi duplicate/non ordinate e byte di coda → `InvalidInput`.
/// Da usare quando i byte CBOR sono legati a un tag/firma e devono essere univoci
/// (es. `kdf_params` nell'AAD della busta, doc 16 §4).
pub fn decode_canonical<'b, T: Encode<()> + Decode<'b, ()>>(bytes: &'b [u8]) -> CoreResult<T> {
    let value: T = decode(bytes)?;
    if encode(&value)?.as_slice() != bytes {
        return Err(CoreError::InvalidInput);
    }
    Ok(value)
}
