//! Registrazione di un account (doc 05 §4, doc 20 §3).
//!
//! `register` genera i segreti casuali (Secret Key 2SKD, VK, seme di firma) e assembla
//! il [`RegistrationBundle`]: le tre buste della VK (password/passkey/recupero), il
//! verificatore di autenticazione, la pubkey di prova-di-possesso del recupero, la chiave
//! di firma avvolta + il manifest vuoto firmato. La Secret Key esce solo dentro
//! l'[`EmergencyKit`], che la consegna una volta sola.
//!
//! Tutti i segreti restano lato client (zero-knowledge, ADR-0002): al server va il bundle
//! **meno** l'`emergency_kit`. La funzione è composizione di primitive già vettorializzate
//! (doc 16 §8), quindi è coperta da unit test, non da una nuova categoria di vettori.

use minicbor::bytes::ByteArray;
use zeroize::Zeroizing;

use crate::crypto::aead::NONCE_LEN;
use crate::crypto::kdf_params::{self, KdfParams};
use crate::crypto::params::{ARGON2_SALT_LEN, KEY_LEN, SECRET_KEY_LEN};
use crate::crypto::rng;
use crate::crypto::signature;
use crate::envelope::{self, EnvelopeType, ACCOUNT_ID_LEN, EMPTY_KDF_PARAMS_CBOR};
use crate::error::{CoreError, CoreResult};
use crate::keys;
use crate::vault::item::ID_LEN;
use crate::vault::manifest::{self, ManifestContent};

/// Versione del primo manifest di un vault appena creato. Le versioni sono monotone
/// crescenti (doc 16 §6): la verifica anti-rollback parte da qui.
const INITIAL_MANIFEST_VERSION: u64 = 1;

/// Handle one-shot della Secret Key appena generata (doc 20 §2). L'utente la deve
/// custodire offline (Emergency Kit): combinata con la password sblocca il vault su nuovi
/// dispositivi (2SKD), e da sola abilita il recupero (ADR-0006). La consegna è **una
/// volta sola** ([`reveal_secret_key`](EmergencyKit::reveal_secret_key)); dopo, l'handle
/// è vuoto e i byte sono azzerati (SR-5).
///
/// Nota (task 0.7): la **resa testuale** della Secret Key (`display_phrase`, scelta tra
/// base32+checksum e mnemonica BIP39) è rinviata a un task dedicato con il suo ADR — è un
/// formato "supportato per sempre" e va deciso col client/UX. Qui l'handle espone i byte
/// grezzi, che la UX renderizzerà.
pub struct EmergencyKit {
    secret_key: Option<Zeroizing<[u8; SECRET_KEY_LEN]>>,
}

impl EmergencyKit {
    fn new(secret_key: [u8; SECRET_KEY_LEN]) -> Self {
        Self {
            secret_key: Some(Zeroizing::new(secret_key)),
        }
    }

    /// Consegna la Secret Key **una volta sola**. La seconda chiamata fallisce con
    /// `InvalidInput`: il kit va mostrato all'utente una volta e non riletto (one-shot,
    /// doc 20 §3).
    pub fn reveal_secret_key(&mut self) -> CoreResult<Zeroizing<[u8; SECRET_KEY_LEN]>> {
        self.secret_key.take().ok_or(CoreError::InvalidInput)
    }
}

/// Bundle prodotto dalla registrazione (doc 20 §3). Il client carica tutto **tranne**
/// l'`emergency_kit` con `/auth/register`. Non implementa `Debug`: contiene materiale
/// sensibile (verificatore, Secret Key nell'handle) che non deve finire nei log.
pub struct RegistrationBundle {
    /// Identificatore del vault appena creato (UUID raw); lega manifest e chiave di firma.
    pub vault_id: [u8; ID_LEN],
    /// Parametri KDF (Argon2id + salt) in CBOR deterministico, legati nell'AAD della
    /// busta password (anti-downgrade, doc 16 §4).
    pub kdf_params_cbor: Vec<u8>,
    /// Busta password `wrap_PK(VK)`: serve password **e** Secret Key per aprirla.
    pub password_envelope: Vec<u8>,
    /// Busta passkey `wrap_PRF(VK)`: presente solo se è stato fornito l'`prf_output`.
    pub passkey_envelope: Option<Vec<u8>>,
    /// Busta recupero `wrap_SK(VK)`: aperta dalla sola Secret Key (doc 05 §5).
    pub recovery_envelope: Vec<u8>,
    /// Chiave pubblica Ed25519 di prova-di-possesso del recupero (da `RKa`, doc 16 §3).
    pub recovery_pubkey: [u8; 32],
    /// Verificatore di autenticazione della via password (doc 16 §3): va al server, che
    /// ne memorizza un hash. In `Zeroizing` per non lasciarne copie in RAM (SR-5).
    pub auth_verifier: Zeroizing<[u8; KEY_LEN]>,
    /// Secret Key da mostrare all'utente una volta sola.
    pub emergency_kit: EmergencyKit,
    /// Chiave pubblica di verifica del manifest (pinned, doc 16 §6).
    pub signing_pubkey: [u8; 32],
    /// Seme della chiave di firma avvolto dalla VK (doc 16 §6), persistito col vault.
    pub wrapped_signing_key: Vec<u8>,
    /// Manifest vuoto iniziale, firmato (version 1, nessuna voce).
    pub signed_empty_manifest: Vec<u8>,
}

/// Materiale casuale iniettato nella registrazione deterministica ([`register_with`]),
/// per i test. In produzione lo genera il CSPRNG dentro [`register`] (doc 20 §1): mai
/// generato qui, così il percorso deterministico resta confinato ai test.
pub struct RegistrationRandomness<'a> {
    /// Secret Key a 128 bit (2SKD, ADR-0006).
    pub secret_key: &'a [u8; SECRET_KEY_LEN],
    /// Identificatore del nuovo vault (UUID raw).
    pub vault_id: &'a [u8; ID_LEN],
    /// Vault Key a 256 bit (mai derivata, doc 05 §2).
    pub vk: &'a [u8; KEY_LEN],
    /// Seme Ed25519 della chiave di firma del manifest.
    pub signing_seed: &'a [u8; KEY_LEN],
    /// Salt Argon2id della derivazione password.
    pub salt_pk: &'a [u8; ARGON2_SALT_LEN],
    /// Nonce della busta password.
    pub password_nonce: &'a [u8; NONCE_LEN],
    /// Nonce della busta passkey.
    pub passkey_nonce: &'a [u8; NONCE_LEN],
    /// Nonce della busta recupero.
    pub recovery_nonce: &'a [u8; NONCE_LEN],
    /// Nonce della busta della chiave di firma.
    pub signing_key_nonce: &'a [u8; NONCE_LEN],
}

/// Registrazione deterministica: usa il materiale casuale fornito invece del CSPRNG
/// (percorso per i test, doc 20 §1). `prf_output`, se presente, è l'output dell'estensione
/// WebAuthn PRF della passkey (deve avere la lunghezza attesa, altrimenti `InvalidInput`).
pub fn register_with(
    password: &[u8],
    prf_output: Option<&[u8]>,
    account_id: &[u8; ACCOUNT_ID_LEN],
    rnd: &RegistrationRandomness,
) -> CoreResult<RegistrationBundle> {
    // Parametri KDF della via password: salt dedicato, resto dalla suite v1 (doc 16 §3).
    let kdf_params = KdfParams::v1(*rnd.salt_pk);
    let kdf_params_cbor = kdf_params::encode(&kdf_params)?;

    // Derivazioni dal segreto 2SKD `password ‖ Secret Key`: chiave-password e verificatore
    // condividono la radice (stretching Argon2id), calcolata una sola volta, poi due
    // etichette HKDF distinte (domain separation, doc 16 §3).
    let (pk, auth_verifier) = keys::pk_and_auth_verifier(
        password,
        rnd.secret_key,
        rnd.salt_pk,
        &kdf_params.argon2,
        account_id,
    )?;

    // Busta password: i parametri KDF reali sono nell'AAD (anti-downgrade, doc 16 §4).
    let password_envelope = envelope::wrap_with_nonce(
        &pk,
        rnd.vk,
        account_id,
        EnvelopeType::Password,
        &kdf_params_cbor,
        rnd.password_nonce,
    )?;

    // Busta passkey: opzionale (solo se c'è l'`prf_output`); AAD con mappa KDF vuota
    // perché la chiave di wrapping non deriva da Argon2id (doc 16 §4).
    let passkey_envelope = match prf_output {
        Some(prf) => {
            let prf_wrap = keys::prf_wrap_key(prf)?;
            Some(envelope::wrap_with_nonce(
                &prf_wrap,
                rnd.vk,
                account_id,
                EnvelopeType::Passkey,
                EMPTY_KDF_PARAMS_CBOR,
                rnd.passkey_nonce,
            )?)
        }
        None => None,
    };

    // Busta recupero + pubkey di prova-di-possesso, entrambe dalla sola Secret Key.
    let recovery_wrap = keys::rk_wrap_key(rnd.secret_key)?;
    let recovery_envelope = envelope::wrap_with_nonce(
        &recovery_wrap,
        rnd.vk,
        account_id,
        EnvelopeType::Recovery,
        EMPTY_KDF_PARAMS_CBOR,
        rnd.recovery_nonce,
    )?;
    let (_, recovery_pubkey) = keys::rk_auth_keypair(rnd.secret_key)?;

    // Chiave di firma del manifest: seme casuale avvolto dalla VK (non derivato, doc 16 §6).
    let (signing_key, signing_pubkey) = signature::keypair_from_seed(rnd.signing_seed);
    let wrapped_signing_key = manifest::wrap_signing_key_with_nonce(
        rnd.vk,
        rnd.signing_seed,
        rnd.vault_id,
        rnd.signing_key_nonce,
    )?;

    // Manifest vuoto iniziale firmato: inventario di un vault senza voci (doc 16 §6).
    let empty_manifest = ManifestContent {
        vault_id: ByteArray::from(*rnd.vault_id),
        version: INITIAL_MANIFEST_VERSION,
        items: Vec::new(),
        crdt_clock: Vec::new(),
    };
    let signed_empty_manifest = manifest::sign_manifest(&signing_key, &empty_manifest)?;

    Ok(RegistrationBundle {
        vault_id: *rnd.vault_id,
        kdf_params_cbor,
        password_envelope,
        passkey_envelope,
        recovery_envelope,
        recovery_pubkey: recovery_pubkey.to_bytes(),
        auth_verifier,
        emergency_kit: EmergencyKit::new(*rnd.secret_key),
        signing_pubkey: signing_pubkey.to_bytes(),
        wrapped_signing_key,
        signed_empty_manifest,
    })
}

/// Registra un account generando i segreti dal CSPRNG di sistema (doc 05 §4, doc 20 §3).
/// La Secret Key, la VK e il seme di firma sono casuali e mai noti al server; escono solo
/// dentro il bundle (la Secret Key solo via [`EmergencyKit`]). `prf_output` è l'output
/// WebAuthn PRF della passkey, se l'utente ne registra una in fase di onboarding.
pub fn register(
    password: &[u8],
    prf_output: Option<&[u8]>,
    account_id: &[u8; ACCOUNT_ID_LEN],
) -> CoreResult<RegistrationBundle> {
    // Segreti in `Zeroizing`: azzerati appena escono dallo scope (SR-5).
    let mut secret_key = Zeroizing::new([0u8; SECRET_KEY_LEN]);
    rng::fill(secret_key.as_mut_slice())?;
    let mut vk = Zeroizing::new([0u8; KEY_LEN]);
    rng::fill(vk.as_mut_slice())?;
    let mut signing_seed = Zeroizing::new([0u8; KEY_LEN]);
    rng::fill(signing_seed.as_mut_slice())?;

    // Materiale non segreto ma comunque casuale: id del vault, salt e nonce.
    let mut vault_id = [0u8; ID_LEN];
    rng::fill(&mut vault_id)?;
    let mut salt_pk = [0u8; ARGON2_SALT_LEN];
    rng::fill(&mut salt_pk)?;
    let mut password_nonce = [0u8; NONCE_LEN];
    rng::fill(&mut password_nonce)?;
    let mut passkey_nonce = [0u8; NONCE_LEN];
    rng::fill(&mut passkey_nonce)?;
    let mut recovery_nonce = [0u8; NONCE_LEN];
    rng::fill(&mut recovery_nonce)?;
    let mut signing_key_nonce = [0u8; NONCE_LEN];
    rng::fill(&mut signing_key_nonce)?;

    let rnd = RegistrationRandomness {
        secret_key: &secret_key,
        vault_id: &vault_id,
        vk: &vk,
        signing_seed: &signing_seed,
        salt_pk: &salt_pk,
        password_nonce: &password_nonce,
        passkey_nonce: &passkey_nonce,
        recovery_nonce: &recovery_nonce,
        signing_key_nonce: &signing_key_nonce,
    };
    register_with(password, prf_output, account_id, &rnd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::params::{ARGON2_V1, PRF_OUTPUT_LEN};

    const PASSWORD: &[u8] = b"correct horse battery staple";
    const SECRET_KEY: [u8; SECRET_KEY_LEN] = [0xA1; SECRET_KEY_LEN];
    const VAULT_ID: [u8; ID_LEN] = [0x66; ID_LEN];
    const VK: [u8; KEY_LEN] = [0x22; KEY_LEN];
    const SIGNING_SEED: [u8; KEY_LEN] = [0x44; KEY_LEN];
    const SALT_PK: [u8; ARGON2_SALT_LEN] = [0x07; ARGON2_SALT_LEN];
    const ACCOUNT: [u8; ACCOUNT_ID_LEN] = [0x10; ACCOUNT_ID_LEN];
    const PRF: [u8; PRF_OUTPUT_LEN] = [0x5A; PRF_OUTPUT_LEN];
    const N_PW: [u8; NONCE_LEN] = [0x01; NONCE_LEN];
    const N_PK: [u8; NONCE_LEN] = [0x02; NONCE_LEN];
    const N_RK: [u8; NONCE_LEN] = [0x03; NONCE_LEN];
    const N_SK: [u8; NONCE_LEN] = [0x04; NONCE_LEN];

    fn randomness() -> RegistrationRandomness<'static> {
        RegistrationRandomness {
            secret_key: &SECRET_KEY,
            vault_id: &VAULT_ID,
            vk: &VK,
            signing_seed: &SIGNING_SEED,
            salt_pk: &SALT_PK,
            password_nonce: &N_PW,
            passkey_nonce: &N_PK,
            recovery_nonce: &N_RK,
            signing_key_nonce: &N_SK,
        }
    }

    #[test]
    fn buste_si_aprono_tutte_sulla_stessa_vk() {
        let bundle = register_with(PASSWORD, Some(&PRF), &ACCOUNT, &randomness()).unwrap();

        // Busta password: PK derivata da `password ‖ Secret Key`, parametri reali nell'AAD.
        let pk = keys::pk_from_password(PASSWORD, &SECRET_KEY, &SALT_PK, &ARGON2_V1).unwrap();
        let from_password = envelope::unwrap(
            &pk,
            &bundle.password_envelope,
            &ACCOUNT,
            EnvelopeType::Password,
            &bundle.kdf_params_cbor,
        )
        .unwrap();
        assert_eq!(*from_password, VK);

        // Busta passkey: chiave PRF, mappa KDF vuota nell'AAD.
        let prf_wrap = keys::prf_wrap_key(&PRF).unwrap();
        let from_passkey = envelope::unwrap(
            &prf_wrap,
            bundle.passkey_envelope.as_ref().unwrap(),
            &ACCOUNT,
            EnvelopeType::Passkey,
            EMPTY_KDF_PARAMS_CBOR,
        )
        .unwrap();
        assert_eq!(*from_passkey, VK);

        // Busta recupero: chiave dalla sola Secret Key.
        let recovery_wrap = keys::rk_wrap_key(&SECRET_KEY).unwrap();
        let from_recovery = envelope::unwrap(
            &recovery_wrap,
            &bundle.recovery_envelope,
            &ACCOUNT,
            EnvelopeType::Recovery,
            EMPTY_KDF_PARAMS_CBOR,
        )
        .unwrap();
        assert_eq!(*from_recovery, VK);
    }

    #[test]
    fn verificatore_e_pubkey_coincidono_con_le_derivazioni() {
        let bundle = register_with(PASSWORD, Some(&PRF), &ACCOUNT, &randomness()).unwrap();

        let av =
            keys::auth_verifier(PASSWORD, &SECRET_KEY, &SALT_PK, &ARGON2_V1, &ACCOUNT).unwrap();
        assert_eq!(*bundle.auth_verifier, *av);

        let (_, recovery_pub) = keys::rk_auth_keypair(&SECRET_KEY).unwrap();
        assert_eq!(bundle.recovery_pubkey, recovery_pub.to_bytes());

        let (_, signing_pub) = signature::keypair_from_seed(&SIGNING_SEED);
        assert_eq!(bundle.signing_pubkey, signing_pub.to_bytes());
    }

    #[test]
    fn chiave_di_firma_avvolta_si_riapre_e_firma_il_manifest() {
        let bundle = register_with(PASSWORD, Some(&PRF), &ACCOUNT, &randomness()).unwrap();

        // La busta della chiave di firma si apre con la VK e ricostruisce la stessa pubkey.
        let signing_key =
            manifest::unwrap_signing_key(&VK, &bundle.wrapped_signing_key, &VAULT_ID).unwrap();
        assert_eq!(
            signing_key.verifying_key().to_bytes(),
            bundle.signing_pubkey
        );

        // Il manifest vuoto verifica con la pubkey pinned: version iniziale, nessuna voce.
        let (_, signing_pub) = signature::keypair_from_seed(&SIGNING_SEED);
        let view = manifest::verify_manifest(
            &signing_pub,
            &bundle.signed_empty_manifest,
            &VAULT_ID,
            INITIAL_MANIFEST_VERSION,
        )
        .unwrap();
        assert_eq!(view.version, INITIAL_MANIFEST_VERSION);
        assert!(view.items.is_empty());
    }

    #[test]
    fn senza_prf_output_niente_busta_passkey() {
        let bundle = register_with(PASSWORD, None, &ACCOUNT, &randomness()).unwrap();
        assert!(bundle.passkey_envelope.is_none());
        // Le altre buste restano: password e recupero ci sono sempre.
        assert!(!bundle.password_envelope.is_empty());
        assert!(!bundle.recovery_envelope.is_empty());
    }

    #[test]
    fn prf_output_di_lunghezza_errata_rifiutato() {
        // Un output PRF troncato deriverebbe una chiave a bassa entropia → rifiuto al confine.
        assert!(matches!(
            register_with(
                PASSWORD,
                Some(&[0x5A; PRF_OUTPUT_LEN - 1]),
                &ACCOUNT,
                &randomness()
            ),
            Err(CoreError::InvalidInput)
        ));
    }

    #[test]
    fn emergency_kit_one_shot() {
        let mut bundle = register_with(PASSWORD, Some(&PRF), &ACCOUNT, &randomness()).unwrap();
        let revealed = bundle.emergency_kit.reveal_secret_key().unwrap();
        assert_eq!(*revealed, SECRET_KEY);
        // Seconda lettura: il kit è già stato consumato.
        assert!(matches!(
            bundle.emergency_kit.reveal_secret_key(),
            Err(CoreError::InvalidInput)
        ));
    }

    #[test]
    fn register_produzione_round_trip_end_to_end() {
        // `register` genera i segreti dal CSPRNG: non possiamo predire i byte, ma la Secret
        // Key esce dall'Emergency Kit e i parametri dal bundle, così ricostruiamo la VK da
        // due percorsi indipendenti (password e recupero) e verifichiamo che coincidano.
        let mut bundle = register(PASSWORD, Some(&PRF), &ACCOUNT).unwrap();
        let secret_key = bundle.emergency_kit.reveal_secret_key().unwrap();
        let params = kdf_params::decode(&bundle.kdf_params_cbor).unwrap();

        let pk =
            keys::pk_from_password(PASSWORD, &secret_key[..], &params.salt[..], &params.argon2)
                .unwrap();
        let from_password = envelope::unwrap(
            &pk,
            &bundle.password_envelope,
            &ACCOUNT,
            EnvelopeType::Password,
            &bundle.kdf_params_cbor,
        )
        .unwrap();

        let recovery_wrap = keys::rk_wrap_key(&secret_key[..]).unwrap();
        let from_recovery = envelope::unwrap(
            &recovery_wrap,
            &bundle.recovery_envelope,
            &ACCOUNT,
            EnvelopeType::Recovery,
            EMPTY_KDF_PARAMS_CBOR,
        )
        .unwrap();

        assert_eq!(
            *from_password, *from_recovery,
            "stessa VK da percorsi diversi"
        );

        // La VK ricostruita apre anche la busta passkey: i tre percorsi convergono.
        let prf_wrap = keys::prf_wrap_key(&PRF).unwrap();
        let from_passkey = envelope::unwrap(
            &prf_wrap,
            bundle.passkey_envelope.as_ref().unwrap(),
            &ACCOUNT,
            EnvelopeType::Passkey,
            EMPTY_KDF_PARAMS_CBOR,
        )
        .unwrap();
        assert_eq!(
            *from_password, *from_passkey,
            "stessa VK anche dalla passkey"
        );
    }
}
