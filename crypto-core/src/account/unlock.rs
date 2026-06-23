//! Sblocco del vault (doc 05 §6, doc 20 §4).
//!
//! Ogni via di sblocco apre una busta della VK con la chiave di wrapping del percorso
//! corrispondente e restituisce un [`VaultKey`]: handle opaco che tiene la VK in memoria
//! azzerabile (SR-5) finché non viene bloccato. L'autenticazione verso il server (assertion
//! WebAuthn, verificatore password) è del client/backend, separata dallo sblocco (ADR-0006):
//! qui c'è solo l'apertura della busta. Decifrazione fail-closed (doc 16 §7): chiave
//! sbagliata, busta trapiantata su un altro account o parametri alterati → `DecryptFailed`.

use zeroize::Zeroizing;

use crate::crypto::kdf_params;
use crate::crypto::params::KEY_LEN;
use crate::envelope::{self, EnvelopeType, ACCOUNT_ID_LEN, EMPTY_KDF_PARAMS_CBOR};
use crate::error::CoreResult;
use crate::keys;
use crate::vault::item::{self, ID_LEN};

/// Handle opaco della VK sbloccata (doc 20 §1-2). La VK vive in `Zeroizing`: azzerata al
/// drop o esplicitamente con [`lock`](VaultKey::lock). I byte della chiave non escono
/// dalla superficie pubblica; le operazioni sul vault (item, manifest) la consumano dentro
/// il crate.
pub struct VaultKey {
    vk: Zeroizing<[u8; KEY_LEN]>,
}

impl VaultKey {
    /// Costruisce l'handle dalla VK appena scartata da una busta. `pub(crate)`: solo i
    /// flussi del core (unlock, recovery) producono un `VaultKey`, mai un chiamante esterno.
    pub(crate) fn new(vk: Zeroizing<[u8; KEY_LEN]>) -> Self {
        Self { vk }
    }

    /// Blocca il vault azzerando subito la VK (doc 20 §4). Consuma l'handle: dopo il
    /// `lock` non è più utilizzabile.
    pub fn lock(self) {
        // La VK è azzerata dal `Drop` di `Zeroizing` quando `self` esce di scope qui.
    }

    /// Accesso interno alla VK per le operazioni sul vault dello stesso crate (item,
    /// manifest, abilitazione di nuove buste). Non è esposto fuori dal core: gli handle
    /// non emettono byte di chiave (doc 20 §1).
    pub(crate) fn expose(&self) -> &[u8; KEY_LEN] {
        &self.vk
    }

    /// Cifra un item del vault con questa VK (doc 16 §5, doc 20 §5). Genera CEK e nonce
    /// freschi e lega `vault_id ‖ item_id` nell'AAD (anti-trapianto/swap). Ritorna
    /// `(ciphertext, wrapped_cek)`. È così che i client (CLI compresa) consumano la VK
    /// **come handle opaco**: i byte della chiave non lasciano il core (doc 20 §1).
    pub fn encrypt_item(
        &self,
        vault_id: &[u8; ID_LEN],
        item_id: &[u8; ID_LEN],
        content_cbor: &[u8],
    ) -> CoreResult<(Vec<u8>, Vec<u8>)> {
        item::encrypt_item(self.expose(), vault_id, item_id, content_cbor)
    }

    /// Decifra un item del vault con questa VK (doc 16 §5, doc 20 §5). Trapianto su un altro
    /// item/vault o ciphertext manomesso → `DecryptFailed`. Ritorna il CBOR del contenuto
    /// (azzerato al drop).
    pub fn decrypt_item(
        &self,
        vault_id: &[u8; ID_LEN],
        item_id: &[u8; ID_LEN],
        ciphertext: &[u8],
        wrapped_cek: &[u8],
    ) -> CoreResult<Zeroizing<Vec<u8>>> {
        item::decrypt_item(self.expose(), vault_id, item_id, ciphertext, wrapped_cek)
    }

    /// Cifra un delta CRDT del sync con questa VK (doc 20 §8, ADR-0022): stesso principio di
    /// [`encrypt_item`](Self::encrypt_item), il delta della directory è cifrato direttamente
    /// con la VK (niente CEK, è un oggetto separato dal contenuto degli item).
    pub fn encode_sync_delta(
        &self,
        vault_id: &[u8; ID_LEN],
        local_changes: &[u8],
    ) -> CoreResult<Vec<u8>> {
        crate::sync::sync_encode_delta(self.expose(), vault_id, local_changes)
    }

    /// Decifra e applica una sequenza di delta CRDT ricevuti, risolvendo la directory
    /// convergente (doc 20 §8). Come [`decrypt_item`](Self::decrypt_item): i byte della VK non
    /// lasciano il core.
    pub fn apply_sync_deltas(
        &self,
        doc: &mut crate::sync::SyncDoc,
        vault_id: &[u8; ID_LEN],
        encrypted_deltas: &[Vec<u8>],
    ) -> CoreResult<crate::sync::MergeResult> {
        crate::sync::sync_apply_deltas(doc, self.expose(), vault_id, encrypted_deltas)
    }

    /// Avvolge il seme della chiave di firma con questa VK (doc 16 §6). Come
    /// [`encrypt_item`](Self::encrypt_item): è così che i client la incartano alla
    /// registrazione senza toccare byte di chiave.
    pub fn wrap_signing_key(
        &self,
        signing_seed: &[u8; KEY_LEN],
        vault_id: &[u8; ID_LEN],
    ) -> CoreResult<Vec<u8>> {
        crate::vault::manifest::wrap_signing_key(self.expose(), signing_seed, vault_id)
    }

    /// Apre la busta della chiave di firma e firma un nuovo contenuto di manifest, in
    /// un'unica chiamata (doc 16 §6): serve a ri-firmare il manifest dopo un login o un CRUD
    /// item (task 1.3), non solo alla registrazione. Restituisce solo i byte del manifest
    /// firmato: la `SigningKey` (tipo di `ed25519-dalek`) non esce mai dal core, così i
    /// client non hanno bisogno di importare quella dipendenza solo per nominarne il tipo
    /// (SR-1, doc 19 §5). Trapianto su un altro vault o busta manomessa → `DecryptFailed`.
    pub fn sign_manifest(
        &self,
        wrapped_signing_key: &[u8],
        vault_id: &[u8; ID_LEN],
        content: &crate::vault::manifest::ManifestContent,
    ) -> CoreResult<Vec<u8>> {
        let signing_key = crate::vault::manifest::unwrap_signing_key(
            self.expose(),
            wrapped_signing_key,
            vault_id,
        )?;
        crate::vault::manifest::sign_manifest(&signing_key, content)
    }
}

/// Deriva il verificatore di autenticazione della via password (doc 16 §3) per
/// autenticarsi al server, **prima** di aprire la busta. Estrae il salt dai
/// `kdf_params` (CBOR canonico) e delega a [`keys::auth_verifier`]: il verificatore è
/// legato all'account, distinto dalla chiave-password e non reversibile (doc 16 §3).
pub fn derive_auth_verifier(
    password: &[u8],
    secret_key: &[u8],
    kdf_params_cbor: &[u8],
    account_id: &[u8; ACCOUNT_ID_LEN],
) -> CoreResult<Zeroizing<[u8; KEY_LEN]>> {
    let params = kdf_params::decode(kdf_params_cbor)?;
    keys::auth_verifier(
        password,
        secret_key,
        &params.salt[..],
        &params.argon2,
        account_id,
    )
}

/// Sblocco con master password (doc 05 §6b). Deriva PK da `password ‖ Secret Key` (2SKD,
/// stessi parametri della registrazione) e apre la busta password. Password o Secret Key
/// errate, account diverso o parametri alterati (anti-downgrade) → `DecryptFailed`.
pub fn unlock_with_password(
    password: &[u8],
    secret_key: &[u8],
    password_envelope: &[u8],
    kdf_params_cbor: &[u8],
    account_id: &[u8; ACCOUNT_ID_LEN],
) -> CoreResult<VaultKey> {
    let params = kdf_params::decode(kdf_params_cbor)?;
    let pk = keys::pk_from_password(password, secret_key, &params.salt[..], &params.argon2)?;
    let vk = envelope::unwrap(
        &pk,
        password_envelope,
        account_id,
        EnvelopeType::Password,
        kdf_params_cbor,
    )?;
    Ok(VaultKey::new(vk))
}

/// Sblocco con passkey (doc 05 §6a). L'assertion WebAuthn (auth al server) è del client; il
/// core riceve l'`prf_output` dell'estensione PRF, ne deriva la chiave di wrapping e apre la
/// busta passkey. `prf_output` di lunghezza errata → `InvalidInput`.
pub fn unlock_with_passkey(
    prf_output: &[u8],
    passkey_envelope: &[u8],
    account_id: &[u8; ACCOUNT_ID_LEN],
) -> CoreResult<VaultKey> {
    let prf_wrap = keys::prf_wrap_key(prf_output)?;
    let vk = envelope::unwrap(
        &prf_wrap,
        passkey_envelope,
        account_id,
        EnvelopeType::Passkey,
        EMPTY_KDF_PARAMS_CBOR,
    )?;
    Ok(VaultKey::new(vk))
}

/// Sblocco biometrico/PIN, locale al dispositivo (doc 05 §6c). La device key DK è custodita
/// nel Secure Enclave/Keystore e rilasciata all'app **solo dopo** l'autenticazione
/// biometrica: il binding di piattaforma (`DeviceKeyRef` nei binding) la consegna qui come
/// byte, da cui il core deriva la chiave di wrapping e apre la busta biometria. La busta
/// vive sul dispositivo, non sul server (doc 11). DK errata → `DecryptFailed`.
pub fn unlock_with_device_key(
    device_key: &[u8],
    biometric_envelope: &[u8],
    account_id: &[u8; ACCOUNT_ID_LEN],
) -> CoreResult<VaultKey> {
    let dk_wrap = keys::dk_wrap_key(device_key)?;
    let vk = envelope::unwrap(
        &dk_wrap,
        biometric_envelope,
        account_id,
        EnvelopeType::Biometric,
        EMPTY_KDF_PARAMS_CBOR,
    )?;
    Ok(VaultKey::new(vk))
}

/// Abilita lo sblocco con passkey su un vault già sbloccato (doc 20 §4): avvolge la VK con
/// la chiave PRF e restituisce la busta passkey (nonce fresco dal CSPRNG). Permette di
/// aggiungere la passkey a un account registrato con la sola password.
pub fn enable_passkey_unlock(
    vk: &VaultKey,
    prf_output: &[u8],
    account_id: &[u8; ACCOUNT_ID_LEN],
) -> CoreResult<Vec<u8>> {
    let prf_wrap = keys::prf_wrap_key(prf_output)?;
    envelope::wrap(
        &prf_wrap,
        vk.expose(),
        account_id,
        EnvelopeType::Passkey,
        EMPTY_KDF_PARAMS_CBOR,
    )
}

/// Abilita lo sblocco biometrico su un vault già sbloccato (doc 20 §4): avvolge la VK con la
/// chiave derivata dalla device key e restituisce la busta biometria, da custodire **sul
/// dispositivo** (non sul server, doc 11). È così che nasce la busta che
/// [`unlock_with_device_key`] aprirà.
pub fn enable_biometric_unlock(
    vk: &VaultKey,
    device_key: &[u8],
    account_id: &[u8; ACCOUNT_ID_LEN],
) -> CoreResult<Vec<u8>> {
    let dk_wrap = keys::dk_wrap_key(device_key)?;
    envelope::wrap(
        &dk_wrap,
        vk.expose(),
        account_id,
        EnvelopeType::Biometric,
        EMPTY_KDF_PARAMS_CBOR,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::registration::{register_with, RegistrationRandomness};
    use crate::crypto::aead::NONCE_LEN;
    use crate::crypto::params::{ARGON2_SALT_LEN, PRF_OUTPUT_LEN, SECRET_KEY_LEN};
    use crate::error::CoreError;
    use crate::vault::item::ID_LEN;

    const PASSWORD: &[u8] = b"correct horse battery staple";
    const SECRET_KEY: [u8; SECRET_KEY_LEN] = [0xA1; SECRET_KEY_LEN];
    const VAULT_ID: [u8; ID_LEN] = [0x66; ID_LEN];
    const VK: [u8; KEY_LEN] = [0x22; KEY_LEN];
    const SIGNING_SEED: [u8; KEY_LEN] = [0x44; KEY_LEN];
    const SALT_PK: [u8; ARGON2_SALT_LEN] = [0x07; ARGON2_SALT_LEN];
    const ACCOUNT: [u8; ACCOUNT_ID_LEN] = [0x10; ACCOUNT_ID_LEN];
    const PRF: [u8; PRF_OUTPUT_LEN] = [0x5A; PRF_OUTPUT_LEN];
    const DEVICE_KEY: [u8; KEY_LEN] = [0xDC; KEY_LEN];
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

    fn bundle() -> crate::account::registration::RegistrationBundle {
        register_with(PASSWORD, Some(&PRF), &ACCOUNT, &randomness()).unwrap()
    }

    #[test]
    fn sblocco_password_restituisce_la_vk() {
        let b = bundle();
        let vk = unlock_with_password(
            PASSWORD,
            &SECRET_KEY,
            &b.password_envelope,
            &b.kdf_params_cbor,
            &ACCOUNT,
        )
        .unwrap();
        assert_eq!(vk.expose(), &VK);
    }

    #[test]
    fn sblocco_passkey_restituisce_la_vk() {
        let b = bundle();
        let vk = unlock_with_passkey(&PRF, b.passkey_envelope.as_ref().unwrap(), &ACCOUNT).unwrap();
        assert_eq!(vk.expose(), &VK);
    }

    #[test]
    fn derive_auth_verifier_coincide_col_bundle() {
        let b = bundle();
        let av = derive_auth_verifier(PASSWORD, &SECRET_KEY, &b.kdf_params_cbor, &ACCOUNT).unwrap();
        assert_eq!(*av, *b.auth_verifier);
    }

    #[test]
    fn password_errata_decrypt_failed() {
        let b = bundle();
        assert!(matches!(
            unlock_with_password(
                b"password sbagliata",
                &SECRET_KEY,
                &b.password_envelope,
                &b.kdf_params_cbor,
                &ACCOUNT,
            ),
            Err(CoreError::DecryptFailed)
        ));
    }

    #[test]
    fn secret_key_errata_decrypt_failed() {
        let b = bundle();
        assert!(matches!(
            unlock_with_password(
                PASSWORD,
                &[0xFF; SECRET_KEY_LEN],
                &b.password_envelope,
                &b.kdf_params_cbor,
                &ACCOUNT,
            ),
            Err(CoreError::DecryptFailed)
        ));
    }

    #[test]
    fn passkey_su_altro_account_decrypt_failed() {
        let b = bundle();
        let altro = [0x99; ACCOUNT_ID_LEN];
        assert!(matches!(
            unlock_with_passkey(&PRF, b.passkey_envelope.as_ref().unwrap(), &altro),
            Err(CoreError::DecryptFailed)
        ));
    }

    #[test]
    fn prf_di_lunghezza_errata_invalid_input() {
        let b = bundle();
        assert!(matches!(
            unlock_with_passkey(
                &[0x5A; PRF_OUTPUT_LEN - 1],
                b.passkey_envelope.as_ref().unwrap(),
                &ACCOUNT,
            ),
            Err(CoreError::InvalidInput)
        ));
    }

    #[test]
    fn biometria_round_trip_enable_poi_unlock() {
        let b = bundle();
        // Sblocco con password per ottenere un VaultKey, poi abilito la biometria.
        let vk = unlock_with_password(
            PASSWORD,
            &SECRET_KEY,
            &b.password_envelope,
            &b.kdf_params_cbor,
            &ACCOUNT,
        )
        .unwrap();
        let bio_env = enable_biometric_unlock(&vk, &DEVICE_KEY, &ACCOUNT).unwrap();
        // La busta biometria appena creata si riapre con la stessa device key.
        let unlocked = unlock_with_device_key(&DEVICE_KEY, &bio_env, &ACCOUNT).unwrap();
        assert_eq!(unlocked.expose(), &VK);
        // Device key sbagliata → DecryptFailed.
        assert!(matches!(
            unlock_with_device_key(&[0x00; KEY_LEN], &bio_env, &ACCOUNT),
            Err(CoreError::DecryptFailed)
        ));
    }

    #[test]
    fn abilita_passkey_su_vault_sbloccato() {
        let b = bundle();
        let vk = unlock_with_password(
            PASSWORD,
            &SECRET_KEY,
            &b.password_envelope,
            &b.kdf_params_cbor,
            &ACCOUNT,
        )
        .unwrap();
        // Una passkey diversa da quella di registrazione: la busta nuova si apre con essa.
        let altra_prf = [0x7B; PRF_OUTPUT_LEN];
        let pk_env = enable_passkey_unlock(&vk, &altra_prf, &ACCOUNT).unwrap();
        let unlocked = unlock_with_passkey(&altra_prf, &pk_env, &ACCOUNT).unwrap();
        assert_eq!(unlocked.expose(), &VK);
    }

    #[test]
    fn item_round_trip_via_vaultkey() {
        // La VK sbloccata cifra e ridecifra un item come handle opaco (doc 20 §5): i byte
        // della chiave non escono mai dalla superficie pubblica.
        let b = bundle();
        let vk = unlock_with_password(
            PASSWORD,
            &SECRET_KEY,
            &b.password_envelope,
            &b.kdf_params_cbor,
            &ACCOUNT,
        )
        .unwrap();
        let item_id = [0xEE; ID_LEN];
        let content = b"contenuto-item-di-prova";
        let (ct, wcek) = vk.encrypt_item(&VAULT_ID, &item_id, content).unwrap();
        let got = vk.decrypt_item(&VAULT_ID, &item_id, &ct, &wcek).unwrap();
        assert_eq!(&got[..], content);
        // Trapianto su un altro item_id → DecryptFailed (binding AAD, doc 16 §5).
        let altro_item = [0x00; ID_LEN];
        assert!(matches!(
            vk.decrypt_item(&VAULT_ID, &altro_item, &ct, &wcek),
            Err(CoreError::DecryptFailed)
        ));
    }

    #[test]
    fn lock_consuma_l_handle() {
        let b = bundle();
        let vk = unlock_with_passkey(&PRF, b.passkey_envelope.as_ref().unwrap(), &ACCOUNT).unwrap();
        vk.lock();
        // Dopo il lock l'handle non è più disponibile (garantito dal move di `lock`).
    }

    #[test]
    fn sync_delta_round_trip_via_vaultkey() {
        // Come item_round_trip_via_vaultkey, ma per il delta CRDT (doc 20 §8, ADR-0022): la VK
        // resta un handle opaco anche qui.
        let b = bundle();
        let vk = unlock_with_password(
            PASSWORD,
            &SECRET_KEY,
            &b.password_envelope,
            &b.kdf_params_cbor,
            &ACCOUNT,
        )
        .unwrap();
        let mut doc_a = crate::sync::SyncDoc::new_with_actor(&[0xAA]);
        doc_a.record_item_change(&[0x01; ID_LEN], 1, false).unwrap();
        let delta = vk
            .encode_sync_delta(&VAULT_ID, &doc_a.take_pending_changes())
            .unwrap();

        let mut doc_b = crate::sync::SyncDoc::new();
        let merged = vk
            .apply_sync_deltas(&mut doc_b, &VAULT_ID, std::slice::from_ref(&delta))
            .unwrap();
        assert_eq!(merged.items.len(), 1);
        assert_eq!(merged.items[0].item_version, 1);

        // Trapianto su un altro vault → DecryptFailed (binding AAD, doc 16 §8).
        let altro_vault = [0x00; ID_LEN];
        let mut doc_c = crate::sync::SyncDoc::new();
        assert!(matches!(
            vk.apply_sync_deltas(&mut doc_c, &altro_vault, &[delta]),
            Err(CoreError::DecryptFailed)
        ));
    }

    #[test]
    fn sign_manifest_via_vaultkey() {
        // Come item_round_trip_via_vaultkey, ma per ri-firmare il manifest dopo un login
        // (task 1.3/C2), non solo alla registrazione: un'unica chiamata, mai un byte di
        // SigningKey fuori dal core (SR-1).
        use crate::vault::manifest::{self, ItemRef, ManifestContent};

        let b = bundle();
        let vk = unlock_with_password(
            PASSWORD,
            &SECRET_KEY,
            &b.password_envelope,
            &b.kdf_params_cbor,
            &ACCOUNT,
        )
        .unwrap();
        let seed = [0x42; KEY_LEN];
        let wrapped = vk.wrap_signing_key(&seed, &VAULT_ID).unwrap();
        let content = ManifestContent {
            vault_id: VAULT_ID.into(),
            version: 2,
            items: vec![ItemRef {
                item_id: [0x01; ID_LEN].into(),
                item_version: 1,
            }],
            crdt_clock: vec![],
        };
        let signed = vk.sign_manifest(&wrapped, &VAULT_ID, &content).unwrap();
        let (_, expected_pub) = crate::crypto::signature::keypair_from_seed(&seed);
        let view =
            manifest::verify_manifest_with_pubkey(&expected_pub.to_bytes(), &signed, &VAULT_ID, 2)
                .unwrap();
        assert_eq!(view.version, 2);

        // Trapianto su un altro vault → DecryptFailed (binding AAD, doc 16 §6).
        let altro_vault = [0x00; ID_LEN];
        assert!(matches!(
            vk.sign_manifest(&wrapped, &altro_vault, &content),
            Err(CoreError::DecryptFailed)
        ));
    }
}
