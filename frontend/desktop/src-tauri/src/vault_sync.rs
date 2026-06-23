//! Helper di sincronizzazione e manifest condivisi dal CRUD voci (`items.rs`, task 1.3/C2,
//! ADR-0022): ogni scrittura aggiorna il documento CRDT locale, pubblica il delta e ri-firma
//! il manifest dalla directory risolta — collegando al client il lavoro del task 1.2, che
//! finora nessun client (CLI compresa) sfruttava per il CRUD reale.

use kunuk_crypto_core::sync::MergeResult;
use kunuk_crypto_core::vault::manifest::{self, ManifestContent};

use crate::api::Client;
use crate::session::UnlockedVault;
use crate::util::{b64, ce, expect_status, field_str, unb64};

/// Scarica tutti i delta non ancora visti (paginando finché `next_cursor` non è null — il
/// cursore è sempre opaco, mai ricostruito a mano, doc 21) e li applica al documento CRDT
/// locale. Ritorna la directory convergente (item_id → versione, esclusi gli eliminati).
pub fn pull_and_merge(http: &Client, unlocked: &mut UnlockedVault) -> Result<MergeResult, String> {
    loop {
        let mut path = "/v1/sync/changes?limit=200".to_string();
        if let Some(cursor) = &unlocked.sync_cursor {
            path.push_str("&cursor=");
            path.push_str(cursor);
        }
        let r = http.get(&path, Some(&unlocked.token))?;
        expect_status(&r, 200, "GET /sync/changes")?;
        let page = r.json()?;
        let raw_items = page
            .get("items")
            .and_then(|v| v.as_array())
            .ok_or("GET /sync/changes: items mancante")?;
        if !raw_items.is_empty() {
            let mut deltas = Vec::with_capacity(raw_items.len());
            for it in raw_items {
                deltas.push(unb64(field_str(it, "ciphertext")?)?);
            }
            unlocked
                .vk
                .apply_sync_deltas(&mut unlocked.sync_doc, &unlocked.vault_id, &deltas)
                .map_err(ce)?;
        }
        match page.get("next_cursor").and_then(|v| v.as_str()) {
            Some(c) => unlocked.sync_cursor = Some(c.to_string()),
            None => break,
        }
    }
    unlocked.sync_doc.snapshot().map_err(ce)
}

/// Scarica e verifica il manifest corrente (fail-closed, doc 16 §6): firma valida, vault_id
/// atteso, versione non regredita rispetto a quanto già visto in questa sessione. Aggiorna
/// `manifest_version`. Non gestisce un eventuale cambio di `wrapped_signing_key` (il seme
/// della chiave di firma è immutabile per vault, non ruota mai in questo MVP).
pub fn fetch_and_verify_manifest(
    http: &Client,
    unlocked: &mut UnlockedVault,
) -> Result<Vec<manifest::ItemRef>, String> {
    let r = http.get("/v1/vault", Some(&unlocked.token))?;
    expect_status(&r, 200, "GET /vault")?;
    let vault = r.json()?;
    let manifest_pubkey: [u8; 32] = unb64(field_str(&vault, "manifest_pubkey")?)?
        .try_into()
        .map_err(|_| "manifest_pubkey di lunghezza errata".to_string())?;
    let mut signed = unb64(field_str(&vault, "manifest")?)?;
    signed.extend_from_slice(&unb64(field_str(&vault, "signature")?)?);
    let view = manifest::verify_manifest_with_pubkey(
        &manifest_pubkey,
        &signed,
        &unlocked.vault_id,
        unlocked.manifest_version,
    )
    .map_err(ce)?;
    unlocked.manifest_version = view.version;
    Ok(view.items)
}

/// Firma e pubblica un nuovo manifest a partire dalla directory CRDT risolta (doc 16 §6,
/// ADR-0022): CAS lato server (la versione deve crescere). Aggiorna `manifest_version` solo
/// se la pubblicazione riesce.
pub fn resign_manifest(
    http: &Client,
    unlocked: &mut UnlockedVault,
    merged: &MergeResult,
) -> Result<(), String> {
    let new_version = unlocked.manifest_version + 1;
    let content = ManifestContent {
        vault_id: unlocked.vault_id.into(),
        version: new_version,
        items: merged.items.clone(),
        crdt_clock: merged.crdt_clock.clone(),
    };
    let signed = unlocked
        .vk
        .sign_manifest(&unlocked.wrapped_signing_key, &unlocked.vault_id, &content)
        .map_err(ce)?;
    let (body, signature) = manifest::split_signed_manifest(&signed).map_err(ce)?;
    let r = http.put_json(
        "/v1/vault/manifest",
        Some(&unlocked.token),
        &serde_json::json!({
            "manifest": b64(body),
            "signature": b64(signature),
            "version": new_version,
        }),
    )?;
    expect_status(&r, 200, "PUT /vault/manifest")?;
    unlocked.manifest_version = new_version;
    Ok(())
}
