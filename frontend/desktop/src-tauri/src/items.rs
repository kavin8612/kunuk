//! Comandi Tauri del CRUD voci (task 1.3/C2). Ogni scrittura aggiorna anche il documento
//! CRDT locale e ri-firma il manifest (`vault_sync.rs`, ADR-0022): il manifest resta lo
//! snapshot firmato e veritiero della directory, non un residuo della registrazione.
//!
//! Il contenuto attraversa il confine Tauri come [`ItemContentDto`] (JSON, camelCase: è un
//! confine interno app↔webview, non l'API REST di doc 12, che resta snake_case) — mai come
//! tipo di `ed25519-dalek`/minicbor grezzo: la conversione con `kunuk_crypto_core::vault::item`
//! vive solo qui.

use serde::{Deserialize, Serialize};
use tauri::State;

use kunuk_crypto_core::vault::item::{self, CustomField, ItemContent, ItemData};

use crate::config::AppConfig;
use crate::session::Session;
use crate::util::{
    ce, client, expect_status, field_str, rand_id, uuid_from_string, uuid_to_string,
};
use crate::vault_sync::{fetch_and_verify_manifest, pull_and_merge, resign_manifest};

#[derive(Serialize, Deserialize, Clone)]
pub struct CustomFieldDto {
    pub label: String,
    pub value: String,
    pub hidden: bool,
}

/// Mirror JSON di [`ItemData`] (doc 17 §2, ADR-0021). Tag `type` discriminante: il frontend
/// React lo popola in base al modulo di editing scelto dall'utente.
#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ItemDataDto {
    Login {
        username: String,
        password: String,
        uris: Vec<String>,
        notes: String,
    },
    SecureNote {
        text: String,
    },
    Card {
        cardholder_name: String,
        number: String,
        exp_month: u8,
        exp_year: u16,
        security_code: String,
    },
    Identity {
        full_name: String,
        email: String,
        phone: String,
    },
    Folder {},
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ItemContentDto {
    pub title: String,
    /// UUID testuale della voce-cartella di appartenenza, `null` = radice (ADR-0021).
    pub folder: Option<String>,
    pub favorite: bool,
    pub custom_fields: Vec<CustomFieldDto>,
    pub data: ItemDataDto,
}

fn to_core(dto: ItemContentDto) -> Result<ItemContent, String> {
    let folder = match dto.folder {
        Some(s) => Some(uuid_from_string(&s)?.into()),
        None => None,
    };
    let data = match dto.data {
        ItemDataDto::Login {
            username,
            password,
            uris,
            notes,
        } => ItemData::Login {
            username,
            password,
            uris,
            notes,
        },
        ItemDataDto::SecureNote { text } => ItemData::SecureNote { text },
        ItemDataDto::Card {
            cardholder_name,
            number,
            exp_month,
            exp_year,
            security_code,
        } => ItemData::Card {
            cardholder_name,
            number,
            exp_month,
            exp_year,
            security_code,
        },
        ItemDataDto::Identity {
            full_name,
            email,
            phone,
        } => ItemData::Identity {
            full_name,
            email,
            phone,
        },
        ItemDataDto::Folder {} => ItemData::Folder {},
    };
    Ok(ItemContent {
        title: dto.title,
        folder,
        favorite: dto.favorite,
        custom_fields: dto
            .custom_fields
            .into_iter()
            .map(|c| CustomField {
                label: c.label,
                value: c.value,
                hidden: c.hidden,
            })
            .collect(),
        data,
    })
}

fn from_core(content: ItemContent) -> ItemContentDto {
    let data = match content.data {
        ItemData::Login {
            username,
            password,
            uris,
            notes,
        } => ItemDataDto::Login {
            username,
            password,
            uris,
            notes,
        },
        ItemData::SecureNote { text } => ItemDataDto::SecureNote { text },
        ItemData::Card {
            cardholder_name,
            number,
            exp_month,
            exp_year,
            security_code,
        } => ItemDataDto::Card {
            cardholder_name,
            number,
            exp_month,
            exp_year,
            security_code,
        },
        ItemData::Identity {
            full_name,
            email,
            phone,
        } => ItemDataDto::Identity {
            full_name,
            email,
            phone,
        },
        ItemData::Folder {} => ItemDataDto::Folder {},
    };
    ItemContentDto {
        title: content.title,
        folder: content.folder.map(|f| uuid_to_string(&f)),
        favorite: content.favorite,
        custom_fields: content
            .custom_fields
            .into_iter()
            .map(|c| CustomFieldDto {
                label: c.label,
                value: c.value,
                hidden: c.hidden,
            })
            .collect(),
        data,
    }
}

#[derive(Serialize)]
pub struct ItemSummary {
    pub id: String,
    pub content: ItemContentDto,
}

/// Elenca le voci del vault. Verifica fail-closed (doc 16 §6): il manifest deve avere firma
/// valida e versione non regredita; ogni voce mostrata deve comparire nella directory CRDT
/// risolta (`pull_and_merge`) — una voce presente lato server ma assente dalla directory
/// (changeset mai pubblicato, o tampering) non viene mostrata, senza far fallire l'intera
/// lista (fail-closed sulla singola voce, non un oracolo).
#[tauri::command]
pub fn list_items(
    config: State<AppConfig>,
    session: State<Session>,
) -> Result<Vec<ItemSummary>, String> {
    session.touch();
    let http = client(&config)?;
    let mut guard = session
        .unlocked
        .lock()
        .map_err(|_| "stato sessione corrotto")?;
    let unlocked = guard.as_mut().ok_or("vault bloccato")?;

    let merged = pull_and_merge(&http, unlocked)?;
    fetch_and_verify_manifest(&http, unlocked)?;
    let known_ids: std::collections::HashSet<String> = merged
        .items
        .iter()
        .map(|r| uuid_to_string(&r.item_id))
        .collect();

    let r = http.get("/v1/items?limit=200", Some(&unlocked.token))?;
    expect_status(&r, 200, "GET /items")?;
    let page = r.json()?;
    let raw_items = page
        .get("items")
        .and_then(|v| v.as_array())
        .ok_or("GET /items: items mancante")?;

    let mut out = Vec::new();
    for raw in raw_items {
        let id = field_str(raw, "id")?.to_string();
        if !known_ids.contains(&id) {
            eprintln!("kunuk-desktop: item {id} assente dalla directory CRDT, escluso");
            continue;
        }
        let item_id = uuid_from_string(&id)?;
        let ciphertext = crate::util::unb64(field_str(raw, "ciphertext")?)?;
        let wrapped_cek = crate::util::unb64(field_str(raw, "wrapped_cek")?)?;
        let plaintext = unlocked
            .vk
            .decrypt_item(&unlocked.vault_id, &item_id, &ciphertext, &wrapped_cek)
            .map_err(ce)?;
        let content = item::decode_content(&plaintext).map_err(ce)?;
        out.push(ItemSummary {
            id,
            content: from_core(content),
        });
    }
    Ok(out)
}

/// Crea una voce: cifra il contenuto, la carica, registra la modifica nel documento CRDT
/// locale, pubblica il delta e ri-firma il manifest (doc 16 §5-6, ADR-0022).
#[tauri::command]
pub fn create_item(
    config: State<AppConfig>,
    session: State<Session>,
    content: ItemContentDto,
) -> Result<ItemSummary, String> {
    session.touch();
    let http = client(&config)?;
    let mut guard = session
        .unlocked
        .lock()
        .map_err(|_| "stato sessione corrotto")?;
    let unlocked = guard.as_mut().ok_or("vault bloccato")?;

    // Pull prima di scrivere (anche se l'esito non serve qui): senza, un `sync_doc` mai
    // idratato con la storia pregressa (es. prima scrittura della sessione) produrrebbe uno
    // snapshot che dimentica le voci create in sessioni precedenti, perdendole dal prossimo
    // manifest firmato.
    pull_and_merge(&http, unlocked)?;

    let core_content = to_core(content.clone())?;
    let item_id = rand_id()?;
    let content_cbor = item::encode_content(&core_content).map_err(ce)?;
    let (ciphertext, wrapped_cek) = unlocked
        .vk
        .encrypt_item(&unlocked.vault_id, &item_id, &content_cbor)
        .map_err(ce)?;

    let id_str = uuid_to_string(&item_id);
    let r = http.post_json(
        "/v1/items",
        Some(&unlocked.token),
        &serde_json::json!({
            "id": id_str,
            "ciphertext": crate::util::b64(&ciphertext),
            "wrapped_cek": crate::util::b64(&wrapped_cek),
        }),
    )?;
    expect_status(&r, 201, "POST /items")?;

    unlocked
        .sync_doc
        .record_item_change(&item_id, 1, false)
        .map_err(ce)?;
    let delta = unlocked
        .vk
        .encode_sync_delta(
            &unlocked.vault_id,
            &unlocked.sync_doc.take_pending_changes(),
        )
        .map_err(ce)?;
    let r = http.post_json(
        "/v1/sync/changes",
        Some(&unlocked.token),
        &serde_json::json!({ "changes": [{ "ciphertext": crate::util::b64(&delta), "clock": "" }] }),
    )?;
    expect_status(&r, 202, "POST /sync/changes")?;

    let merged = unlocked.sync_doc.snapshot().map_err(ce)?;
    resign_manifest(&http, unlocked, &merged)?;

    Ok(ItemSummary {
        id: id_str,
        content,
    })
}

/// Aggiorna una voce esistente: nuova CEK/nonce (il core ne genera sempre di freschi),
/// versione CRDT incrementata rispetto a quella convergente più recente.
#[tauri::command]
pub fn update_item(
    config: State<AppConfig>,
    session: State<Session>,
    id: String,
    content: ItemContentDto,
) -> Result<(), String> {
    session.touch();
    let http = client(&config)?;
    let mut guard = session
        .unlocked
        .lock()
        .map_err(|_| "stato sessione corrotto")?;
    let unlocked = guard.as_mut().ok_or("vault bloccato")?;

    let item_id = uuid_from_string(&id)?;
    let merged = pull_and_merge(&http, unlocked)?;
    let current_version = merged
        .items
        .iter()
        .find(|r| r.item_id[..] == item_id[..])
        .map(|r| r.item_version)
        .unwrap_or(0);

    let core_content = to_core(content)?;
    let content_cbor = item::encode_content(&core_content).map_err(ce)?;
    let (ciphertext, wrapped_cek) = unlocked
        .vk
        .encrypt_item(&unlocked.vault_id, &item_id, &content_cbor)
        .map_err(ce)?;
    let r = http.put_json(
        &format!("/v1/items/{id}"),
        Some(&unlocked.token),
        &serde_json::json!({
            "ciphertext": crate::util::b64(&ciphertext),
            "wrapped_cek": crate::util::b64(&wrapped_cek),
        }),
    )?;
    expect_status(&r, 200, "PUT /items/{id}")?;

    unlocked
        .sync_doc
        .record_item_change(&item_id, current_version + 1, false)
        .map_err(ce)?;
    let delta = unlocked
        .vk
        .encode_sync_delta(
            &unlocked.vault_id,
            &unlocked.sync_doc.take_pending_changes(),
        )
        .map_err(ce)?;
    let r = http.post_json(
        "/v1/sync/changes",
        Some(&unlocked.token),
        &serde_json::json!({ "changes": [{ "ciphertext": crate::util::b64(&delta), "clock": "" }] }),
    )?;
    expect_status(&r, 202, "POST /sync/changes")?;

    let merged = unlocked.sync_doc.snapshot().map_err(ce)?;
    resign_manifest(&http, unlocked, &merged)
}

/// Elimina (tombstone) una voce: il delta CRDT registra l'eliminazione, che vince a parità di
/// versione su un edit concorrente (doc 16 §8 "Delta CRDT").
#[tauri::command]
pub fn delete_item(
    config: State<AppConfig>,
    session: State<Session>,
    id: String,
) -> Result<(), String> {
    session.touch();
    let http = client(&config)?;
    let mut guard = session
        .unlocked
        .lock()
        .map_err(|_| "stato sessione corrotto")?;
    let unlocked = guard.as_mut().ok_or("vault bloccato")?;

    let item_id = uuid_from_string(&id)?;
    let merged = pull_and_merge(&http, unlocked)?;
    let current_version = merged
        .items
        .iter()
        .find(|r| r.item_id[..] == item_id[..])
        .map(|r| r.item_version)
        .unwrap_or(0);

    let r = http.delete(&format!("/v1/items/{id}"), Some(&unlocked.token))?;
    expect_status(&r, 204, "DELETE /items/{id}")?;

    unlocked
        .sync_doc
        .record_item_change(&item_id, current_version + 1, true)
        .map_err(ce)?;
    let delta = unlocked
        .vk
        .encode_sync_delta(
            &unlocked.vault_id,
            &unlocked.sync_doc.take_pending_changes(),
        )
        .map_err(ce)?;
    let r = http.post_json(
        "/v1/sync/changes",
        Some(&unlocked.token),
        &serde_json::json!({ "changes": [{ "ciphertext": crate::util::b64(&delta), "clock": "" }] }),
    )?;
    expect_status(&r, 202, "POST /sync/changes")?;

    let merged = unlocked.sync_doc.snapshot().map_err(ce)?;
    resign_manifest(&http, unlocked, &merged)
}
