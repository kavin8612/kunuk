package vaultstorage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"kunuk.dev/core/internal/httpx"
)

// Tutte le query girano dentro una WithAccountTx: la RLS limita le righe all'account della
// sessione (SR-32). Un id di un altro account non è visibile → 0 righe → 404 (anti-IDOR,
// SR-30), senza distinguere "non esiste" da "non tuo".

// ── Buste (envelope) ──────────────────────────────────────────────────────────
const listEnvelopesSQL = `SELECT type, wrapped_vk, params FROM envelope WHERE account_id = current_account_id() ORDER BY type`

func listEnvelopes(ctx context.Context, tx pgx.Tx) ([]Envelope, error) {
	rows, err := tx.Query(ctx, listEnvelopesSQL)
	if err != nil {
		return nil, fmt.Errorf("select envelopes: %w", err)
	}
	defer rows.Close()
	var out []Envelope
	for rows.Next() {
		var typ string
		var wrapped, params []byte
		if err := rows.Scan(&typ, &wrapped, &params); err != nil {
			return nil, fmt.Errorf("scan envelope: %w", err)
		}
		out = append(out, Envelope{Type: typ, WrappedVK: httpx.Bytes(wrapped), Params: json.RawMessage(params)})
	}
	return out, rows.Err()
}

const updateEnvelopeSQL = `UPDATE envelope SET wrapped_vk = $2, params = $3::jsonb, updated_at = now()
    WHERE account_id = current_account_id() AND type = $1`

func updateEnvelope(ctx context.Context, tx pgx.Tx, typ string, wrapped []byte, params *string) (int64, error) {
	tag, err := tx.Exec(ctx, updateEnvelopeSQL, typ, wrapped, params)
	if err != nil {
		return 0, fmt.Errorf("update envelope: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ── Vault / manifest ──────────────────────────────────────────────────────────
const getVaultSQL = `SELECT id, manifest, manifest_pubkey, signature, version, wrapped_signing_key FROM vault WHERE account_id = current_account_id()`

func getVault(ctx context.Context, tx pgx.Tx) (VaultManifest, error) {
	var vid string
	var m, pk, sig, wsk []byte
	var ver int
	if err := tx.QueryRow(ctx, getVaultSQL).Scan(&vid, &m, &pk, &sig, &ver, &wsk); err != nil {
		return VaultManifest{}, fmt.Errorf("select vault: %w", err)
	}
	return VaultManifest{
		VaultID: vid, Manifest: httpx.Bytes(m), ManifestPubkey: httpx.Bytes(pk), Signature: httpx.Bytes(sig),
		Version: ver, WrappedSigningKey: httpx.Bytes(wsk),
	}, nil
}

// updateManifest applica il nuovo manifest solo se la versione è strettamente maggiore
// (anti-rollback, CAS). 0 righe = conflitto di versione (il chiamante risponde 409).
const updateManifestSQL = `UPDATE vault SET manifest = $1, signature = $2, version = $3, updated_at = now()
    WHERE account_id = current_account_id() AND version < $3`

func updateManifest(ctx context.Context, tx pgx.Tx, manifest, sig []byte, version int) (int64, error) {
	tag, err := tx.Exec(ctx, updateManifestSQL, manifest, sig, version)
	if err != nil {
		return 0, fmt.Errorf("update manifest: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ── Item ──────────────────────────────────────────────────────────────────────
// L'id può arrivare dal client (UUID legato nell'AAD del ciphertext, doc 16 §5) o, se assente,
// lo genera il DB. La RLS (p_item) verifica comunque che il vault_id appartenga all'account.
// La chiave primaria è composita (vault_id, id) (migrazione 00003): l'unicità dell'id è
// per-vault, quindi un 23505 qui significa "id già usato in QUESTO vault" — niente oracolo
// cross-tenant (SR-26).
const insertItemSQL = `INSERT INTO item (vault_id, ciphertext, wrapped_cek)
    VALUES ((SELECT id FROM vault WHERE account_id = current_account_id()), $1, $2)
    RETURNING id, deleted, created_at, updated_at`
const insertItemWithIDSQL = `INSERT INTO item (id, vault_id, ciphertext, wrapped_cek)
    VALUES ($1::uuid, (SELECT id FROM vault WHERE account_id = current_account_id()), $2, $3)
    RETURNING id, deleted, created_at, updated_at`

func insertItem(ctx context.Context, tx pgx.Tx, id string, ciphertext, cek []byte) (Item, error) {
	var row pgx.Row
	if id == "" {
		row = tx.QueryRow(ctx, insertItemSQL, ciphertext, cek)
	} else {
		row = tx.QueryRow(ctx, insertItemWithIDSQL, id, ciphertext, cek)
	}
	var gotID string
	var deleted bool
	var created, updated time.Time
	if err := row.Scan(&gotID, &deleted, &created, &updated); err != nil {
		// Id fornito dal client già in uso NEL VAULT → conflitto (409), non un 500 opaco.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return Item{}, ErrItemExists
		}
		return Item{}, fmt.Errorf("insert item: %w", err)
	}
	return Item{
		ID: gotID, Ciphertext: httpx.Bytes(ciphertext), WrappedCEK: httpx.Bytes(cek),
		Deleted: deleted, CreatedAt: created, UpdatedAt: updated,
	}, nil
}

const getItemSQL = `SELECT id, ciphertext, wrapped_cek, deleted, created_at, updated_at FROM item WHERE id = $1`

func getItem(ctx context.Context, tx pgx.Tx, id string) (Item, error) {
	return scanItem(tx.QueryRow(ctx, getItemSQL, id))
}

const updateItemSQL = `UPDATE item SET ciphertext = $2, wrapped_cek = $3, updated_at = now() WHERE id = $1`

func updateItem(ctx context.Context, tx pgx.Tx, id string, ciphertext, cek []byte) (int64, error) {
	tag, err := tx.Exec(ctx, updateItemSQL, id, ciphertext, cek)
	if err != nil {
		return 0, fmt.Errorf("update item: %w", err)
	}
	return tag.RowsAffected(), nil
}

const deleteItemSQL = `UPDATE item SET deleted = true, updated_at = now() WHERE id = $1`

func deleteItem(ctx context.Context, tx pgx.Tx, id string) (int64, error) {
	tag, err := tx.Exec(ctx, deleteItemSQL, id)
	if err != nil {
		return 0, fmt.Errorf("delete item: %w", err)
	}
	return tag.RowsAffected(), nil
}

// cursor è la posizione di paginazione: (updated_at, id) dell'ultimo item visto.
type cursor struct {
	updatedAt time.Time
	id        string
}

const listItemsSQL = `SELECT id, ciphertext, wrapped_cek, deleted, created_at, updated_at FROM item
    ORDER BY updated_at, id LIMIT $1`
const listItemsCursorSQL = `SELECT id, ciphertext, wrapped_cek, deleted, created_at, updated_at FROM item
    WHERE (updated_at, id) > ($2, $3::uuid) ORDER BY updated_at, id LIMIT $1`

func listItems(ctx context.Context, tx pgx.Tx, cur *cursor, limit int) ([]Item, error) {
	var rows pgx.Rows
	var err error
	if cur == nil {
		rows, err = tx.Query(ctx, listItemsSQL, limit)
	} else {
		rows, err = tx.Query(ctx, listItemsCursorSQL, limit, cur.updatedAt, cur.id)
	}
	if err != nil {
		return nil, fmt.Errorf("select items: %w", err)
	}
	defer rows.Close()
	var out []Item
	for rows.Next() {
		it, err := scanItem(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// rowScanner è il minimo comune di pgx.Row / pgx.Rows per lo scan di un item.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanItem(row rowScanner) (Item, error) {
	var id string
	var ciphertext, cek []byte
	var deleted bool
	var created, updated time.Time
	if err := row.Scan(&id, &ciphertext, &cek, &deleted, &created, &updated); err != nil {
		return Item{}, fmt.Errorf("scan item: %w", err)
	}
	return Item{
		ID: id, Ciphertext: httpx.Bytes(ciphertext), WrappedCEK: httpx.Bytes(cek),
		Deleted: deleted, CreatedAt: created, UpdatedAt: updated,
	}, nil
}
