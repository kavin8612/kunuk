package vaultsync

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"kunuk.dev/core/internal/httpx"
)

// Tutte le query girano dentro una WithAccountTx: la RLS (policy p_sync) limita le righe ai
// sync_change del vault dell'account della sessione (SR-32).

const insertChangeSQL = `INSERT INTO sync_change (vault_id, ciphertext, clock)
    VALUES ((SELECT id FROM vault WHERE account_id = current_account_id()), $1, $2)`

func insertChange(ctx context.Context, tx pgx.Tx, ciphertext []byte, clock string) error {
	if _, err := tx.Exec(ctx, insertChangeSQL, ciphertext, clock); err != nil {
		return fmt.Errorf("insert sync_change: %w", err)
	}
	return nil
}

// listChanges pagina i delta con id > since (cursore monotono, doc 21): non serve un cursore a
// tupla come per gli item, l'id bigint IDENTITY del delta è già totalmente ordinato. L'id è
// esposto come stringa (non un numero JSON): un bigint può eccedere la precisione sicura di un
// float64 lato client.
const listChangesSQL = `SELECT id, device_id, ciphertext, clock, created_at FROM sync_change
    WHERE id > $1 ORDER BY id LIMIT $2`

func listChanges(ctx context.Context, tx pgx.Tx, since int64, limit int) ([]SyncChange, error) {
	rows, err := tx.Query(ctx, listChangesSQL, since, limit)
	if err != nil {
		return nil, fmt.Errorf("select sync_change: %w", err)
	}
	defer rows.Close()
	var out []SyncChange
	for rows.Next() {
		var id int64
		var deviceID *string
		var ciphertext []byte
		var clock string
		var createdAt time.Time
		if err := rows.Scan(&id, &deviceID, &ciphertext, &clock, &createdAt); err != nil {
			return nil, fmt.Errorf("scan sync_change: %w", err)
		}
		out = append(out, SyncChange{
			ID: strconv.FormatInt(id, 10), DeviceID: deviceID, Ciphertext: httpx.Bytes(ciphertext),
			Clock: clock, CreatedAt: createdAt,
		})
	}
	return out, rows.Err()
}
