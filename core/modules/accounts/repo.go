// Package accounts gestisce il ciclo di vita dell'account autenticato (doc 12: GET/DELETE
// /account). Tutte le query girano dentro una WithAccountTx (RLS per-account, SR-32): la
// clausola `id = current_account_id()` è ridondante con la RLS ma rende esplicito lo scoping.
package accounts

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// Account è la vista dell'account corrente.
type Account struct {
	ID        string
	Email     string
	KdfParams json.RawMessage
	Status    string
}

const getSQL = `SELECT id, email, kdf_params, status FROM account WHERE id = current_account_id()`

func getAccount(ctx context.Context, tx pgx.Tx) (Account, error) {
	var a Account
	if err := tx.QueryRow(ctx, getSQL).Scan(&a.ID, &a.Email, &a.KdfParams, &a.Status); err != nil {
		return Account{}, fmt.Errorf("select account: %w", err)
	}
	return a, nil
}

const deleteSQL = `DELETE FROM account WHERE id = current_account_id()`

// deleteAccount cancella l'account corrente; la FK ON DELETE CASCADE rimuove vault, buste,
// item e sessioni. Ritorna il numero di righe toccate (0 = nessun account in sessione).
func deleteAccount(ctx context.Context, tx pgx.Tx) (int64, error) {
	tag, err := tx.Exec(ctx, deleteSQL)
	if err != nil {
		return 0, fmt.Errorf("delete account: %w", err)
	}
	return tag.RowsAffected(), nil
}
