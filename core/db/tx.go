package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// setAccountSQL imposta l'account della sessione, transaction-local e parametrizzato
// (`set_config(..., true)` = SET LOCAL; niente concatenazione di stringhe, SR-30).
const setAccountSQL = `SELECT set_config('app.account_id', $1, true)`

// WithAccountTx esegue fn dentro una transazione in cui `app.account_id` è impostato:
// le policy RLS filtrano le righe per quell'account dentro il DB (SR-32). I repo ricevono
// la `pgx.Tx` e non aprono mai connessioni proprie, così ogni query dell'unità di lavoro
// gira sotto lo stesso scope. È il pattern provato in db/rls_test.go, promosso a produzione.
func WithAccountTx(ctx context.Context, pool *pgxpool.Pool, accountID string, fn func(pgx.Tx) error) (err error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("apertura transazione: %w", err)
	}
	defer func() {
		// Rollback solo se l'unità di lavoro è fallita; dopo un Commit riuscito è un no-op
		// (ErrTxClosed), che ignoriamo. Un rollback fallito si aggrega all'errore originale.
		if err != nil {
			if rbErr := tx.Rollback(ctx); rbErr != nil && !errors.Is(rbErr, pgx.ErrTxClosed) {
				err = errors.Join(err, fmt.Errorf("rollback: %w", rbErr))
			}
		}
	}()

	if _, err = tx.Exec(ctx, setAccountSQL, accountID); err != nil {
		return fmt.Errorf("set app.account_id: %w", err)
	}
	if err = fn(tx); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}
