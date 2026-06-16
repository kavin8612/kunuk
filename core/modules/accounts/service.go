package accounts

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"kunuk.dev/core/db"
)

// Service orchestra le operazioni sull'account, ciascuna in una transazione con lo scope RLS
// dell'account corrente.
type Service struct {
	pool *pgxpool.Pool
}

// NewService costruisce il servizio sul pool del ruolo applicativo (kunuk_app).
func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

// Get restituisce l'account della sessione.
func (s *Service) Get(ctx context.Context, accountID string) (Account, error) {
	var a Account
	err := db.WithAccountTx(ctx, s.pool, accountID, func(tx pgx.Tx) error {
		var e error
		a, e = getAccount(ctx, tx)
		return e
	})
	return a, err
}

// Delete cancella l'account della sessione. deleted=false se non c'è nulla da cancellare.
func (s *Service) Delete(ctx context.Context, accountID string) (bool, error) {
	var deleted bool
	err := db.WithAccountTx(ctx, s.pool, accountID, func(tx pgx.Tx) error {
		n, e := deleteAccount(ctx, tx)
		deleted = n > 0
		return e
	})
	return deleted, err
}
