package vaultsync

import (
	"context"
	"errors"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"kunuk.dev/core/db"
)

// ErrInvalidCursor indica un cursore non decodificabile o negativo.
var ErrInvalidCursor = errors.New("cursore non valido")

// Service orchestra il trasporto dei delta, ogni operazione sotto lo scope RLS dell'account.
type Service struct {
	pool *pgxpool.Pool
}

// NewService costruisce il servizio sul pool del ruolo applicativo.
func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

func (s *Service) tx(ctx context.Context, accountID string, fn func(pgx.Tx) error) error {
	return db.WithAccountTx(ctx, s.pool, accountID, fn)
}

// ListChanges restituisce i delta successivi al cursore `since` (escluso), in ordine.
func (s *Service) ListChanges(ctx context.Context, accountID string, since int64, limit int) ([]SyncChange, error) {
	var out []SyncChange
	err := s.tx(ctx, accountID, func(t pgx.Tx) error {
		var e error
		out, e = listChanges(ctx, t, since, limit)
		return e
	})
	return out, err
}

// PushChanges accoda i delta cifrati ricevuti dal client. device_id resta NULL: il modulo di
// registrazione dispositivi è un TODO separato (rinviato dal task 0.9), non in scope qui.
func (s *Service) PushChanges(ctx context.Context, accountID string, changes []SyncChangeInput) error {
	return s.tx(ctx, accountID, func(t pgx.Tx) error {
		for _, c := range changes {
			if e := insertChange(ctx, t, c.Ciphertext, c.Clock); e != nil {
				return e
			}
		}
		return nil
	})
}

// parseCursor decodifica il token opaco "cursor" (decimale) in un cursore. Vuoto => 0 (prima
// pagina, dall'inizio della storia). Malformato o negativo => ErrInvalidCursor.
func parseCursor(token string) (int64, error) {
	if token == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(token, 10, 64)
	if err != nil || n < 0 {
		return 0, ErrInvalidCursor
	}
	return n, nil
}

// encodeCursor produce il token (decimale, già stringa) dell'ultimo delta visto (poi reso
// opaco dall'handler).
func encodeCursor(c SyncChange) string {
	return c.ID
}
