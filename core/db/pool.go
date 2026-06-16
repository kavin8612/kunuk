package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// NewPool apre il pool di connessioni del ruolo applicativo (runtime, soggetto a RLS) e
// verifica la raggiungibilità con un ping. La DSN va costruita dal pacchetto config.
func NewPool(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("creazione pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping del pool: %w", err)
	}
	return pool, nil
}
