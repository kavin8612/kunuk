// Package db incorpora le migrazioni dello schema e le applica con goose.
//
// Le migrazioni (`migrations/*.sql`) sono incluse nel binario via go:embed: lo stesso
// codice è usato dai test (Postgres effimero), dal comando one-shot `migrate` (servizio del
// Compose, stile Home Assistant: a ogni avvio applica il nuovo, idempotente e tracciato) e,
// dal task 0.9, dall'avvio del backend. Va eseguito con una connessione del ruolo
// kunuk_migrations (DDL); il ruolo runtime kunuk_app non ha privilegi di migrazione (SR-32).
package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"

	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// migrationsDir è il percorso delle migrazioni dentro l'FS incorporato.
const migrationsDir = "migrations"

// Apply applica in avanti tutte le migrazioni pendenti, in modo idempotente e tracciato
// (tabella goose_db_version). `db` deve essere aperto come ruolo kunuk_migrations.
func Apply(ctx context.Context, db *sql.DB) error {
	goose.SetBaseFS(migrationsFS)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("goose: dialetto postgres: %w", err)
	}
	if err := goose.UpContext(ctx, db, migrationsDir); err != nil {
		return fmt.Errorf("goose: applicazione migrazioni: %w", err)
	}
	return nil
}
