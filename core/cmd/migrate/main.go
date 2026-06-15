// Comando one-shot: applica le migrazioni del DB come ruolo kunuk_migrations e termina.
//
// È il servizio `migrate` del Compose (stile Home Assistant: a ogni `up` applica le
// migrazioni pendenti, idempotente, prima dell'API) e serve per esecuzioni manuali/ops.
// A 0.9 il backend richiamerà lo stesso `db.Apply` all'avvio.
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	// Registra il driver database/sql "pgx".
	_ "github.com/jackc/pgx/v5/stdlib"

	"kunuk.dev/core/db"
)

// readyTimeout limita l'attesa che il DB sia raggiungibile e le migrazioni applicate.
const readyTimeout = 60 * time.Second

func main() {
	if err := run(); err != nil {
		log.Fatalf("migrate: %v", err)
	}
	log.Print("migrate: migrazioni applicate.")
}

func run() error {
	dsn, err := dsnFromEnv()
	if err != nil {
		return err
	}
	pool, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("apertura connessione: %w", err)
	}
	defer func() {
		if cerr := pool.Close(); cerr != nil {
			log.Printf("migrate: chiusura connessione: %v", cerr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), readyTimeout)
	defer cancel()
	if err := waitReady(ctx, pool); err != nil {
		return err
	}
	return db.Apply(ctx, pool)
}

// dsnFromEnv costruisce la DSN dal ruolo migrazioni. Variabili assenti → errore esplicito,
// non un fallimento oscuro a runtime.
func dsnFromEnv() (string, error) {
	required := []string{
		"KUNUK_DB_HOST", "KUNUK_DB_PORT", "KUNUK_DB_NAME",
		"KUNUK_DB_MIGRATIONS_USER", "KUNUK_DB_MIGRATIONS_PASSWORD",
	}
	v := make(map[string]string, len(required))
	for _, k := range required {
		val := os.Getenv(k)
		if val == "" {
			return "", fmt.Errorf("variabile d'ambiente mancante: %s", k)
		}
		v[k] = val
	}
	sslmode := os.Getenv("KUNUK_DB_SSLMODE")
	if sslmode == "" {
		sslmode = "disable"
	}
	return fmt.Sprintf(
		"host=%s port=%s dbname=%s user=%s password=%s sslmode=%s",
		v["KUNUK_DB_HOST"], v["KUNUK_DB_PORT"], v["KUNUK_DB_NAME"],
		v["KUNUK_DB_MIGRATIONS_USER"], v["KUNUK_DB_MIGRATIONS_PASSWORD"], sslmode,
	), nil
}

// waitReady attende che il DB risponda al ping, ritentando finché il contesto non scade
// (il servizio dipende già dall'healthcheck di Postgres, ma un retry rende l'avvio robusto).
func waitReady(ctx context.Context, pool *sql.DB) error {
	for {
		if err := pool.PingContext(ctx); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("database non raggiungibile entro %s: %w", readyTimeout, ctx.Err())
		case <-time.After(time.Second):
		}
	}
}
