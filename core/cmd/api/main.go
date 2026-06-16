// Comando api: entrypoint del backend Kunuk (task 0.9). Carica la configurazione, apre il
// pool del ruolo applicativo (kunuk_app, soggetto a RLS), costruisce il router e avvia il
// server con arresto controllato. Le migrazioni le applica il servizio one-shot `migrate`
// (non l'API). Tratta solo ciphertext/verificatori: nessuna crittografia qui (vive nel
// crypto-core lato client).
package main

import (
	"context"
	"log"

	"kunuk.dev/core/db"
	"kunuk.dev/core/internal/config"
	"kunuk.dev/core/internal/httpserver"
	"kunuk.dev/core/internal/session"
	"kunuk.dev/core/modules/auth"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("api: %v", err)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx := context.Background()

	pool, err := db.NewPool(ctx, cfg.AppDSN())
	if err != nil {
		return err
	}
	defer pool.Close()

	sessions := session.NewService(pool, cfg.SessionTTL)
	wa, err := auth.NewWebAuthn(cfg)
	if err != nil {
		return err
	}
	router := httpserver.NewRouter(httpserver.Deps{
		Pool:     pool,
		Sessions: sessions,
		WebAuthn: wa,
		Config:   cfg,
	})
	return httpserver.Run(ctx, httpserver.New(cfg.ListenAddr, router))
}
