// Package httpserver costruisce il server HTTP, il router (chi) e ne governa l'avvio e
// l'arresto controllato. Tratta solo ciphertext/verificatori (zero-knowledge): nessuna
// crittografia qui, vive nel crypto-core lato client.
package httpserver

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// New costruisce l'http.Server con timeout espliciti (niente Serve senza timeout, gosec G114).
func New(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

// Run avvia il server e lo arresta con grazia su SIGINT/SIGTERM (drena le richieste in corso).
func Run(ctx context.Context, srv *http.Server) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		log.Printf("api: ascolto su %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Print("api: arresto in corso...")
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	}
}
