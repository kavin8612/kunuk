// Comando api: entrypoint del backend Kunuk.
//
// TODO(task-0.9): wiring reale dei moduli (auth, accounts, vault-storage) e del
// router secondo l'OpenAPI (doc 12) — placeholder del bootstrap (task 0.1). Per
// ora espone solo /health, così il Docker Compose di sviluppo (scripts/infra/)
// ha un servizio applicativo da avviare dietro Caddy. Un /health che risponde
// 200 non è il backend: è lo scaffold (doc 19 §3).
package main

import (
	"errors"
	"log"
	"net/http"
	"os"
	"time"
)

// defaultListenAddr è l'indirizzo usato quando KUNUK_API_LISTEN_ADDR è assente.
const defaultListenAddr = ":8080"

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", health)

	// ReadHeaderTimeout esplicito: niente Serve senza timeout (gosec G114).
	server := &http.Server{
		Addr:              listenAddr(),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("api: ascolto su %s (placeholder /health; backend reale in task-0.9)", server.Addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("api: errore del server: %v", err)
	}
}

// listenAddr restituisce l'indirizzo di ascolto da KUNUK_API_LISTEN_ADDR, con un
// default sicuro quando la variabile non è impostata.
func listenAddr() string {
	if addr := os.Getenv("KUNUK_API_LISTEN_ADDR"); addr != "" {
		return addr
	}
	return defaultListenAddr
}

// health è la sonda di liveness usata da Caddy e dall'healthcheck del container.
func health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("ok")); err != nil {
		log.Printf("api: scrittura della risposta /health fallita: %v", err)
	}
}
