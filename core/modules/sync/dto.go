// Package vaultsync espone il trasporto dei delta CRDT (doc 12 §sync, doc 20 §8): il server
// li conserva e li inoltra senza leggerli (sono cifrati con la VK lato client, ADR-0022). Nome
// del package diverso dal nome della cartella (come vaultstorage) per non collidere con il
// package `sync` della standard library.
package vaultsync

import (
	"time"

	"kunuk.dev/core/internal/httpx"
)

// SyncChange è un delta CRDT cifrato (risposta di GET /sync/changes). ID è una stringa (il
// bigint del DB può eccedere la precisione sicura di un float64 lato client, doc 21). DeviceID
// è sempre nil per ora: il modulo di registrazione dispositivi è un TODO separato (rinviato dal
// task 0.9), non in scope per il task 1.2.
type SyncChange struct {
	ID         string      `json:"id"`
	DeviceID   *string     `json:"device_id"`
	Ciphertext httpx.Bytes `json:"ciphertext"`
	Clock      string      `json:"clock"`
	CreatedAt  time.Time   `json:"created_at"`
}

// SyncChangeInput è un delta in ingresso (corpo di POST /sync/changes). `clock` è una stringa
// opaca scelta dal client (non interpretata dal server, come `ciphertext`).
type SyncChangeInput struct {
	Ciphertext httpx.Bytes `json:"ciphertext"`
	Clock      string      `json:"clock"`
}

// PushChangesInput è il corpo di POST /sync/changes (doc 12).
type PushChangesInput struct {
	Changes []SyncChangeInput `json:"changes"`
}
