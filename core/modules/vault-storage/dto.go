// Package vaultstorage espone lo storage zero-knowledge del vault (doc 12): buste della VK,
// manifest firmato e item cifrati. Il server vede solo ciphertext/verificatori: i campi
// binari sono opachi (base64url sul filo). Ogni operazione gira sotto lo scope RLS
// dell'account (WithAccountTx, SR-32).
package vaultstorage

import (
	"encoding/json"
	"time"

	"kunuk.dev/core/internal/httpx"
)

// Envelope è una busta della VK (risposta GET /envelopes).
type Envelope struct {
	Type      string          `json:"type"`
	WrappedVK httpx.Bytes     `json:"wrapped_vk"`
	Params    json.RawMessage `json:"params,omitempty"`
}

// EnvelopeInput è il corpo di PUT /envelopes/{type} (il tipo arriva dal path).
type EnvelopeInput struct {
	WrappedVK httpx.Bytes     `json:"wrapped_vk"`
	Params    json.RawMessage `json:"params,omitempty"`
}

// VaultManifest è il manifest firmato del vault (GET /vault). manifest_pubkey è fissata alla
// registrazione e immutabile.
type VaultManifest struct {
	Manifest       httpx.Bytes `json:"manifest"`
	ManifestPubkey httpx.Bytes `json:"manifest_pubkey"`
	Signature      httpx.Bytes `json:"signature"`
	Version        int         `json:"version"`
}

// ManifestInput è il corpo di PUT /vault/manifest. manifest_pubkey è accettata per coerenza
// col contratto ma ignorata (immutabile); la versione deve essere strettamente crescente
// (anti-rollback, CAS → 409).
type ManifestInput struct {
	Manifest       httpx.Bytes `json:"manifest"`
	ManifestPubkey httpx.Bytes `json:"manifest_pubkey,omitempty"`
	Signature      httpx.Bytes `json:"signature"`
	Version        int         `json:"version"`
}

// Item è una voce cifrata del vault (il tipo è dentro il ciphertext, SR-25).
type Item struct {
	ID         string      `json:"id"`
	Ciphertext httpx.Bytes `json:"ciphertext"`
	WrappedCEK httpx.Bytes `json:"wrapped_cek"`
	Deleted    bool        `json:"deleted"`
	CreatedAt  time.Time   `json:"created_at"`
	UpdatedAt  time.Time   `json:"updated_at"`
}

// ItemInput è il corpo di POST/PUT /items. Su POST il client PUÒ fornire l'id (UUID): il
// core lega `vault_id ‖ item_id` nell'AAD del ciphertext (doc 16 §5), quindi l'id va scelto
// dal client PRIMA di cifrare. Id assente → lo genera il server (compat. con i client che non
// cifrano per-item). L'id è opaco al server (zero-knowledge): nessun significato lato server.
type ItemInput struct {
	ID         string      `json:"id,omitempty"`
	Ciphertext httpx.Bytes `json:"ciphertext"`
	WrappedCEK httpx.Bytes `json:"wrapped_cek"`
}
