package auth

import (
	"encoding/json"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"kunuk.dev/core/internal/httpx"
)

// RegisterStart: il client chiede le opzioni di creazione passkey.
type RegisterStartRequest struct {
	Email string `json:"email"`
}

type RegisterStartResponse struct {
	Handle                  string                       `json:"handle"`
	WebAuthnCreationOptions *protocol.CredentialCreation `json:"webauthn_creation_options"`
}

// RegisterFinish: il client carica il RegistrationBundle (tutto opaco al server). La passkey è
// opzionale: senza `passkey_attestation` è una registrazione solo-password (es. la CLI del gate).
type RegisterFinishRequest struct {
	Email              string          `json:"email"`
	Handle             string          `json:"handle"`
	PasskeyAttestation json.RawMessage `json:"passkey_attestation"`
	PasswordVerifier   httpx.Bytes     `json:"password_verifier"`
	KdfParams          json.RawMessage `json:"kdf_params"`
	RecoveryPubkey     httpx.Bytes     `json:"recovery_pubkey"`
	PasswordEnvelope   httpx.Bytes     `json:"password_envelope"`
	PasskeyEnvelope    httpx.Bytes     `json:"passkey_envelope"`
	RecoveryEnvelope   httpx.Bytes     `json:"recovery_envelope"`
	Manifest           httpx.Bytes     `json:"manifest"`
	ManifestPubkey     httpx.Bytes     `json:"manifest_pubkey"`
	Signature          httpx.Bytes     `json:"signature"`
	WrappedSigningKey  httpx.Bytes     `json:"wrapped_signing_key"`
	Version            int             `json:"version"`
}

// LoginStart: forma identica per email esistente e inesistente (anti-enum, SR-26).
type LoginStartRequest struct {
	Email string `json:"email"`
}

type LoginStartResponse struct {
	Handle                 string                        `json:"handle"`
	WebAuthnRequestOptions *protocol.CredentialAssertion `json:"webauthn_request_options"`
	KdfParams              json.RawMessage               `json:"kdf_params"`
}

// LoginFinish: assertion passkey OPPURE verificatore password.
type LoginFinishRequest struct {
	Email            string          `json:"email"`
	Handle           string          `json:"handle"`
	PasskeyAssertion json.RawMessage `json:"passkey_assertion"`
	PasswordVerifier httpx.Bytes     `json:"password_verifier"`
}

type LoginFinishResponse struct {
	SessionToken string    `json:"session_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// EmailVerify.
type EmailVerifyRequest struct {
	Token string `json:"token"`
}
