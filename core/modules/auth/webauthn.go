// Package auth implementa registrazione e login (doc 12): cerimonie WebAuthn server-side
// (verifica attestation/assertion, ADR-0006) e via password (confronto del verificatore 2SKD),
// con anti-enumeration (SR-26). Il backend non fa crittografia del vault: hash SHA-256 del
// verificatore e dei token, verifica WebAuthn via libreria, confronto a tempo costante.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/go-webauthn/webauthn/webauthn"

	"kunuk.dev/core/internal/config"
)

// NewWebAuthn costruisce il verificatore WebAuthn: RP ID = dominio, origin = base URL pubblica.
func NewWebAuthn(cfg config.Config) (*webauthn.WebAuthn, error) {
	return webauthn.New(&webauthn.Config{
		RPID:          cfg.Domain,
		RPDisplayName: "Kunuk",
		RPOrigins:     []string{cfg.PublicBaseURL},
	})
}

// authUser implementa webauthn.User. L'id (handle) è stabile per account e coincide con lo
// stesso valore usato in registrazione (memorizzato con la credenziale), così il login lo
// ritrova e la verifica dello userHandle dell'assertion torna.
type authUser struct {
	id    []byte
	name  string
	creds []webauthn.Credential
}

func (u *authUser) WebAuthnID() []byte                         { return u.id }
func (u *authUser) WebAuthnName() string                       { return u.name }
func (u *authUser) WebAuthnDisplayName() string                { return u.name }
func (u *authUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// storedCredential è il JSON salvato in webauthn_credential.data: la credenziale + l'handle
// utente, così al login si ricostruisce lo stesso WebAuthnID.
type storedCredential struct {
	UserHandle []byte              `json:"user_handle"`
	Credential webauthn.Credential `json:"credential"`
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("csprng: %w", err)
	}
	return b, nil
}

// newHandle genera un handle opaco per lo stato della cerimonia (stringa per il client, byte
// per il DB).
func newHandle() (string, []byte, error) {
	b, err := randomBytes(32)
	if err != nil {
		return "", nil, err
	}
	return base64.RawURLEncoding.EncodeToString(b), b, nil
}

func decodeHandle(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// ── Decoy anti-enumeration (SR-26) ─────────────────────────────────────────────
// Per un'email inesistente login/start deve avere forma e tempi identici a un account reale.
// I valori sono derivati in modo deterministico da email + segreto: stabili tra chiamate, così
// un attaccante non distingue il decoy dal reale osservando la varianza.

func derive(secret []byte, label, email string, n int) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(label + ":" + email))
	return mac.Sum(nil)[:n]
}

// decoyUser costruisce un utente fittizio con una credenziale plausibile per BeginLogin.
func decoyUser(secret []byte, email string) *authUser {
	id := derive(secret, "cred", email, 16)
	return &authUser{
		id:   derive(secret, "user", email, 16),
		name: email,
		creds: []webauthn.Credential{{
			ID:        id,
			PublicKey: derive(secret, "pub", email, 32),
		}},
	}
}

// decoyKdfParams genera parametri KDF plausibili (suite v1, salt deterministico).
func decoyKdfParams(secret []byte, email string) json.RawMessage {
	salt := base64.RawStdEncoding.EncodeToString(derive(secret, "salt", email, 16))
	return json.RawMessage(fmt.Sprintf(
		`{"memory_kib":65536,"iterations":3,"parallelism":4,"salt":%q}`, salt))
}

// decoyVerifierHash è l'obiettivo del confronto a tempo costante quando l'email non esiste.
func decoyVerifierHash(secret []byte, email string) []byte {
	return derive(secret, "verifier", email, sha256.Size)
}
