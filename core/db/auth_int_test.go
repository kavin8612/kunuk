package db_test

// Test d'integrazione del modulo auth via PASSWORD (il percorso del gate 0.10: una CLI non
// fa passkey hardware) + anti-enumeration (SR-26). La passkey server-side è esercitata dalla
// libreria go-webauthn; il round-trip completo dell'assertion richiede un autenticatore
// virtuale → TODO (qui si coprono registrazione/login via verificatore e la forma anti-enum).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"kunuk.dev/core/internal/config"
	"kunuk.dev/core/internal/httpserver"
	"kunuk.dev/core/internal/session"
	"kunuk.dev/core/modules/auth"
)

// registerBody costruisce un RegistrationBundle solo-password (niente passkey).
func registerBody(email string, av []byte) string {
	d := b64([]byte{0xAA, 0xBB})
	return fmt.Sprintf(`{"email":%q,"password_verifier":%q,`+
		`"kdf_params":{"memory_kib":65536,"iterations":3,"parallelism":4,"salt":"AAAAAAAAAAAAAAAAAAAAAA"},`+
		`"recovery_pubkey":%q,"password_envelope":%q,"recovery_envelope":%q,`+
		`"manifest":%q,"manifest_pubkey":%q,"signature":%q,"wrapped_signing_key":%q,"version":1}`,
		email, b64(av), d, d, d, d, d, d, d)
}

func loginFinishBody(email string, av []byte) string {
	return fmt.Sprintf(`{"email":%q,"password_verifier":%q}`, email, b64(av))
}

func TestAuthPasswordFlow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	pool, _ := setupPreauth(ctx, t)

	cfg := config.Config{Domain: "localhost", PublicBaseURL: "http://localhost", DecoySecret: []byte(strings.Repeat("x", 32))}
	wa, err := auth.NewWebAuthn(cfg)
	if err != nil {
		t.Fatalf("webauthn: %v", err)
	}
	sessions := session.NewService(pool, time.Hour)
	router := httpserver.NewRouter(httpserver.Deps{Pool: pool, Sessions: sessions, WebAuthn: wa, Config: cfg})

	av := []byte("verificatore-di-A-32-byte-xxxxxx")

	// Registrazione (solo password) → 201; email duplicata → ancora 201 (anti-enum).
	assertStatus(t, reqJSON(t, router, http.MethodPost, "/v1/auth/register/finish", "", registerBody("a@example.com", av)), http.StatusCreated)
	assertStatus(t, reqJSON(t, router, http.MethodPost, "/v1/auth/register/finish", "", registerBody("a@example.com", av)), http.StatusCreated)

	// login/start: stessa forma (200) per email reale e inesistente.
	assertStatus(t, reqJSON(t, router, http.MethodPost, "/v1/auth/login/start", "", `{"email":"a@example.com"}`), http.StatusOK)
	assertStatus(t, reqJSON(t, router, http.MethodPost, "/v1/auth/login/start", "", `{"email":"nessuno@example.com"}`), http.StatusOK)

	// login/finish con verificatore corretto → 200 + token usabile.
	w := reqJSON(t, router, http.MethodPost, "/v1/auth/login/finish", "", loginFinishBody("a@example.com", av))
	assertStatus(t, w, http.StatusOK)
	var got struct {
		SessionToken string `json:"session_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || got.SessionToken == "" {
		t.Fatalf("token mancante: err=%v body=%s", err, w.Body.String())
	}
	assertStatus(t, reqWithToken(t, router, http.MethodGet, "/v1/account", got.SessionToken), http.StatusOK)

	// Verificatore errato ed email inesistente → 401 uniforme.
	assertStatus(t, reqJSON(t, router, http.MethodPost, "/v1/auth/login/finish", "", loginFinishBody("a@example.com", []byte("verificatore-sbagliato-32byte-xx"))), http.StatusUnauthorized)
	assertStatus(t, reqJSON(t, router, http.MethodPost, "/v1/auth/login/finish", "", loginFinishBody("nessuno@example.com", av)), http.StatusUnauthorized)
}
