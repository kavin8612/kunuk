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

	"github.com/google/uuid"

	"kunuk.dev/core/internal/config"
	"kunuk.dev/core/internal/httpserver"
	"kunuk.dev/core/internal/session"
	"kunuk.dev/core/modules/auth"
)

// registerBody costruisce un RegistrationBundle solo-password (niente passkey).
func registerBody(email string, av []byte) string {
	d := b64([]byte{0xAA, 0xBB})
	// account_id/vault_id scelti dal client (UUID), deterministici per email (ADR-0020).
	aid := uuid.NewSHA1(uuid.NameSpaceURL, []byte("kunuk-account:"+email)).String()
	vid := uuid.NewSHA1(uuid.NameSpaceURL, []byte("kunuk-vault:"+email)).String()
	return fmt.Sprintf(`{"email":%q,"account_id":%q,"vault_id":%q,"password_verifier":%q,`+
		`"kdf_params":{"memory_kib":65536,"iterations":3,"parallelism":4,"salt":"AAAAAAAAAAAAAAAAAAAAAA"},`+
		`"recovery_pubkey":%q,"password_envelope":%q,"recovery_envelope":%q,`+
		`"manifest":%q,"manifest_pubkey":%q,"signature":%q,"wrapped_signing_key":%q,"version":1}`,
		email, aid, vid, b64(av), d, d, d, d, d, d, d)
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

// TestClientChosenIDsExposed copre il task 0.11 (ADR-0020): account_id/vault_id scelti dal
// client sono persistiti e riesposti — account_id REALE a login/start (per un device vergine),
// vault_id su GET /vault (autenticato) — e per email ignota account_id è un decoy stabile,
// UUID valido, indistinguibile dal reale (anti-enum, SR-26).
func TestClientChosenIDsExposed(t *testing.T) {
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

	const email = "a@example.com"
	av := []byte("verificatore-di-A-32-byte-xxxxxx")
	wantAccount := uuid.NewSHA1(uuid.NameSpaceURL, []byte("kunuk-account:"+email)).String()
	wantVault := uuid.NewSHA1(uuid.NameSpaceURL, []byte("kunuk-vault:"+email)).String()

	assertStatus(t, reqJSON(t, router, http.MethodPost, "/v1/auth/register/finish", "", registerBody(email, av)), http.StatusCreated)

	// login/start espone l'account_id REALE (= quello scelto in registrazione, persistito).
	if got := loginStartAccountID(t, router, email); got != wantAccount {
		t.Fatalf("login/start account_id: atteso %s, ottenuto %s", wantAccount, got)
	}

	// GET /vault (autenticato) espone il vault_id REALE.
	w := reqJSON(t, router, http.MethodPost, "/v1/auth/login/finish", "", loginFinishBody(email, av))
	assertStatus(t, w, http.StatusOK)
	var tok struct {
		SessionToken string `json:"session_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &tok); err != nil {
		t.Fatalf("decode login/finish: %v", err)
	}
	wv := reqWithToken(t, router, http.MethodGet, "/v1/vault", tok.SessionToken)
	assertStatus(t, wv, http.StatusOK)
	var vault struct {
		VaultID string `json:"vault_id"`
	}
	if err := json.Unmarshal(wv.Body.Bytes(), &vault); err != nil {
		t.Fatalf("decode vault: %v", err)
	}
	if vault.VaultID != wantVault {
		t.Fatalf("GET /vault vault_id: atteso %s, ottenuto %s", wantVault, vault.VaultID)
	}

	// Email IGNOTA: account_id decoy, UUID valido, stabile tra chiamate, != reale (SR-26).
	d1 := loginStartAccountID(t, router, "ignota@example.com")
	d2 := loginStartAccountID(t, router, "ignota@example.com")
	if d1 != d2 {
		t.Fatalf("decoy account_id non stabile tra chiamate: %s vs %s", d1, d2)
	}
	if _, err := uuid.Parse(d1); err != nil {
		t.Fatalf("decoy account_id non è un UUID valido: %s", d1)
	}
	if d1 == wantAccount {
		t.Fatalf("decoy account_id coincide col reale (distinguibile)")
	}
}

// loginStartAccountID estrae account_id dalla risposta di login/start.
func loginStartAccountID(t *testing.T, router http.Handler, email string) string {
	t.Helper()
	w := reqJSON(t, router, http.MethodPost, "/v1/auth/login/start", "", fmt.Sprintf(`{"email":%q}`, email))
	assertStatus(t, w, http.StatusOK)
	var resp struct {
		AccountID string `json:"account_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode login/start: %v", err)
	}
	return resp.AccountID
}
