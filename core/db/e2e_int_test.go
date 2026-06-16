package db_test

// Test E2E della fondazione del backend (task 0.9, L8): concatena i tre moduli su HTTP reale
// lungo il percorso PASSWORD (quello esercitabile senza autenticatore hardware, anticipa il
// gate 0.10): registrazione → login → token → upload item → rilettura. Verifica end-to-end
// che la catena auth+RLS+storage componga e che il server conservi il ciphertext in modo
// OPACO (round-trip byte-identico di ciphertext e wrapped_cek): nessuna trasformazione,
// nessuna lettura del plaintext lato server (zero-knowledge, SR-21/SR-25).

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"kunuk.dev/core/internal/config"
	"kunuk.dev/core/internal/httpserver"
	"kunuk.dev/core/internal/session"
	"kunuk.dev/core/modules/auth"
)

func TestEndToEndPasswordFlow(t *testing.T) {
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

	const email = "e2e@example.com"
	av := []byte("verificatore-e2e-32-byte-xxxxxxx")

	// 1) Registrazione solo-password (RegistrationBundle opaco al server) → 201.
	assertStatus(t, reqJSON(t, router, http.MethodPost, "/v1/auth/register/finish", "", registerBody(email, av)), http.StatusCreated)

	// 2) login/start → 200 (forma uniforme, anti-enum).
	assertStatus(t, reqJSON(t, router, http.MethodPost, "/v1/auth/login/start", "", `{"email":"`+email+`"}`), http.StatusOK)

	// 3) login/finish col verificatore corretto → token di sessione vero (non Issue diretto).
	w := reqJSON(t, router, http.MethodPost, "/v1/auth/login/finish", "", loginFinishBody(email, av))
	assertStatus(t, w, http.StatusOK)
	var login struct {
		SessionToken string `json:"session_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &login); err != nil || login.SessionToken == "" {
		t.Fatalf("token di login mancante: err=%v body=%s", err, w.Body.String())
	}
	token := login.SessionToken

	// Il token di login autorizza le route protette: il manifest del vault creato in
	// registrazione è leggibile (versione 1).
	assertStatus(t, reqWithToken(t, router, http.MethodGet, "/v1/vault", token), http.StatusOK)

	// 4) Upload di un item con ciphertext NOTO (byte non banali, distinti da CEK).
	ct := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33}
	cek := []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x44, 0x55}
	cw := reqJSON(t, router, http.MethodPost, "/v1/items", token, itemBody(ct, cek))
	assertStatus(t, cw, http.StatusCreated)
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(cw.Body.Bytes(), &created); err != nil || created.ID == "" {
		t.Fatalf("id item mancante: err=%v body=%s", err, cw.Body.String())
	}

	// 5) Rilettura: il server restituisce il ciphertext BYTE-IDENTICO (opaco, mai trasformato).
	gw := reqWithToken(t, router, http.MethodGet, "/v1/items/"+created.ID, token)
	assertStatus(t, gw, http.StatusOK)
	var got struct {
		Ciphertext string `json:"ciphertext"`
		WrappedCEK string `json:"wrapped_cek"`
	}
	if err := json.Unmarshal(gw.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode item riletto: %v", err)
	}
	if got.Ciphertext != b64(ct) {
		t.Fatalf("ciphertext alterato dal server: atteso %s, ottenuto %s", b64(ct), got.Ciphertext)
	}
	if got.WrappedCEK != b64(cek) {
		t.Fatalf("wrapped_cek alterato dal server: atteso %s, ottenuto %s", b64(cek), got.WrappedCEK)
	}
}
