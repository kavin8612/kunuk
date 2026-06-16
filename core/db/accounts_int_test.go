package db_test

// Test d'integrazione HTTP del modulo accounts: valida la catena auth (Bearer → sessione →
// account in ctx) + WithAccountTx + RLS end-to-end. Riusa setupPreauth/mustRegister.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"kunuk.dev/core/internal/config"
	"kunuk.dev/core/internal/httpserver"
	"kunuk.dev/core/internal/session"
)

// reqWithToken esegue una richiesta verso il router con un eventuale Bearer.
func reqWithToken(t *testing.T, router http.Handler, method, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func assertStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status = %d, atteso %d (body=%s)", w.Code, want, w.Body.String())
	}
}

func TestAccountAPI(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	pool, _ := setupPreauth(ctx, t)
	idA := mustRegister(ctx, t, pool, "a@example.com")
	idB := mustRegister(ctx, t, pool, "b@example.com")

	sessions := session.NewService(pool, time.Hour)
	tokA, _, err := sessions.Issue(ctx, idA)
	if err != nil {
		t.Fatalf("Issue A: %v", err)
	}
	tokB, _, err := sessions.Issue(ctx, idB)
	if err != nil {
		t.Fatalf("Issue B: %v", err)
	}

	router := httpserver.NewRouter(httpserver.Deps{Pool: pool, Sessions: sessions, Config: config.Config{}})

	// A legge il proprio account.
	w := reqWithToken(t, router, http.MethodGet, "/v1/account", tokA)
	assertStatus(t, w, http.StatusOK)
	var got struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ID != idA || got.Email != "a@example.com" {
		t.Fatalf("account inatteso: %+v", got)
	}

	// Senza token o con token fasullo → 401 uniforme.
	assertStatus(t, reqWithToken(t, router, http.MethodGet, "/v1/account", ""), http.StatusUnauthorized)
	assertStatus(t, reqWithToken(t, router, http.MethodGet, "/v1/account", "token-fasullo"), http.StatusUnauthorized)

	// A cancella il proprio account → 204; poi il suo token non è più valido (sessione in cascade).
	assertStatus(t, reqWithToken(t, router, http.MethodDelete, "/v1/account", tokA), http.StatusNoContent)
	assertStatus(t, reqWithToken(t, router, http.MethodGet, "/v1/account", tokA), http.StatusUnauthorized)

	// B non è stato toccato dalla cancellazione di A.
	assertStatus(t, reqWithToken(t, router, http.MethodGet, "/v1/account", tokB), http.StatusOK)
}
