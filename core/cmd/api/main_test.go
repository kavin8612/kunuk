package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHealth verifica che la sonda risponda 200 con corpo "ok".
func TestHealth(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		wantStatus int
		wantBody   string
	}{
		{name: "GET", method: http.MethodGet, wantStatus: http.StatusOK, wantBody: "ok"},
		{name: "HEAD", method: http.MethodHead, wantStatus: http.StatusOK, wantBody: "ok"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			health(rec, httptest.NewRequest(tc.method, "/health", nil))
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, atteso %d", rec.Code, tc.wantStatus)
			}
			if got := rec.Body.String(); got != tc.wantBody {
				t.Fatalf("body = %q, atteso %q", got, tc.wantBody)
			}
		})
	}
}

// TestListenAddr verifica il default e l'override via variabile d'ambiente.
func TestListenAddr(t *testing.T) {
	t.Setenv("KUNUK_API_LISTEN_ADDR", "")
	if got := listenAddr(); got != defaultListenAddr {
		t.Fatalf("listenAddr() = %q, atteso il default %q", got, defaultListenAddr)
	}
	t.Setenv("KUNUK_API_LISTEN_ADDR", ":9999")
	if got := listenAddr(); got != ":9999" {
		t.Fatalf("listenAddr() = %q, atteso \":9999\"", got)
	}
}
