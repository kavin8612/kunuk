package httpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthEMiddleware(t *testing.T) {
	r := NewRouter(Deps{})
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, atteso 200", w.Code)
	}
	if w.Body.String() != "ok" {
		t.Fatalf("corpo = %q, atteso ok", w.Body.String())
	}
	// I middleware globali devono essere applicati anche a /health.
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, atteso no-store", got)
	}
	if w.Header().Get("X-Request-Id") == "" {
		t.Fatal("manca X-Request-Id")
	}
}

func TestNotFound(t *testing.T) {
	r := NewRouter(Deps{})
	req := httptest.NewRequest(http.MethodGet, "/inesistente", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, atteso 404", w.Code)
	}
}
