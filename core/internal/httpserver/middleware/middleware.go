// Package middleware contiene la catena HTTP del backend (scritta a mano, doc 21/SR):
// recupero panic, request_id, header di sicurezza + no-store, logging, rate-limit e auth.
package middleware

import (
	"log"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/google/uuid"

	"kunuk.dev/core/internal/httpx"
	"kunuk.dev/core/internal/reqctx"
)

// Recover intercetta i panic, logga lo stack internamente ed emette un 500 generico (mai
// dettagli all'esterno, doc 18 §5).
func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("api: panic [request_id=%s]: %v\n%s",
					reqctx.RequestID(r.Context()), rec, debug.Stack())
				httpx.WriteError(w, r, httpx.CodeInternal, "errore interno")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// RequestID genera un identificativo per richiesta, lo mette nel context e nell'header di
// risposta (tracciamento, doc 21).
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := uuid.NewString()
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(reqctx.WithRequestID(r.Context(), id)))
	})
}

// SecurityHeaders imposta no-store su tutte le API (SR-29) e gli header di base; HSTS/TLS
// sono terminati da Caddy (ADR-0014).
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

// Logging registra metodo, path, stato e latenza con il request_id. Mai corpo, token o
// email (SR-26): solo metadati non sensibili. Metodo e path sono sanificati (CR/LF e
// caratteri di controllo rimossi) per evitare log injection.
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		//nolint:gosec // G706: metodo e path sono sanificati da stripControl (no CR/LF)
		log.Printf("api: %s %s -> %d (%s) [request_id=%s]",
			stripControl(r.Method), stripControl(r.URL.Path), sw.status,
			time.Since(start), reqctx.RequestID(r.Context()))
	})
}

// stripControl rimuove newline e caratteri di controllo (anti log-injection).
func stripControl(s string) string {
	return strings.Map(func(c rune) rune {
		if c == '\n' || c == '\r' || c < 0x20 {
			return -1
		}
		return c
	}, s)
}

// statusWriter cattura lo stato HTTP per il log.
type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusWriter) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}
