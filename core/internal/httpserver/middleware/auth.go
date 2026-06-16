package middleware

import (
	"net/http"
	"strings"

	"kunuk.dev/core/internal/httpx"
	"kunuk.dev/core/internal/reqctx"
	"kunuk.dev/core/internal/session"
)

// Auth richiede un token Bearer valido: convalida la sessione e mette account e sessione nel
// context per gli handler. Token assente, scaduto o revocato → 401 uniforme (nessuna
// distinzione, coerente con l'anti-enumeration). Va montato solo sulle route protette.
func Auth(sessions *session.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			accountID, sessionID, ok, err := sessions.Authenticate(r.Context(), bearer(r))
			if err != nil {
				httpx.WriteInternal(w, r, err)
				return
			}
			if !ok {
				httpx.WriteError(w, r, httpx.CodeUnauthorized, "non autorizzato")
				return
			}
			ctx := reqctx.WithSession(reqctx.WithAccount(r.Context(), accountID), sessionID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// bearer estrae il token dall'header Authorization: Bearer <token>.
func bearer(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return h[len(prefix):]
	}
	return ""
}
