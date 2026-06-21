package httpserver

import (
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/time/rate"

	"kunuk.dev/core/internal/config"
	"kunuk.dev/core/internal/httpserver/middleware"
	"kunuk.dev/core/internal/session"
	"kunuk.dev/core/modules/accounts"
	"kunuk.dev/core/modules/auth"
	vaultsync "kunuk.dev/core/modules/sync"
	vaultstorage "kunuk.dev/core/modules/vault-storage"
)

// Deps sono le dipendenze condivise iniettate negli handler dei moduli.
type Deps struct {
	Pool     *pgxpool.Pool
	Sessions *session.Service
	WebAuthn *webauthn.WebAuthn
	Config   config.Config
}

// NewRouter costruisce il router con la catena middleware globale e l'endpoint di liveness.
// I moduli (auth pubblico, accounts/vault-storage protetti) si montano sotto /v1 negli strati
// 5–7 (il modulo protetto userà middleware.Auth, quello auth no).
func NewRouter(d Deps) http.Handler {
	r := chi.NewRouter()
	r.Use(
		middleware.Recover,
		middleware.RequestID,
		middleware.SecurityHeaders,
		middleware.Logging,
		middleware.RateLimit(rate.Every(time.Second/50), 100), // ~50 req/s, picco 100
	)

	r.Get("/health", health)

	authHandler := auth.NewHandler(auth.NewService(d.Pool, d.Sessions, d.WebAuthn, d.Config.DecoySecret))
	accountsHandler := accounts.NewHandler(accounts.NewService(d.Pool))
	vaultHandler := vaultstorage.NewHandler(vaultstorage.NewService(d.Pool))
	syncHandler := vaultsync.NewHandler(vaultsync.NewService(d.Pool))
	r.Route("/v1", func(v chi.Router) {
		// Route pubbliche: registrazione/login/verifica email (nessun Bearer).
		authHandler.Routes(v)
		// Route protette: richiedono un Bearer valido (auth → account in ctx → RLS).
		v.Group(func(p chi.Router) {
			p.Use(middleware.Auth(d.Sessions))
			p.Route("/account", accountsHandler.Routes)
			vaultHandler.Routes(p)
			syncHandler.Routes(p)
		})
	})
	return r
}

// health è la sonda di liveness usata da Caddy e dall'healthcheck del container.
func health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("ok")); err != nil {
		log.Printf("api: scrittura della risposta /health fallita: %v", err)
	}
}
