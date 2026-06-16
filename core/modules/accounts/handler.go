package accounts

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"kunuk.dev/core/internal/httpx"
	"kunuk.dev/core/internal/reqctx"
)

// Handler espone gli endpoint dell'account.
type Handler struct {
	svc *Service
}

// NewHandler costruisce l'handler dal servizio.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// Routes registra le route, montate sotto /v1/account dietro il middleware Auth.
func (h *Handler) Routes(r chi.Router) {
	r.Get("/", h.get)
	r.Delete("/", h.delete)
}

type accountResponse struct {
	ID        string          `json:"id"`
	Email     string          `json:"email"`
	KdfParams json.RawMessage `json:"kdf_params"`
	Status    string          `json:"status"`
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	a, err := h.svc.Get(r.Context(), reqctx.AccountID(r.Context()))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			httpx.WriteError(w, r, httpx.CodeNotFound, "non trovato")
			return
		}
		httpx.WriteInternal(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, accountResponse(a))
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	deleted, err := h.svc.Delete(r.Context(), reqctx.AccountID(r.Context()))
	if err != nil {
		httpx.WriteInternal(w, r, err)
		return
	}
	if !deleted {
		httpx.WriteError(w, r, httpx.CodeNotFound, "non trovato")
		return
	}
	httpx.WriteStatus(w, http.StatusNoContent)
}
