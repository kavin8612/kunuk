package vaultsync

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"kunuk.dev/core/internal/httpx"
	"kunuk.dev/core/internal/reqctx"
)

// Handler espone gli endpoint del trasporto dei delta CRDT.
type Handler struct {
	svc *Service
}

// NewHandler costruisce l'handler dal servizio.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// Routes registra le route, montate sotto /v1 dietro il middleware Auth.
func (h *Handler) Routes(r chi.Router) {
	r.Get("/sync/changes", h.listChanges)
	r.Post("/sync/changes", h.pushChanges)
}

func (h *Handler) account(r *http.Request) string { return reqctx.AccountID(r.Context()) }

func (h *Handler) listChanges(w http.ResponseWriter, r *http.Request) {
	raw, err := httpx.Cursor(r)
	if err != nil {
		httpx.WriteError(w, r, httpx.CodeInvalidRequest, "cursore non valido")
		return
	}
	since, err := parseCursor(raw)
	if err != nil {
		httpx.WriteError(w, r, httpx.CodeInvalidRequest, "cursore non valido")
		return
	}
	limit := httpx.Limit(r)
	changes, err := h.svc.ListChanges(r.Context(), h.account(r), since, limit)
	if err != nil {
		httpx.WriteInternal(w, r, err)
		return
	}
	next := ""
	if len(changes) == limit && limit > 0 {
		next = encodeCursor(changes[len(changes)-1])
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.NewPage(changes, next))
}

func (h *Handler) pushChanges(w http.ResponseWriter, r *http.Request) {
	var in PushChangesInput
	if err := httpx.DecodeStrict(w, r, &in); err != nil {
		httpx.WriteError(w, r, httpx.CodeInvalidRequest, "corpo non valido")
		return
	}
	if err := h.svc.PushChanges(r.Context(), h.account(r), in.Changes); err != nil {
		httpx.WriteInternal(w, r, err)
		return
	}
	httpx.WriteStatus(w, http.StatusAccepted)
}
