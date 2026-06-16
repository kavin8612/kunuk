package vaultstorage

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"kunuk.dev/core/internal/httpx"
	"kunuk.dev/core/internal/reqctx"
)

// Handler espone gli endpoint dello storage del vault.
type Handler struct {
	svc *Service
}

// NewHandler costruisce l'handler dal servizio.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// Routes registra le route, montate sotto /v1 dietro il middleware Auth.
func (h *Handler) Routes(r chi.Router) {
	r.Get("/envelopes", h.listEnvelopes)
	r.Put("/envelopes/{type}", h.replaceEnvelope)
	r.Get("/vault", h.getVault)
	r.Put("/vault/manifest", h.updateManifest)
	r.Get("/items", h.listItems)
	r.Post("/items", h.createItem)
	r.Get("/items/{id}", h.getItem)
	r.Put("/items/{id}", h.updateItem)
	r.Delete("/items/{id}", h.deleteItem)
}

func (h *Handler) account(r *http.Request) string { return reqctx.AccountID(r.Context()) }

// writeErr mappa gli errori del dominio sui codici HTTP (resto → 500 generico).
func (h *Handler) writeErr(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		httpx.WriteError(w, r, httpx.CodeNotFound, "non trovato")
	case errors.Is(err, ErrVersionConflict):
		httpx.WriteError(w, r, httpx.CodeConflict, "conflitto di versione")
	case errors.Is(err, ErrInvalidEnvelope):
		httpx.WriteError(w, r, httpx.CodeInvalidRequest, "tipo busta non valido")
	default:
		httpx.WriteInternal(w, r, err)
	}
}

func (h *Handler) listEnvelopes(w http.ResponseWriter, r *http.Request) {
	envs, err := h.svc.ListEnvelopes(r.Context(), h.account(r))
	if err != nil {
		h.writeErr(w, r, err)
		return
	}
	if envs == nil {
		envs = []Envelope{}
	}
	httpx.WriteJSON(w, http.StatusOK, envs)
}

func (h *Handler) replaceEnvelope(w http.ResponseWriter, r *http.Request) {
	var in EnvelopeInput
	if err := httpx.DecodeStrict(w, r, &in); err != nil {
		httpx.WriteError(w, r, httpx.CodeInvalidRequest, "corpo non valido")
		return
	}
	if err := h.svc.ReplaceEnvelope(r.Context(), h.account(r), chi.URLParam(r, "type"), in); err != nil {
		h.writeErr(w, r, err)
		return
	}
	httpx.WriteStatus(w, http.StatusOK)
}

func (h *Handler) getVault(w http.ResponseWriter, r *http.Request) {
	v, err := h.svc.GetVault(r.Context(), h.account(r))
	if err != nil {
		h.writeErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

func (h *Handler) updateManifest(w http.ResponseWriter, r *http.Request) {
	var in ManifestInput
	if err := httpx.DecodeStrict(w, r, &in); err != nil {
		httpx.WriteError(w, r, httpx.CodeInvalidRequest, "corpo non valido")
		return
	}
	if in.Version <= 0 {
		httpx.WriteError(w, r, httpx.CodeInvalidRequest, "versione non valida")
		return
	}
	if err := h.svc.UpdateManifest(r.Context(), h.account(r), in); err != nil {
		h.writeErr(w, r, err)
		return
	}
	httpx.WriteStatus(w, http.StatusOK)
}

func (h *Handler) listItems(w http.ResponseWriter, r *http.Request) {
	raw, err := httpx.Cursor(r)
	if err != nil {
		httpx.WriteError(w, r, httpx.CodeInvalidRequest, "cursore non valido")
		return
	}
	cur, err := parseCursor(raw)
	if err != nil {
		httpx.WriteError(w, r, httpx.CodeInvalidRequest, "cursore non valido")
		return
	}
	limit := httpx.Limit(r)
	items, err := h.svc.ListItems(r.Context(), h.account(r), cur, limit)
	if err != nil {
		h.writeErr(w, r, err)
		return
	}
	next := ""
	if len(items) == limit && limit > 0 {
		next = encodeCursor(items[len(items)-1])
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.NewPage(items, next))
}

func (h *Handler) createItem(w http.ResponseWriter, r *http.Request) {
	var in ItemInput
	if err := httpx.DecodeStrict(w, r, &in); err != nil {
		httpx.WriteError(w, r, httpx.CodeInvalidRequest, "corpo non valido")
		return
	}
	it, err := h.svc.CreateItem(r.Context(), h.account(r), in)
	if err != nil {
		h.writeErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, it)
}

func (h *Handler) getItem(w http.ResponseWriter, r *http.Request) {
	id, ok := itemID(w, r)
	if !ok {
		return
	}
	it, err := h.svc.GetItem(r.Context(), h.account(r), id)
	if err != nil {
		h.writeErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, it)
}

func (h *Handler) updateItem(w http.ResponseWriter, r *http.Request) {
	id, ok := itemID(w, r)
	if !ok {
		return
	}
	var in ItemInput
	if err := httpx.DecodeStrict(w, r, &in); err != nil {
		httpx.WriteError(w, r, httpx.CodeInvalidRequest, "corpo non valido")
		return
	}
	if err := h.svc.UpdateItem(r.Context(), h.account(r), id, in); err != nil {
		h.writeErr(w, r, err)
		return
	}
	httpx.WriteStatus(w, http.StatusOK)
}

func (h *Handler) deleteItem(w http.ResponseWriter, r *http.Request) {
	id, ok := itemID(w, r)
	if !ok {
		return
	}
	if err := h.svc.DeleteItem(r.Context(), h.account(r), id); err != nil {
		h.writeErr(w, r, err)
		return
	}
	httpx.WriteStatus(w, http.StatusNoContent)
}

// itemID estrae e valida l'id (UUID) dal path. Id malformato → 404 (uniforme con l'IDOR:
// non si distingue "malformato" da "non tuo").
func itemID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := chi.URLParam(r, "id")
	if _, err := uuid.Parse(id); err != nil {
		httpx.WriteError(w, r, httpx.CodeNotFound, "non trovato")
		return "", false
	}
	return id, true
}
