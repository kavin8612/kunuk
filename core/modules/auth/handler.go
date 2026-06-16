package auth

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"kunuk.dev/core/internal/httpx"
)

// Handler espone gli endpoint di registrazione e login (route pubbliche, nessun Auth).
type Handler struct {
	svc *Service
}

// NewHandler costruisce l'handler dal servizio.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// Routes registra le route pubbliche sotto /v1.
func (h *Handler) Routes(r chi.Router) {
	r.Post("/auth/register/start", h.registerStart)
	r.Post("/auth/register/finish", h.registerFinish)
	r.Post("/auth/login/start", h.loginStart)
	r.Post("/auth/login/finish", h.loginFinish)
	r.Post("/auth/email/verify", h.emailVerify)
}

func (h *Handler) registerStart(w http.ResponseWriter, r *http.Request) {
	var req RegisterStartRequest
	if err := httpx.DecodeStrict(w, r, &req); err != nil || req.Email == "" {
		httpx.WriteError(w, r, httpx.CodeInvalidRequest, "richiesta non valida")
		return
	}
	resp, err := h.svc.RegisterStart(r.Context(), req.Email)
	if err != nil {
		httpx.WriteInternal(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handler) registerFinish(w http.ResponseWriter, r *http.Request) {
	var req RegisterFinishRequest
	if err := httpx.DecodeStrict(w, r, &req); err != nil {
		httpx.WriteError(w, r, httpx.CodeInvalidRequest, "richiesta non valida")
		return
	}
	if err := h.svc.RegisterFinish(r.Context(), req); err != nil {
		if errors.Is(err, ErrBadInput) {
			httpx.WriteError(w, r, httpx.CodeInvalidRequest, "richiesta non valida")
			return
		}
		httpx.WriteInternal(w, r, err)
		return
	}
	httpx.WriteStatus(w, http.StatusCreated)
}

func (h *Handler) loginStart(w http.ResponseWriter, r *http.Request) {
	var req LoginStartRequest
	if err := httpx.DecodeStrict(w, r, &req); err != nil || req.Email == "" {
		httpx.WriteError(w, r, httpx.CodeInvalidRequest, "richiesta non valida")
		return
	}
	resp, err := h.svc.LoginStart(r.Context(), req.Email)
	if err != nil {
		httpx.WriteInternal(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handler) loginFinish(w http.ResponseWriter, r *http.Request) {
	var req LoginFinishRequest
	if err := httpx.DecodeStrict(w, r, &req); err != nil {
		httpx.WriteError(w, r, httpx.CodeInvalidRequest, "richiesta non valida")
		return
	}
	resp, ok, err := h.svc.LoginFinish(r.Context(), req)
	if err != nil {
		httpx.WriteInternal(w, r, err)
		return
	}
	if !ok {
		httpx.WriteError(w, r, httpx.CodeUnauthorized, "credenziali non valide")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handler) emailVerify(w http.ResponseWriter, r *http.Request) {
	var req EmailVerifyRequest
	if err := httpx.DecodeStrict(w, r, &req); err != nil || req.Token == "" {
		httpx.WriteError(w, r, httpx.CodeInvalidRequest, "richiesta non valida")
		return
	}
	ok, err := h.svc.VerifyEmail(r.Context(), req.Token)
	if err != nil {
		httpx.WriteInternal(w, r, err)
		return
	}
	if !ok {
		httpx.WriteError(w, r, httpx.CodeInvalidRequest, "token non valido o scaduto")
		return
	}
	httpx.WriteStatus(w, http.StatusOK)
}
