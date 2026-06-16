// Package httpx contiene il telaio HTTP condiviso: envelope d'errore, decodifica JSON
// stretta e paginazione a cursore (convenzioni doc 21). Gli errori verso l'esterno sono
// generici (niente dettagli interni, doc 18 §5); il dettaglio sta nei log.
package httpx

import (
	"log"
	"net/http"

	"kunuk.dev/core/internal/reqctx"
)

// ErrorCode è il codice stabile (snake_case) su cui i client fanno switch (doc 21).
type ErrorCode string

const (
	CodeInvalidRequest ErrorCode = "invalid_request"
	CodeUnauthorized   ErrorCode = "unauthorized"
	CodeForbidden      ErrorCode = "forbidden"
	CodeNotFound       ErrorCode = "not_found"
	CodeConflict       ErrorCode = "conflict"
	CodeTooEarly       ErrorCode = "too_early"
	CodeRateLimited    ErrorCode = "rate_limited"
	CodeInternal       ErrorCode = "internal"
)

// codeStatus mappa il codice sullo stato HTTP (doc 21).
var codeStatus = map[ErrorCode]int{
	CodeInvalidRequest: http.StatusBadRequest,
	CodeUnauthorized:   http.StatusUnauthorized,
	CodeForbidden:      http.StatusForbidden,
	CodeNotFound:       http.StatusNotFound,
	CodeConflict:       http.StatusConflict,
	CodeTooEarly:       http.StatusTooEarly,
	CodeRateLimited:    http.StatusTooManyRequests,
	CodeInternal:       http.StatusInternalServerError,
}

// Status restituisce lo stato HTTP per un codice (500 per codici sconosciuti).
func Status(code ErrorCode) int {
	if s, ok := codeStatus[code]; ok {
		return s
	}
	return http.StatusInternalServerError
}

type apiError struct {
	Code      ErrorCode `json:"code"`
	Message   string    `json:"message"`
	RequestID string    `json:"request_id"`
}

type errorEnvelope struct {
	Error apiError `json:"error"`
}

// WriteError scrive l'envelope d'errore `{"error":{code,message,request_id}}` con lo stato
// corrispondente. Il message è generico; il request_id viene dal context (middleware).
func WriteError(w http.ResponseWriter, r *http.Request, code ErrorCode, message string) {
	env := errorEnvelope{Error: apiError{
		Code:      code,
		Message:   message,
		RequestID: reqctx.RequestID(r.Context()),
	}}
	WriteJSON(w, Status(code), env)
}

// WriteInternal logga il dettaglio interno (ricco) ed emette un errore generico (anti
// information-disclosure, doc 18 §5).
func WriteInternal(w http.ResponseWriter, r *http.Request, internal error) {
	log.Printf("api: errore interno [request_id=%s]: %v", reqctx.RequestID(r.Context()), internal)
	WriteError(w, r, CodeInternal, "errore interno")
}
