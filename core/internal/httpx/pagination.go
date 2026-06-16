package httpx

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
)

const (
	defaultLimit = 50
	maxLimit     = 200
)

// Limit estrae `?limit=` con clamp in [1, maxLimit] e default (doc 21: limite massimo
// imposto lato server). Valori non validi tornano al default.
func Limit(r *http.Request) int {
	v := r.URL.Query().Get("limit")
	if v == "" {
		return defaultLimit
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return defaultLimit
	}
	if n > maxLimit {
		return maxLimit
	}
	return n
}

// EncodeCursor rende opaco (base64url) il token interno del repo. Stringa vuota => nessun
// cursore (fine pagina).
func EncodeCursor(token string) string {
	if token == "" {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString([]byte(token))
}

// Cursor estrae e decodifica `?cursor=`; assente => stringa vuota. Malformato => errore
// (il chiamante risponde invalid_request).
func Cursor(r *http.Request) (string, error) {
	v := r.URL.Query().Get("cursor")
	if v == "" {
		return "", nil
	}
	b, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		return "", errors.New("cursore non valido")
	}
	return string(b), nil
}

// Page è la forma di risposta paginata a cursore (doc 21): {items, next_cursor}.
// next_cursor è null quando non ci sono altre pagine.
type Page[T any] struct {
	Items      []T     `json:"items"`
	NextCursor *string `json:"next_cursor"`
}

// NewPage costruisce una pagina; nextToken vuoto => next_cursor null.
func NewPage[T any](items []T, nextToken string) Page[T] {
	if items == nil {
		items = []T{}
	}
	var next *string
	if nextToken != "" {
		c := EncodeCursor(nextToken)
		next = &c
	}
	return Page[T]{Items: items, NextCursor: next}
}
