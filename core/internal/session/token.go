// Package session gestisce i token di sessione opachi (SR-31): generati dal CSPRNG del
// server, memorizzati solo come hash, revocabili. Niente JWT. La creazione e il lookup
// passano dalle funzioni SECURITY DEFINER (pre-auth), wrappate in internal/preauth.
package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// tokenBytes è l'entropia del token opaco (256 bit).
const tokenBytes = 32

// NewToken genera un token opaco (base64url) e il suo hash SHA-256 da memorizzare. Il token
// in chiaro va consegnato al client e non viene mai persistito.
func NewToken() (token string, hash []byte, err error) {
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("generazione token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	hash = HashToken(token)
	return token, hash, nil
}

// HashToken calcola l'hash di un token presentato, per il confronto in lookup (il token ha
// alta entropia: l'hash non invertibile è sufficiente, niente pepper, SR-31).
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}
