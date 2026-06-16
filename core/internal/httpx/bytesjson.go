package httpx

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Bytes serializza/deserializza []byte come base64url **senza padding** sul filo JSON
// (doc 16 §1, doc 21): è l'encoding dei campi binari (ciphertext, buste, firme). Si usa nei
// DTO al posto di []byte, che `encoding/json` renderebbe in base64 standard con padding.
type Bytes []byte

// MarshalJSON emette la stringa base64url.
func (b Bytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.RawURLEncoding.EncodeToString(b))
}

// UnmarshalJSON accetta una stringa base64url; input malformato → errore (il chiamante
// risponde invalid_request).
func (b *Bytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	decoded, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return fmt.Errorf("base64url non valido: %w", err)
	}
	*b = decoded
	return nil
}
