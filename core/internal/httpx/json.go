package httpx

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
)

// maxBodyBytes limita la dimensione del corpo richiesta (anti-abuso; i payload sono piccoli,
// ciphertext di voci singole).
const maxBodyBytes = 1 << 20 // 1 MiB

// ErrBadJSON indica un corpo JSON malformato o con campi non previsti (DTO strict).
var ErrBadJSON = errors.New("corpo JSON non valido")

// DecodeStrict decodifica il corpo in dst rifiutando campi sconosciuti (mass-assignment,
// doc 18 §3) e dati in eccesso dopo il primo valore. Errore => il chiamante risponde
// invalid_request.
func DecodeStrict(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return errors.Join(ErrBadJSON, err)
	}
	if dec.More() {
		return errors.Join(ErrBadJSON, errors.New("dati in eccesso dopo il valore JSON"))
	}
	return nil
}

// WriteJSON serializza v con lo stato dato. Un fallimento di scrittura (header già inviati)
// si può solo loggare.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("api: scrittura della risposta JSON fallita: %v", err)
	}
}

// WriteStatus risponde con il solo stato (es. 204), senza corpo.
func WriteStatus(w http.ResponseWriter, status int) {
	w.WriteHeader(status)
}
