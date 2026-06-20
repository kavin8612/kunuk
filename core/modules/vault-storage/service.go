package vaultstorage

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"kunuk.dev/core/db"
)

// Errori del dominio, mappati su codici HTTP dal handler.
var (
	ErrNotFound        = errors.New("non trovato")
	ErrVersionConflict = errors.New("conflitto di versione")
	ErrInvalidEnvelope = errors.New("tipo busta non valido")
	ErrItemExists      = errors.New("item già esistente")
)

// validEnvelopeTypes sono i tipi sostituibili via API (la passkey si imposta in registrazione).
var validEnvelopeTypes = map[string]bool{"password": true, "recovery": true}

// Service orchestra lo storage del vault, ogni operazione sotto lo scope RLS dell'account.
type Service struct {
	pool *pgxpool.Pool
}

// NewService costruisce il servizio sul pool del ruolo applicativo.
func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

func (s *Service) tx(ctx context.Context, accountID string, fn func(pgx.Tx) error) error {
	return db.WithAccountTx(ctx, s.pool, accountID, fn)
}

// ListEnvelopes restituisce le buste della VK dell'account.
func (s *Service) ListEnvelopes(ctx context.Context, accountID string) ([]Envelope, error) {
	var out []Envelope
	err := s.tx(ctx, accountID, func(t pgx.Tx) error {
		var e error
		out, e = listEnvelopes(ctx, t)
		return e
	})
	return out, err
}

// ReplaceEnvelope sostituisce la busta del tipo dato (password|recovery). ErrNotFound se la
// busta non esiste (dev'essere stata creata alla registrazione).
func (s *Service) ReplaceEnvelope(ctx context.Context, accountID, typ string, in EnvelopeInput) error {
	if !validEnvelopeTypes[typ] {
		return ErrInvalidEnvelope
	}
	var params *string
	if len(in.Params) > 0 {
		p := string(in.Params)
		params = &p
	}
	return s.tx(ctx, accountID, func(t pgx.Tx) error {
		n, e := updateEnvelope(ctx, t, typ, in.WrappedVK, params)
		if e != nil {
			return e
		}
		if n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// GetVault restituisce il manifest firmato del vault.
func (s *Service) GetVault(ctx context.Context, accountID string) (VaultManifest, error) {
	var v VaultManifest
	err := s.tx(ctx, accountID, func(t pgx.Tx) error {
		var e error
		v, e = getVault(ctx, t)
		return e
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return VaultManifest{}, ErrNotFound
	}
	return v, err
}

// UpdateManifest applica il nuovo manifest (versione strettamente crescente). ErrVersionConflict
// se la versione non è maggiore (anti-rollback).
func (s *Service) UpdateManifest(ctx context.Context, accountID string, in ManifestInput) error {
	return s.tx(ctx, accountID, func(t pgx.Tx) error {
		n, e := updateManifest(ctx, t, in.Manifest, in.Signature, in.Version)
		if e != nil {
			return e
		}
		if n == 0 {
			return ErrVersionConflict
		}
		return nil
	})
}

// ListItems pagina gli item (cursore opaco su updated_at,id).
func (s *Service) ListItems(ctx context.Context, accountID string, cur *cursor, limit int) ([]Item, error) {
	var out []Item
	err := s.tx(ctx, accountID, func(t pgx.Tx) error {
		var e error
		out, e = listItems(ctx, t, cur, limit)
		return e
	})
	return out, err
}

// CreateItem crea un item nel vault dell'account. Se in.ID è valorizzato (UUID scelto dal
// client per legare l'AAD, doc 16 §5) lo usa come id; altrimenti lo genera il server.
func (s *Service) CreateItem(ctx context.Context, accountID string, in ItemInput) (Item, error) {
	var it Item
	err := s.tx(ctx, accountID, func(t pgx.Tx) error {
		var e error
		it, e = insertItem(ctx, t, in.ID, in.Ciphertext, in.WrappedCEK)
		return e
	})
	return it, err
}

// GetItem restituisce un item per id (RLS: un id altrui non è visibile → ErrNotFound).
func (s *Service) GetItem(ctx context.Context, accountID, id string) (Item, error) {
	var it Item
	err := s.tx(ctx, accountID, func(t pgx.Tx) error {
		var e error
		it, e = getItem(ctx, t, id)
		return e
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Item{}, ErrNotFound
	}
	return it, err
}

// UpdateItem sostituisce ciphertext/CEK di un item. ErrNotFound se l'id non è dell'account.
func (s *Service) UpdateItem(ctx context.Context, accountID, id string, in ItemInput) error {
	return s.tx(ctx, accountID, func(t pgx.Tx) error {
		n, e := updateItem(ctx, t, id, in.Ciphertext, in.WrappedCEK)
		if e != nil {
			return e
		}
		if n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// DeleteItem applica il tombstone a un item. ErrNotFound se l'id non è dell'account.
func (s *Service) DeleteItem(ctx context.Context, accountID, id string) error {
	return s.tx(ctx, accountID, func(t pgx.Tx) error {
		n, e := deleteItem(ctx, t, id)
		if e != nil {
			return e
		}
		if n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// parseCursor decodifica il token opaco "updated_at|id" in un cursore. Vuoto → nil (prima
// pagina). Malformato → errore.
func parseCursor(token string) (*cursor, error) {
	if token == "" {
		return nil, nil
	}
	tsStr, id, ok := strings.Cut(token, "|")
	if !ok || id == "" {
		return nil, errors.New("cursore non valido")
	}
	ts, err := time.Parse(time.RFC3339Nano, tsStr)
	if err != nil {
		return nil, errors.New("cursore non valido")
	}
	return &cursor{updatedAt: ts, id: id}, nil
}

// encodeCursor produce il token "updated_at|id" dell'ultimo item (poi reso opaco dall'handler).
func encodeCursor(it Item) string {
	return it.UpdatedAt.UTC().Format(time.RFC3339Nano) + "|" + it.ID
}
