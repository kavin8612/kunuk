package session

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"kunuk.dev/core/internal/preauth"
)

// Service emette e convalida le sessioni. Usa le funzioni SECURITY DEFINER (pre-auth) via
// preauth: la creazione/lookup avvengono prima che ci sia un account in sessione.
type Service struct {
	q   preauth.Querier
	ttl time.Duration
}

// NewService costruisce il servizio sessioni con la durata configurata (KUNUK_SESSION_TTL).
func NewService(q preauth.Querier, ttl time.Duration) *Service {
	return &Service{q: q, ttl: ttl}
}

// Issue crea una sessione per accountID e restituisce il token opaco (da consegnare al
// client) e la scadenza. Del token si memorizza solo l'hash.
func (s *Service) Issue(ctx context.Context, accountID string) (token string, expiresAt time.Time, err error) {
	token, hash, err := NewToken()
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt = time.Now().Add(s.ttl)
	if _, err := preauth.SessionCreate(ctx, s.q, accountID, hash, expiresAt); err != nil {
		return "", time.Time{}, err
	}
	return token, expiresAt, nil
}

// Authenticate convalida un token Bearer e restituisce account e sessione. ok=false se il
// token è assente, scaduto o revocato (il chiamante risponde 401 uniforme).
func (s *Service) Authenticate(ctx context.Context, token string) (accountID, sessionID string, ok bool, err error) {
	if token == "" {
		return "", "", false, nil
	}
	return preauth.SessionLookup(ctx, s.q, HashToken(token))
}

// RevokeAllForAccount revoca tutte le sessioni dell'account corrente (sotto RLS, dentro una
// WithAccountTx). Lo useranno i futuri cambio password/email; esposto già ora.
func RevokeAllForAccount(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `UPDATE session SET revoked = true WHERE account_id = current_account_id()`); err != nil {
		return fmt.Errorf("revoca sessioni: %w", err)
	}
	return nil
}
