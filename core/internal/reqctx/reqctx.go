// Package reqctx trasporta nel context i valori per-richiesta condivisi tra middleware e
// handler: il request_id (tracciamento, doc 21) e, dopo l'autenticazione, l'account e la
// sessione correnti. Chiavi tipizzate e non esportate: nessuna collisione tra pacchetti.
package reqctx

import "context"

type ctxKey int

const (
	keyRequestID ctxKey = iota
	keyAccountID
	keySessionID
)

// WithRequestID/RequestID: identificativo di richiesta (in log ed errori).
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, keyRequestID, id)
}

func RequestID(ctx context.Context) string { return str(ctx, keyRequestID) }

// WithAccount/AccountID: account della sessione autenticata (per RLS e scoping).
func WithAccount(ctx context.Context, accountID string) context.Context {
	return context.WithValue(ctx, keyAccountID, accountID)
}

func AccountID(ctx context.Context) string { return str(ctx, keyAccountID) }

// WithSession/SessionID: sessione corrente (per revoca/logout).
func WithSession(ctx context.Context, sessionID string) context.Context {
	return context.WithValue(ctx, keySessionID, sessionID)
}

func SessionID(ctx context.Context) string { return str(ctx, keySessionID) }

func str(ctx context.Context, k ctxKey) string {
	if v, ok := ctx.Value(k).(string); ok {
		return v
	}
	return ""
}
