// Package preauth incapsula le chiamate alle funzioni SECURITY DEFINER del DB usate nei
// flussi PRE-autenticazione (registrazione, login, verifica email, sessione, challenge
// WebAuthn): in quel momento non c'è ancora un account in sessione, quindi non si passa da
// kunuk_app con RLS aperta (schema §RLS, SR-32). Tutte le query sono parametrizzate (SR-30).
package preauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Querier è il minimo comune di pgxpool.Pool / pgx.Conn usato qui (nessuna transazione: le
// funzioni definer sono atomiche per conto loro).
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// RegisterParams sono i campi del RegistrationBundle persistiti al server (tutti opachi:
// ciphertext/verificatori). I campi JSONB arrivano come testo JSON (cast `::jsonb` in SQL).
type RegisterParams struct {
	Email                string
	PasswordVerifierHash []byte
	KdfParamsJSON        string
	RecoveryPubkey       []byte
	PasswordWrapped      []byte
	PasskeyWrapped       []byte // nil se l'utente non registra una passkey
	RecoveryWrapped      []byte
	Manifest             []byte
	ManifestPubkey       []byte
	Signature            []byte
	WrappedSigningKey    []byte
	Version              int
	CredentialID         []byte  // nil se nessuna passkey
	CredentialDataJSON   *string // nil se nessuna passkey
}

const registerSQL = `SELECT register_account(
    $1::citext, $2, $3::jsonb, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::jsonb)`

// RegisterAccount crea account+buste+vault+credenziale in modo atomico. created=false se
// l'email è già registrata (anti-enumeration: nessun errore distinguibile, il chiamante
// risponde identico a una registrazione nuova).
func RegisterAccount(ctx context.Context, q Querier, p RegisterParams) (accountID string, created bool, err error) {
	var id *string
	err = q.QueryRow(ctx, registerSQL,
		p.Email, p.PasswordVerifierHash, p.KdfParamsJSON, p.RecoveryPubkey,
		p.PasswordWrapped, p.PasskeyWrapped, p.RecoveryWrapped,
		p.Manifest, p.ManifestPubkey, p.Signature, p.WrappedSigningKey, p.Version,
		p.CredentialID, p.CredentialDataJSON,
	).Scan(&id)
	if err != nil {
		return "", false, fmt.Errorf("register_account: %w", err)
	}
	if id == nil {
		return "", false, nil // email già presente
	}
	return *id, true, nil
}

// LoginMaterial è il materiale per il login di un'email (verificatore hashato, kdf, credenziali
// WebAuthn). found=false se l'email non esiste (il chiamante genera un decoy, anti-enum).
type LoginMaterial struct {
	AccountID            string
	PasswordVerifierHash []byte
	KdfParamsJSON        []byte
	CredentialsJSON      []byte
}

const loginMaterialSQL = `SELECT account_id, password_verifier, kdf_params, credentials FROM login_material($1::citext)`

func GetLoginMaterial(ctx context.Context, q Querier, email string) (LoginMaterial, bool, error) {
	rows, err := q.Query(ctx, loginMaterialSQL, email)
	if err != nil {
		return LoginMaterial{}, false, fmt.Errorf("login_material: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return LoginMaterial{}, false, rows.Err()
	}
	var m LoginMaterial
	if err := rows.Scan(&m.AccountID, &m.PasswordVerifierHash, &m.KdfParamsJSON, &m.CredentialsJSON); err != nil {
		return LoginMaterial{}, false, fmt.Errorf("scan login_material: %w", err)
	}
	return m, true, nil
}

// SessionCreate registra una sessione (token già hashato) e ritorna l'id sessione.
func SessionCreate(ctx context.Context, q Querier, accountID string, tokenHash []byte, expiresAt time.Time) (string, error) {
	var id string
	if err := q.QueryRow(ctx, `SELECT session_create($1, $2, $3)`, accountID, tokenHash, expiresAt).Scan(&id); err != nil {
		return "", fmt.Errorf("session_create: %w", err)
	}
	return id, nil
}

// SessionLookup convalida un token (per richiesta). found=false se assente/scaduto/revocato.
func SessionLookup(ctx context.Context, q Querier, tokenHash []byte) (accountID, sessionID string, found bool, err error) {
	rows, err := q.Query(ctx, `SELECT account_id, session_id FROM session_lookup($1)`, tokenHash)
	if err != nil {
		return "", "", false, fmt.Errorf("session_lookup: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return "", "", false, rows.Err()
	}
	if err := rows.Scan(&accountID, &sessionID); err != nil {
		return "", "", false, fmt.Errorf("scan session_lookup: %w", err)
	}
	return accountID, sessionID, true, nil
}

// VerifyEmail consuma un token di verifica e attiva l'account. ok=false se non valido.
func VerifyEmail(ctx context.Context, q Querier, tokenHash []byte) (bool, error) {
	var ok bool
	if err := q.QueryRow(ctx, `SELECT verify_email($1)`, tokenHash).Scan(&ok); err != nil {
		return false, fmt.Errorf("verify_email: %w", err)
	}
	return ok, nil
}

// ChallengeStore salva lo stato della cerimonia WebAuthn sotto un handle opaco.
func ChallengeStore(ctx context.Context, q Querier, handle []byte, sessionDataJSON string, expiresAt time.Time) error {
	if _, err := q.Exec(ctx, `SELECT webauthn_challenge_store($1, $2::jsonb, $3)`, handle, sessionDataJSON, expiresAt); err != nil {
		return fmt.Errorf("webauthn_challenge_store: %w", err)
	}
	return nil
}

// ChallengeConsume legge e cancella lo stato della cerimonia (one-shot). found=false se
// l'handle è assente o scaduto.
func ChallengeConsume(ctx context.Context, q Querier, handle []byte) (sessionDataJSON []byte, found bool, err error) {
	var data []byte
	if err := q.QueryRow(ctx, `SELECT webauthn_challenge_consume($1)`, handle).Scan(&data); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("webauthn_challenge_consume: %w", err)
	}
	if data == nil {
		return nil, false, nil
	}
	return data, true, nil
}
