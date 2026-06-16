package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgxpool"

	"kunuk.dev/core/internal/preauth"
	"kunuk.dev/core/internal/session"
)

// challengeTTL è la durata dello stato della cerimonia WebAuthn tra start e finish.
const challengeTTL = 5 * time.Minute

// ErrBadInput indica un input malformato (attestation/assertion non parsabile, handle assente).
var ErrBadInput = errors.New("input non valido")

// Service orchestra registrazione e login.
type Service struct {
	pool     *pgxpool.Pool
	sessions *session.Service
	wa       *webauthn.WebAuthn
	decoy    []byte
}

// NewService costruisce il servizio auth.
func NewService(pool *pgxpool.Pool, sessions *session.Service, wa *webauthn.WebAuthn, decoy []byte) *Service {
	return &Service{pool: pool, sessions: sessions, wa: wa, decoy: decoy}
}

// RegisterStart avvia la cerimonia passkey: opzioni di creazione + handle dello stato.
func (s *Service) RegisterStart(ctx context.Context, email string) (RegisterStartResponse, error) {
	uid, err := randomBytes(16)
	if err != nil {
		return RegisterStartResponse{}, err
	}
	user := &authUser{id: uid, name: email}
	creation, sd, err := s.wa.BeginRegistration(user)
	if err != nil {
		return RegisterStartResponse{}, fmt.Errorf("begin registration: %w", err)
	}
	handleStr, err := s.storeChallenge(ctx, sd)
	if err != nil {
		return RegisterStartResponse{}, err
	}
	return RegisterStartResponse{Handle: handleStr, WebAuthnCreationOptions: creation}, nil
}

// RegisterFinish crea l'account (passkey opzionale). Su email già presente NON distingue:
// stessa risposta di una registrazione nuova (anti-enum). Errori solo per input malformato.
func (s *Service) RegisterFinish(ctx context.Context, req RegisterFinishRequest) error {
	credID, credData, err := s.verifyAttestation(ctx, req)
	if err != nil {
		return err
	}
	pvHash := sha256.Sum256(req.PasswordVerifier)
	_, _, err = preauth.RegisterAccount(ctx, s.pool, preauth.RegisterParams{
		Email:                req.Email,
		PasswordVerifierHash: pvHash[:],
		KdfParamsJSON:        string(req.KdfParams),
		RecoveryPubkey:       req.RecoveryPubkey,
		PasswordWrapped:      req.PasswordEnvelope,
		PasskeyWrapped:       optional(req.PasskeyEnvelope),
		RecoveryWrapped:      req.RecoveryEnvelope,
		Manifest:             req.Manifest,
		ManifestPubkey:       req.ManifestPubkey,
		Signature:            req.Signature,
		WrappedSigningKey:    req.WrappedSigningKey,
		Version:              req.Version,
		CredentialID:         credID,
		CredentialDataJSON:   credData,
	})
	// created=false (email esistente) → stessa risposta; l'invio email di verifica è del
	// modulo email (rinviato): l'account è 'active' subito (non blocca il gate 0.10).
	return err
}

// verifyAttestation verifica l'attestazione passkey se presente e ne ricava (credential_id,
// data da memorizzare). Senza attestazione → registrazione solo-password.
func (s *Service) verifyAttestation(ctx context.Context, req RegisterFinishRequest) ([]byte, *string, error) {
	if len(req.PasskeyAttestation) == 0 {
		return nil, nil, nil
	}
	sd, ok, err := s.consumeChallenge(ctx, req.Handle)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return nil, nil, ErrBadInput
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(req.PasskeyAttestation)
	if err != nil {
		return nil, nil, ErrBadInput
	}
	user := &authUser{id: sd.UserID, name: req.Email}
	cred, err := s.wa.CreateCredential(user, sd, parsed)
	if err != nil {
		return nil, nil, ErrBadInput
	}
	data, err := json.Marshal(storedCredential{UserHandle: sd.UserID, Credential: *cred})
	if err != nil {
		return nil, nil, fmt.Errorf("marshal credential: %w", err)
	}
	str := string(data)
	return cred.ID, &str, nil
}

// LoginStart restituisce opzioni WebAuthn + kdf_params, di forma identica per email reale o no.
func (s *Service) LoginStart(ctx context.Context, email string) (LoginStartResponse, error) {
	mat, found, err := preauth.GetLoginMaterial(ctx, s.pool, email)
	if err != nil {
		return LoginStartResponse{}, err
	}
	user, kdf := s.loginUser(email, mat, found)
	assertion, sd, err := s.wa.BeginLogin(user)
	if err != nil {
		return LoginStartResponse{}, fmt.Errorf("begin login: %w", err)
	}
	handleStr, err := s.storeChallenge(ctx, sd)
	if err != nil {
		return LoginStartResponse{}, err
	}
	return LoginStartResponse{Handle: handleStr, WebAuthnRequestOptions: assertion, KdfParams: kdf}, nil
}

// loginUser costruisce l'utente per BeginLogin: credenziali reali se l'account esiste e ha
// passkey, altrimenti un decoy plausibile (account inesistente o solo-password).
func (s *Service) loginUser(email string, mat preauth.LoginMaterial, found bool) (*authUser, json.RawMessage) {
	if !found {
		return decoyUser(s.decoy, email), decoyKdfParams(s.decoy, email)
	}
	creds, handle := parseStoredCredentials(mat.CredentialsJSON)
	if len(creds) == 0 {
		return decoyUser(s.decoy, email), json.RawMessage(mat.KdfParamsJSON)
	}
	return &authUser{id: handle, name: email, creds: creds}, json.RawMessage(mat.KdfParamsJSON)
}

// LoginFinish completa il login (passkey o password) ed emette il token. ok=false → 401
// uniforme (nessuna distinzione tra email ignota, assertion fallita o verificatore errato).
func (s *Service) LoginFinish(ctx context.Context, req LoginFinishRequest) (LoginFinishResponse, bool, error) {
	mat, found, err := preauth.GetLoginMaterial(ctx, s.pool, req.Email)
	if err != nil {
		return LoginFinishResponse{}, false, err
	}
	accountID, ok, err := s.authenticate(ctx, req, mat, found)
	if err != nil || !ok {
		return LoginFinishResponse{}, false, err
	}
	token, exp, err := s.sessions.Issue(ctx, accountID)
	if err != nil {
		return LoginFinishResponse{}, false, err
	}
	return LoginFinishResponse{SessionToken: token, ExpiresAt: exp}, true, nil
}

// authenticate verifica la credenziale (passkey o password) e ritorna l'account su successo.
func (s *Service) authenticate(ctx context.Context, req LoginFinishRequest, mat preauth.LoginMaterial, found bool) (string, bool, error) {
	if len(req.PasskeyAssertion) > 0 {
		return s.verifyAssertion(ctx, req, mat, found)
	}
	// Via password: confronto a tempo costante (anche sul ramo decoy, per non accorciare i tempi).
	presented := sha256.Sum256(req.PasswordVerifier)
	target := mat.PasswordVerifierHash
	if !found {
		target = decoyVerifierHash(s.decoy, req.Email)
	}
	if subtle.ConstantTimeCompare(presented[:], target) != 1 || !found {
		return "", false, nil
	}
	return mat.AccountID, true, nil
}

// verifyAssertion verifica un'assertion passkey. Consuma sempre il challenge (one-shot).
func (s *Service) verifyAssertion(ctx context.Context, req LoginFinishRequest, mat preauth.LoginMaterial, found bool) (string, bool, error) {
	sd, ok, err := s.consumeChallenge(ctx, req.Handle)
	if err != nil {
		return "", false, err
	}
	if !ok {
		return "", false, nil
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(req.PasskeyAssertion)
	if err != nil {
		return "", false, nil
	}
	user, _ := s.loginUser(req.Email, mat, found)
	if _, err := s.wa.ValidateLogin(user, sd, parsed); err != nil || !found {
		return "", false, nil
	}
	return mat.AccountID, true, nil
}

// VerifyEmail consuma un token di verifica email (il modulo email lo creerà/invierà).
func (s *Service) VerifyEmail(ctx context.Context, token string) (bool, error) {
	return preauth.VerifyEmail(ctx, s.pool, session.HashToken(token))
}

// ── helper su challenge/credenziali ────────────────────────────────────────────
func (s *Service) storeChallenge(ctx context.Context, sd *webauthn.SessionData) (string, error) {
	handleStr, handleBytes, err := newHandle()
	if err != nil {
		return "", err
	}
	sdJSON, err := json.Marshal(sd)
	if err != nil {
		return "", fmt.Errorf("marshal session data: %w", err)
	}
	if err := preauth.ChallengeStore(ctx, s.pool, handleBytes, string(sdJSON), time.Now().Add(challengeTTL)); err != nil {
		return "", err
	}
	return handleStr, nil
}

func (s *Service) consumeChallenge(ctx context.Context, handle string) (webauthn.SessionData, bool, error) {
	handleBytes, err := decodeHandle(handle)
	if err != nil {
		return webauthn.SessionData{}, false, nil
	}
	data, found, err := preauth.ChallengeConsume(ctx, s.pool, handleBytes)
	if err != nil || !found {
		return webauthn.SessionData{}, false, err
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal(data, &sd); err != nil {
		return webauthn.SessionData{}, false, fmt.Errorf("unmarshal session data: %w", err)
	}
	return sd, true, nil
}

// parseStoredCredentials ricostruisce le credenziali e l'handle utente dal JSON di login_material.
func parseStoredCredentials(raw []byte) ([]webauthn.Credential, []byte) {
	var rows []struct {
		Data storedCredential `json:"data"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, nil
	}
	var creds []webauthn.Credential
	var handle []byte
	for _, r := range rows {
		creds = append(creds, r.Data.Credential)
		handle = r.Data.UserHandle
	}
	return creds, handle
}

// optional ritorna nil per uno slice vuoto (campo opzionale → NULL nel DB).
func optional(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}
