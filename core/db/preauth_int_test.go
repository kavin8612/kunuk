package db_test

// Test d'integrazione delle funzioni SECURITY DEFINER pre-auth (migrazione 00002), su
// Postgres reale (riusa l'harness di rls_test.go). Verifica i percorsi che la RLS bloccherebbe
// (nessun account in sessione): registrazione (con anti-enum su email duplicata), materiale
// di login, sessione, verifica email, challenge WebAuthn one-shot.

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	appdb "kunuk.dev/core/db"
	"kunuk.dev/core/internal/preauth"
	"kunuk.dev/core/internal/session"
)

func ptr(s string) *string { return &s }

func sampleRegister(email string) preauth.RegisterParams {
	dummy := []byte{0x01, 0x02, 0x03}
	// UUID scelti dal client, deterministici e unici per email (doc 16 §3-6, ADR-0020).
	return preauth.RegisterParams{
		AccountID:            uuid.NewSHA1(uuid.NameSpaceURL, []byte("kunuk-account:"+email)).String(),
		VaultID:              uuid.NewSHA1(uuid.NameSpaceURL, []byte("kunuk-vault:"+email)).String(),
		Email:                email,
		PasswordVerifierHash: dummy,
		KdfParamsJSON:        `{"memory_kib":65536,"iterations":3,"parallelism":4}`,
		RecoveryPubkey:       dummy,
		PasswordWrapped:      dummy,
		PasskeyWrapped:       dummy,
		RecoveryWrapped:      dummy,
		Manifest:             dummy,
		ManifestPubkey:       dummy,
		Signature:            dummy,
		WrappedSigningKey:    dummy,
		Version:              1,
		CredentialID:         []byte("cred-id-" + email), // unico per account (UNIQUE in DB)
		CredentialDataJSON:   ptr(`{"public_key":"AAAA"}`),
	}
}

// setupPreauth avvia Postgres, applica le migrazioni e restituisce il pool kunuk_app + la
// connessione superuser (per seminare dati bypassando la RLS).
func setupPreauth(ctx context.Context, t *testing.T) (*pgxpool.Pool, *sql.DB) {
	t.Helper()
	dsn := startPostgres(ctx, t)
	super := open(ctx, t, dsn(superUsr, superPw))
	bootstrapRoles(ctx, t, super)
	mig := open(ctx, t, dsn(migUser, migPw))
	if err := appdb.Apply(ctx, mig); err != nil {
		t.Fatalf("applicazione migrazioni: %v", err)
	}
	pool, err := pgxpool.New(ctx, dsn(appUser, appPw))
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool, super
}

func mustRegister(ctx context.Context, t *testing.T, pool *pgxpool.Pool, email string) string {
	t.Helper()
	id, created, err := preauth.RegisterAccount(ctx, pool, sampleRegister(email))
	if err != nil {
		t.Fatalf("RegisterAccount: %v", err)
	}
	if !created || id == "" {
		t.Fatalf("RegisterAccount: created=%v id=%q", created, id)
	}
	return id
}

func TestPreauthRegisterAntiEnum(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	pool, _ := setupPreauth(ctx, t)

	id := mustRegister(ctx, t, pool, "a@example.com")
	// Email duplicata → created=false (stessa risposta, anti-enumeration).
	_, created, err := preauth.RegisterAccount(ctx, pool, sampleRegister("a@example.com"))
	if err != nil {
		t.Fatalf("RegisterAccount duplicato: %v", err)
	}
	if created {
		t.Fatal("email duplicata doveva dare created=false")
	}

	// login_material trova l'esistente, non l'inesistente.
	m, found, err := preauth.GetLoginMaterial(ctx, pool, "a@example.com")
	if err != nil || !found {
		t.Fatalf("GetLoginMaterial esistente: found=%v err=%v", found, err)
	}
	if m.AccountID != id {
		t.Fatalf("account_id atteso %q, ottenuto %q", id, m.AccountID)
	}
	_, found, err = preauth.GetLoginMaterial(ctx, pool, "nessuno@example.com")
	if err != nil {
		t.Fatalf("GetLoginMaterial inesistente: %v", err)
	}
	if found {
		t.Fatal("email inesistente doveva dare found=false")
	}
}

func TestPreauthSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	pool, _ := setupPreauth(ctx, t)
	id := mustRegister(ctx, t, pool, "s@example.com")

	_, hash, err := session.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	sid, err := preauth.SessionCreate(ctx, pool, id, hash, time.Now().Add(time.Hour))
	if err != nil || sid == "" {
		t.Fatalf("SessionCreate: sid=%q err=%v", sid, err)
	}
	acc, sid2, ok, err := preauth.SessionLookup(ctx, pool, hash)
	if err != nil || !ok {
		t.Fatalf("SessionLookup: ok=%v err=%v", ok, err)
	}
	if acc != id || sid2 != sid {
		t.Fatalf("SessionLookup: acc=%q sid=%q (attesi %q/%q)", acc, sid2, id, sid)
	}
}

func TestPreauthVerifyEmailAndChallenge(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	pool, super := setupPreauth(ctx, t)
	id := mustRegister(ctx, t, pool, "v@example.com")

	// verify_email: semino un token come superuser (bypassa RLS) e lo consumo.
	emailTokenHash := session.HashToken("email-token-xyz")
	if _, err := super.ExecContext(ctx,
		`INSERT INTO email_verification_token (account_id, token_hash, expires_at) VALUES ($1, $2, now() + interval '1 hour')`,
		id, emailTokenHash); err != nil {
		t.Fatalf("seed token email: %v", err)
	}
	okv, err := preauth.VerifyEmail(ctx, pool, emailTokenHash)
	if err != nil || !okv {
		t.Fatalf("VerifyEmail: ok=%v err=%v", okv, err)
	}

	// webauthn_challenge: store + consume one-shot.
	handle := []byte("0123456789abcdef0123456789abcdef")
	if err := preauth.ChallengeStore(ctx, pool, handle, `{"challenge":"abc"}`, time.Now().Add(5*time.Minute)); err != nil {
		t.Fatalf("ChallengeStore: %v", err)
	}
	data, found, err := preauth.ChallengeConsume(ctx, pool, handle)
	if err != nil || !found {
		t.Fatalf("ChallengeConsume: found=%v err=%v", found, err)
	}
	if !strings.Contains(string(data), "challenge") {
		t.Fatalf("session_data inattesa: %s", data)
	}
	_, found, err = preauth.ChallengeConsume(ctx, pool, handle)
	if err != nil {
		t.Fatalf("ChallengeConsume secondo: %v", err)
	}
	if found {
		t.Fatal("ChallengeConsume doveva essere one-shot")
	}
}
