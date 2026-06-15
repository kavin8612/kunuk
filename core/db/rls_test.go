package db_test

// Test di isolamento multi-tenant (SR-30/SR-32, doc 18 §9, doc 19 §6): Postgres reale
// effimero (testcontainers), migrazioni applicate come kunuk_migrations, poi verifiche di
// Row-Level Security come kunuk_app. Sono i test negativi obbligatori "A non legge/scrive i
// dati di B" (anti-IDOR): se passassero senza isolamento, sarebbe un bug di sicurezza.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	appdb "kunuk.dev/core/db"
)

// Credenziali del solo DB effimero di test (nessun segreto reale).
const (
	pgImage  = "postgres:18.4-alpine"
	dbName   = "kunuk"
	superPw  = "super-test-pw" //nolint:gosec // password del container di test
	migPw    = "migr-test-pw"  //nolint:gosec // password del container di test
	appPw    = "app-test-pw"   //nolint:gosec // password del container di test
	migUser  = "kunuk_migrations"
	appUser  = "kunuk_app"
	superUsr = "postgres"
)

// startPostgres avvia un Postgres effimero e restituisce un costruttore di DSN per ruolo.
func startPostgres(ctx context.Context, t *testing.T) func(user, pw string) string {
	t.Helper()
	ctr, err := tcpostgres.Run(ctx, pgImage,
		tcpostgres.WithDatabase(dbName),
		tcpostgres.WithUsername(superUsr),
		tcpostgres.WithPassword(superPw),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("avvio Postgres effimero (Docker attivo?): %v", err)
	}
	t.Cleanup(func() {
		if err := testcontainers.TerminateContainer(ctr); err != nil {
			t.Logf("terminazione container: %v", err)
		}
	})

	host, err := ctr.Host(ctx)
	if err != nil {
		t.Fatalf("host del container: %v", err)
	}
	port, err := ctr.MappedPort(ctx, "5432/tcp")
	if err != nil {
		t.Fatalf("porta del container: %v", err)
	}
	return func(user, pw string) string {
		return fmt.Sprintf("host=%s port=%s dbname=%s user=%s password=%s sslmode=disable",
			host, port.Port(), dbName, user, pw)
	}
}

// open apre una connessione e la chiude a fine test.
func open(ctx context.Context, t *testing.T, dsn string) *sql.DB {
	t.Helper()
	conn, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("apertura connessione: %v", err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Logf("chiusura connessione: %v", err)
		}
	})
	if err := conn.PingContext(ctx); err != nil {
		t.Fatalf("ping DB: %v", err)
	}
	return conn
}

// bootstrapRoles replica l'init (scripts/db/init/01-roles.sh) come superuser: estensioni,
// ruoli a privilegio minimo e proprietà dello schema al ruolo migrazioni.
func bootstrapRoles(ctx context.Context, t *testing.T, super *sql.DB) {
	t.Helper()
	stmts := []string{
		`CREATE EXTENSION IF NOT EXISTS pgcrypto`,
		`CREATE EXTENSION IF NOT EXISTS citext`,
		`CREATE ROLE ` + migUser + ` LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD '` + migPw + `'`, //nolint:gosec // DB di test
		`CREATE ROLE ` + appUser + ` LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD '` + appPw + `'`, //nolint:gosec // DB di test
		`GRANT CONNECT ON DATABASE ` + dbName + ` TO ` + migUser + `, ` + appUser,
		`ALTER SCHEMA public OWNER TO ` + migUser,
	}
	for _, s := range stmts {
		if _, err := super.ExecContext(ctx, s); err != nil {
			t.Fatalf("bootstrap ruoli (%q): %v", s, err)
		}
	}
}

// seed inserisce due account A e B con vault, item ed envelope, come superuser (bypassa la
// RLS). Restituisce (accountID, itemID) per A e per B.
type tenant struct {
	accountID string
	itemID    string
}

func seed(ctx context.Context, t *testing.T, super *sql.DB, email string) tenant {
	t.Helper()
	var acc, vault, item string
	dummy := []byte{0x01, 0x02, 0x03}
	if err := super.QueryRowContext(ctx,
		`INSERT INTO account (email, password_verifier, kdf_params, recovery_pubkey)
		 VALUES ($1, $2, '{}'::jsonb, $3) RETURNING id`,
		email, dummy, dummy,
	).Scan(&acc); err != nil {
		t.Fatalf("seed account: %v", err)
	}
	if err := super.QueryRowContext(ctx,
		`INSERT INTO vault (account_id, manifest, manifest_pubkey, signature, wrapped_signing_key)
		 VALUES ($1, $2, $2, $2, $2) RETURNING id`,
		acc, dummy,
	).Scan(&vault); err != nil {
		t.Fatalf("seed vault: %v", err)
	}
	if err := super.QueryRowContext(ctx,
		`INSERT INTO item (vault_id, ciphertext, wrapped_cek) VALUES ($1, $2, $2) RETURNING id`,
		vault, dummy,
	).Scan(&item); err != nil {
		t.Fatalf("seed item: %v", err)
	}
	if _, err := super.ExecContext(ctx,
		`INSERT INTO envelope (account_id, type, wrapped_vk) VALUES ($1, 'password', $2)`,
		acc, dummy,
	); err != nil {
		t.Fatalf("seed envelope: %v", err)
	}
	return tenant{accountID: acc, itemID: item}
}

// inTx esegue fn dentro una transazione con app.account_id impostato (transaction-local) al
// valore dato; account vuoto = sessione senza account (current_account_id NULL). Rollback a
// fine: i test non persistono effetti collaterali.
func inTx(ctx context.Context, t *testing.T, conn *sql.DB, account string, fn func(tx *sql.Tx)) {
	t.Helper()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("apertura transazione: %v", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			t.Logf("rollback: %v", err)
		}
	}()
	// set_config(..., true) = SET LOCAL parametrizzato (niente concatenazione, SR-30).
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.account_id', $1, true)`, account); err != nil {
		t.Fatalf("set app.account_id: %v", err)
	}
	fn(tx)
}

func countItems(ctx context.Context, t *testing.T, tx *sql.Tx) int {
	t.Helper()
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM item`).Scan(&n); err != nil {
		t.Fatalf("count item: %v", err)
	}
	return n
}

func TestRLSIsolation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	dsn := startPostgres(ctx, t)
	super := open(ctx, t, dsn(superUsr, superPw))
	bootstrapRoles(ctx, t, super)

	// Migrazioni come kunuk_migrations; ri-applicarle dev'essere idempotente.
	mig := open(ctx, t, dsn(migUser, migPw))
	if err := appdb.Apply(ctx, mig); err != nil {
		t.Fatalf("applicazione migrazioni: %v", err)
	}
	if err := appdb.Apply(ctx, mig); err != nil {
		t.Fatalf("migrazioni non idempotenti (seconda applicazione): %v", err)
	}

	a := seed(ctx, t, super, "a@example.com")
	b := seed(ctx, t, super, "b@example.com")
	app := open(ctx, t, dsn(appUser, appPw))

	t.Run("A vede solo i propri item", func(t *testing.T) { assertAOnlySeesOwn(ctx, t, app, a, b) })
	t.Run("A non può modificare l'item di B (IDOR)", func(t *testing.T) { assertACannotUpdateB(ctx, t, app, a, b) })
	t.Run("A non può cancellare l'item di B (IDOR)", func(t *testing.T) { assertACannotDeleteB(ctx, t, app, a, b) })
	t.Run("senza account non si vede nulla (fail-closed)", func(t *testing.T) { assertNoAccountNoRows(ctx, t, app) })
	t.Run("kunuk_app non può fare DDL", func(t *testing.T) { assertNoDDL(ctx, t, app) })
	t.Run("kunuk_app non ha BYPASSRLS", func(t *testing.T) { assertNoBypassRLS(ctx, t, app) })
}

// expectZeroRows verifica che una scrittura come A non tocchi righe di B (anti-IDOR).
func expectZeroRows(ctx context.Context, t *testing.T, app *sql.DB, a tenant, query, itemID string) {
	t.Helper()
	inTx(ctx, t, app, a.accountID, func(tx *sql.Tx) {
		res, err := tx.ExecContext(ctx, query, itemID)
		if err != nil {
			t.Fatalf("esecuzione %q: %v", query, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			t.Fatalf("righe toccate: %v", err)
		}
		if n != 0 {
			t.Fatalf("A ha toccato %d righe di B (atteso 0): %q", n, query)
		}
	})
}

func assertAOnlySeesOwn(ctx context.Context, t *testing.T, app *sql.DB, a, b tenant) {
	inTx(ctx, t, app, a.accountID, func(tx *sql.Tx) {
		if n := countItems(ctx, t, tx); n != 1 {
			t.Fatalf("A dovrebbe vedere 1 item (il suo), visti %d", n)
		}
		var id string
		err := tx.QueryRowContext(ctx, `SELECT id FROM item WHERE id = $1`, b.itemID).Scan(&id)
		if !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("A non deve vedere l'item di B: err=%v", err)
		}
	})
}

func assertACannotUpdateB(ctx context.Context, t *testing.T, app *sql.DB, a, b tenant) {
	expectZeroRows(ctx, t, app, a, `UPDATE item SET deleted = true WHERE id = $1`, b.itemID)
}

func assertACannotDeleteB(ctx context.Context, t *testing.T, app *sql.DB, a, b tenant) {
	expectZeroRows(ctx, t, app, a, `DELETE FROM item WHERE id = $1`, b.itemID)
}

func assertNoAccountNoRows(ctx context.Context, t *testing.T, app *sql.DB) {
	inTx(ctx, t, app, "", func(tx *sql.Tx) {
		if n := countItems(ctx, t, tx); n != 0 {
			t.Fatalf("senza app.account_id si dovrebbero vedere 0 item, visti %d", n)
		}
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM account`).Scan(&n); err != nil {
			t.Fatalf("count account: %v", err)
		}
		if n != 0 {
			t.Fatalf("senza app.account_id si dovrebbero vedere 0 account, visti %d", n)
		}
	})
}

func assertNoDDL(ctx context.Context, t *testing.T, app *sql.DB) {
	if _, err := app.ExecContext(ctx, `CREATE TABLE intruso (i int)`); err == nil {
		t.Fatal("kunuk_app ha potuto creare una tabella (DDL dovuto fallire)")
	}
}

func assertNoBypassRLS(ctx context.Context, t *testing.T, app *sql.DB) {
	var bypass bool
	if err := app.QueryRowContext(ctx,
		`SELECT rolbypassrls FROM pg_roles WHERE rolname = $1`, appUser).Scan(&bypass); err != nil {
		t.Fatalf("lettura attributi ruolo: %v", err)
	}
	if bypass {
		t.Fatal("kunuk_app ha BYPASSRLS (dovrebbe essere NOBYPASSRLS)")
	}
}
