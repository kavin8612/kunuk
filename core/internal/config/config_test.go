package config

import (
	"strings"
	"testing"
	"time"
)

func setRequired(t *testing.T) {
	t.Helper()
	for k, v := range map[string]string{
		"KUNUK_PUBLIC_BASE_URL":        "https://kunuk.example",
		"KUNUK_DOMAIN":                 "kunuk.example",
		"KUNUK_DB_HOST":                "postgres",
		"KUNUK_DB_NAME":                "kunuk",
		"KUNUK_DB_APP_USER":            "kunuk_app",
		"KUNUK_DB_APP_PASSWORD":        "app-pw",
		"KUNUK_DB_MIGRATIONS_USER":     "kunuk_migrations",
		"KUNUK_DB_MIGRATIONS_PASSWORD": "migr-pw",
		"KUNUK_AUTH_DECOY_SECRET":      strings.Repeat("x", 32),
	} {
		t.Setenv(k, v)
	}
}

func TestLoadOK(t *testing.T) {
	setRequired(t)
	t.Setenv("KUNUK_SESSION_TTL", "30m")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SessionTTL != 30*time.Minute {
		t.Fatalf("SessionTTL = %v, atteso 30m", cfg.SessionTTL)
	}
	if !strings.Contains(cfg.AppDSN(), "user=kunuk_app") {
		t.Fatalf("AppDSN non contiene il ruolo app: %q", cfg.AppDSN())
	}
	if !strings.Contains(cfg.MigrationsDSN(), "user=kunuk_migrations") {
		t.Fatalf("MigrationsDSN non contiene il ruolo migrazioni")
	}
}

func TestLoadMissing(t *testing.T) {
	// Nessuna variabile obbligatoria impostata in questo test → errore aggregato.
	t.Setenv("KUNUK_PUBLIC_BASE_URL", "")
	if _, err := Load(); err == nil {
		t.Fatal("Load doveva fallire per variabili mancanti")
	}
}

func TestLoadBadTTL(t *testing.T) {
	setRequired(t)
	t.Setenv("KUNUK_SESSION_TTL", "non-una-durata")
	if _, err := Load(); err == nil {
		t.Fatal("Load doveva fallire per TTL non valido")
	}
}

func TestLoadShortDecoy(t *testing.T) {
	setRequired(t)
	t.Setenv("KUNUK_AUTH_DECOY_SECRET", "troppo-corto")
	if _, err := Load(); err == nil {
		t.Fatal("Load doveva fallire per decoy secret troppo corto")
	}
}
