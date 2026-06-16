// Package config carica la configurazione del backend dalle variabili d'ambiente
// (mai da file .env nel processo: l'iniezione è del Compose/ambiente, doc 07). Variabili
// obbligatorie assenti => errore esplicito all'avvio, non un fallimento oscuro a runtime.
package config

import (
	"fmt"
	"os"
	"time"
)

// minDecoySecretLen è la lunghezza minima del segreto anti-enumeration (HMAC dei decoy).
const minDecoySecretLen = 32

// Config è la configurazione tipizzata del backend.
type Config struct {
	Env           string
	ListenAddr    string
	LogLevel      string
	PublicBaseURL string        // origin WebAuthn
	Domain        string        // RP ID WebAuthn
	SessionTTL    time.Duration // durata dei token di sessione (SR-31)
	DecoySecret   []byte        // HMAC per i decoy anti-enumeration (SR-26)
	DB            DBConfig
}

// DBConfig raccoglie i parametri di connessione dei due ruoli (runtime e migrazioni).
type DBConfig struct {
	Host, Port, Name, SSLMode          string
	AppUser, AppPassword               string
	MigrationsUser, MigrationsPassword string
}

// Load legge e valida la configurazione. Restituisce un errore aggregato se mancano
// variabili obbligatorie o se un valore è malformato.
func Load() (Config, error) {
	var missing []string
	get := func(key, def string) string {
		if v := os.Getenv(key); v != "" {
			return v
		}
		return def
	}
	req := func(key string) string {
		v := os.Getenv(key)
		if v == "" {
			missing = append(missing, key)
		}
		return v
	}

	cfg := Config{
		Env:           get("KUNUK_ENV", "dev"),
		ListenAddr:    get("KUNUK_API_LISTEN_ADDR", ":8080"),
		LogLevel:      get("KUNUK_LOG_LEVEL", "info"),
		PublicBaseURL: req("KUNUK_PUBLIC_BASE_URL"),
		Domain:        req("KUNUK_DOMAIN"),
		DB: DBConfig{
			Host:        req("KUNUK_DB_HOST"),
			Port:        get("KUNUK_DB_PORT", "5432"),
			Name:        req("KUNUK_DB_NAME"),
			SSLMode:     get("KUNUK_DB_SSLMODE", "disable"),
			AppUser:     req("KUNUK_DB_APP_USER"),
			AppPassword: req("KUNUK_DB_APP_PASSWORD"),
			// Credenziali migrazioni: opzionali per l'API (le migrazioni le applica il
			// servizio one-shot `migrate`, non l'API). Usate solo da MigrationsDSN().
			MigrationsUser:     get("KUNUK_DB_MIGRATIONS_USER", ""),
			MigrationsPassword: get("KUNUK_DB_MIGRATIONS_PASSWORD", ""),
		},
	}

	ttl, err := time.ParseDuration(get("KUNUK_SESSION_TTL", "12h"))
	if err != nil {
		return Config{}, fmt.Errorf("KUNUK_SESSION_TTL non valido: %w", err)
	}
	cfg.SessionTTL = ttl

	secret := req("KUNUK_AUTH_DECOY_SECRET")
	if secret != "" && len(secret) < minDecoySecretLen {
		return Config{}, fmt.Errorf("KUNUK_AUTH_DECOY_SECRET troppo corto: minimo %d byte", minDecoySecretLen)
	}
	cfg.DecoySecret = []byte(secret)

	if len(missing) > 0 {
		return Config{}, fmt.Errorf("variabili d'ambiente obbligatorie mancanti: %v", missing)
	}
	return cfg, nil
}

// AppDSN è la DSN del ruolo applicativo (runtime, soggetto a RLS).
func (c Config) AppDSN() string { return c.DB.dsn(c.DB.AppUser, c.DB.AppPassword) }

// MigrationsDSN è la DSN del ruolo migrazioni (DDL, solo all'avvio).
func (c Config) MigrationsDSN() string { return c.DB.dsn(c.DB.MigrationsUser, c.DB.MigrationsPassword) }

func (d DBConfig) dsn(user, password string) string {
	return fmt.Sprintf("host=%s port=%s dbname=%s user=%s password=%s sslmode=%s",
		d.Host, d.Port, d.Name, user, password, d.SSLMode)
}
