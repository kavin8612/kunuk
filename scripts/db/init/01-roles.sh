#!/usr/bin/env bash
# Init dei ruoli DB e delle estensioni (task 0.8), eseguito dal superuser al primo avvio
# di Postgres (docker-entrypoint-initdb.d). I ruoli kunuk_app/kunuk_migrations e le loro
# password NON stanno nel SQL committato: le password arrivano dall'ambiente (.env), così
# nessun segreto finisce nel repo (doc 19 §5). Idempotente: rieseguibile senza errori.
#
# Separazione dei privilegi (SR-32): kunuk_migrations possiede lo schema (DDL, solo deploy);
# kunuk_app è il ruolo runtime, soggetto a RLS, senza DDL né BYPASSRLS. I GRANT DML sulle
# tabelle li assegna la migrazione 0001 dopo averle create.
set -euo pipefail

: "${POSTGRES_USER:?manca POSTGRES_USER}"
: "${POSTGRES_DB:?manca POSTGRES_DB}"
: "${KUNUK_DB_APP_USER:?manca KUNUK_DB_APP_USER}"
: "${KUNUK_DB_APP_PASSWORD:?manca KUNUK_DB_APP_PASSWORD}"
: "${KUNUK_DB_MIGRATIONS_USER:?manca KUNUK_DB_MIGRATIONS_USER}"
: "${KUNUK_DB_MIGRATIONS_PASSWORD:?manca KUNUK_DB_MIGRATIONS_PASSWORD}"

psql_super() {
  psql -v ON_ERROR_STOP=1 --no-psqlrc \
    --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" "$@"
}

# Crea il ruolo se manca, poi (sempre) imposta password e attributi a privilegio minimo.
# La password passa via variabile psql `:'pw'` (quoting/escape sicuri), mai concatenata.
ensure_role() {
  local role="$1" pw="$2" exists
  exists="$(psql_super -tAc "SELECT 1 FROM pg_roles WHERE rolname = '$role'")"
  if [ "$exists" != "1" ]; then
    psql_super -c "CREATE ROLE \"$role\" LOGIN"
  fi
  psql_super -v "pw=$pw" -c \
    "ALTER ROLE \"$role\" WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD :'pw'"
}

# Estensioni (gen_random_uuid è in core da PG13; citext serve per l'email case-insensitive).
psql_super -c "CREATE EXTENSION IF NOT EXISTS pgcrypto"
psql_super -c "CREATE EXTENSION IF NOT EXISTS citext"

ensure_role "$KUNUK_DB_MIGRATIONS_USER" "$KUNUK_DB_MIGRATIONS_PASSWORD"
ensure_role "$KUNUK_DB_APP_USER" "$KUNUK_DB_APP_PASSWORD"

# kunuk_migrations possiede lo schema public (PG15+ blocca CREATE ai non-proprietari): può
# creare oggetti durante le migrazioni. Entrambi i ruoli possono connettersi al database.
psql_super -c "GRANT CONNECT ON DATABASE \"$POSTGRES_DB\" TO \"$KUNUK_DB_MIGRATIONS_USER\", \"$KUNUK_DB_APP_USER\""
psql_super -c "ALTER SCHEMA public OWNER TO \"$KUNUK_DB_MIGRATIONS_USER\""

echo "==> Init DB: ruoli ($KUNUK_DB_MIGRATIONS_USER, $KUNUK_DB_APP_USER) ed estensioni pronti."
