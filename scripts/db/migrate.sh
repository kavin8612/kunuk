#!/usr/bin/env bash
# Esecuzione delle migrazioni dello schema Kunuk (task 0.1: runner placeholder).
# Applica in ordine lessicale i file core/db/migrations/*.sql usando il ruolo
# kunuk_migrations (MAI kunuk_app: le migrazioni richiedono DDL, doc 07 + SR-32).
# I parametri di connessione vengono dall'ambiente (.env); la password passa via
# PGPASSWORD e non compare nei log (doc 19 §5).
#
# TODO(task-0.8): schema.sql come migrazione 0001 (ruoli kunuk_app/kunuk_migrations
# inclusi) e tracciamento delle migrazioni applicate (tabella schema_migrations).
# Per ora il runner applica semplicemente i file presenti, in ordine; oggi la
# cartella è vuota e lo script esce pulito.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
migrations_dir="$repo_root/core/db/migrations"

shopt -s nullglob
files=("$migrations_dir"/*.sql)
if [ "${#files[@]}" -eq 0 ]; then
  echo "==> Nessuna migrazione in $migrations_dir (atteso fino al task 0.8)."
  exit 0
fi

# Variabili richieste (assenti => errore esplicito, non un fallimento oscuro).
: "${KUNUK_DB_HOST:?manca KUNUK_DB_HOST}"
: "${KUNUK_DB_PORT:?manca KUNUK_DB_PORT}"
: "${KUNUK_DB_NAME:?manca KUNUK_DB_NAME}"
: "${KUNUK_DB_MIGRATIONS_USER:?manca KUNUK_DB_MIGRATIONS_USER}"
: "${KUNUK_DB_MIGRATIONS_PASSWORD:?manca KUNUK_DB_MIGRATIONS_PASSWORD}"

export PGPASSWORD="$KUNUK_DB_MIGRATIONS_PASSWORD"
for f in "${files[@]}"; do
  echo "==> Applico $(basename "$f")"
  psql -v ON_ERROR_STOP=1 \
    --host "$KUNUK_DB_HOST" --port "$KUNUK_DB_PORT" \
    --username "$KUNUK_DB_MIGRATIONS_USER" --dbname "$KUNUK_DB_NAME" \
    --file "$f"
done
echo "==> Migrazioni applicate: ${#files[@]}."
