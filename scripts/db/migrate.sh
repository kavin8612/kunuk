#!/usr/bin/env bash
# Applicazione manuale delle migrazioni dello schema (ops). In esercizio le migrazioni le
# applica DA SOLO il servizio one-shot `migrate` del Compose a ogni avvio (idempotente,
# tracciato da goose, come kunuk_migrations — mai kunuk_app: DDL, doc 07 + SR-32). Questo
# wrapper serve solo a lanciarle a mano, riusando la stessa immagine: nessun segreto qui,
# le credenziali arrivano da .env tramite il Compose.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
exec docker compose -f "$repo_root/scripts/infra/compose.yaml" run --rm migrate
