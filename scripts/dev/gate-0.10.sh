#!/usr/bin/env bash
# Gate Fase 0 (task 0.10): esegue la CLI end-to-end contro lo stack Compose reale, passando
# dall'ingress Caddy in HTTPS (dev = prod, doc 07). Alza lo stack, estrae la CA interna di
# Caddy per fidare il certificato di sviluppo (verifica TLS attiva, niente verifica disabilitata),
# poi lancia il binario `kunuk` che fa: registrazione → login → sblocco → upload → decifratura
# → verifica del manifest. Uscita 0 = gate verde.
#
# Uso:  scripts/dev/gate-0.10.sh
# Var:  KUNUK_GATE_KEEP=1  lascia lo stack su a fine run (default: lo abbatte).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CA_FILE="$(mktemp)"

dc() {
	docker compose -f "$ROOT/scripts/infra/compose.yaml" --env-file "$ROOT/.env" "$@"
}

cleanup() {
	rm -f "$CA_FILE"
	if [ "${KUNUK_GATE_KEEP:-0}" != "1" ]; then
		echo "→ abbatto lo stack (KUNUK_GATE_KEEP=1 per tenerlo su)"
		dc down >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT

if [ ! -f "$ROOT/.env" ]; then
	echo "manca $ROOT/.env — copialo da .env.example e valorizzalo (doc 07)." >&2
	exit 1
fi

echo "→ avvio dello stack (build incluso)…"
dc up -d --build

echo "→ estrazione della CA interna di Caddy…"
caddy_ca="/data/caddy/pki/authorities/local/root.crt"
ok=0
for _ in $(seq 1 30); do
	if dc cp "caddy:$caddy_ca" "$CA_FILE" 2>/dev/null && [ -s "$CA_FILE" ]; then
		ok=1
		break
	fi
	sleep 2
done
if [ "$ok" != "1" ]; then
	echo "CA di Caddy non disponibile: lo stack è partito?" >&2
	exit 1
fi

echo "→ attesa che l'API risponda via Caddy (HTTPS)…"
# --ssl-no-revoke: su Windows curl usa Schannel, che fa il controllo di revoca anche con
# --cacert e fallisce sulla CA interna di Caddy (nessun OCSP/CRL); il flag lo disattiva
# (no-op sui backend OpenSSL di Linux/CI). La verifica del certificato resta attiva. La
# cerimonia vera (ureq+rustls) non è affetta: questo riguarda solo il probe di liveness.
ok=0
for _ in $(seq 1 60); do
	if curl -fsS --ssl-no-revoke --cacert "$CA_FILE" https://localhost/health >/dev/null 2>&1; then
		ok=1
		break
	fi
	sleep 2
done
if [ "$ok" != "1" ]; then
	echo "l'API non risponde su https://localhost/health" >&2
	dc logs --tail 40 api caddy >&2 || true
	exit 1
fi

echo "→ esecuzione della cerimonia (CLI kunuk)…"
cd "$ROOT/apps/cli" || exit 1
KUNUK_API_URL="https://localhost" KUNUK_CA_CERT="$CA_FILE" cargo run --quiet
