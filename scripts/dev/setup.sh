#!/usr/bin/env bash
# Setup dell'ambiente di sviluppo Kunuk.
# Verifica le toolchain richieste, installa le dipendenze del frontend e registra
# gli hook pre-commit/pre-push (doc 19 §8). Idempotente: rieseguibile senza danni.
set -euo pipefail

# Esegui sempre dalla radice del repo, qualunque sia la cwd del chiamante.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

errori=0

# Verifica la presenza di un comando; registra un errore se manca (non esce subito,
# così l'utente vede l'elenco completo di cosa installare).
richiede() {
  local cmd="$1" nota="$2"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "  [MANCANTE] $cmd — $nota"
    errori=$((errori + 1))
    return
  fi
  echo "  [ok] $cmd"
}

echo "==> Verifica toolchain richieste"
richiede rustup "Rust: https://rustup.rs (la versione è in crypto-core/rust-toolchain.toml)"
richiede cargo  "incluso in rustup"
richiede go     "Go 1.23: https://go.dev/dl"
richiede node   "Node.js 22: https://nodejs.org"
richiede npm    "incluso in Node.js"
richiede golangci-lint "https://golangci-lint.run/welcome/install (v2.12.2)"
richiede pre-commit "pip install pre-commit  oppure  brew install pre-commit (v4.6.0+)"

if [ "$errori" -gt 0 ]; then
  echo ""
  echo "==> $errori strumento/i mancante/i: installali e rilancia questo script." >&2
  exit 1
fi

echo ""
echo "==> Installazione dipendenze frontend (npm ci)"
( cd frontend && npm ci )

echo ""
echo "==> Registrazione hook git (pre-commit + pre-push)"
pre-commit install --install-hooks

echo ""
echo "==> Ambiente pronto. Gli hook gireranno automaticamente su commit e push."
echo "    Esecuzione manuale su tutti i file:  pre-commit run --all-files"
