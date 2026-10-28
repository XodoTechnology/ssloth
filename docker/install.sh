#!/usr/bin/env bash
# ssloth — full docker install on a bare host.
#   docker+compose if missing → .env with generated secrets →
#   compose up --build → post-install → report access.
# Usage: bash docker/install.sh
set -euo pipefail
cd "$(dirname "$0")/.."
log() { printf '==> %s\n' "$*"; }

if ! command -v docker >/dev/null 2>&1; then
  log "installing docker"
  apt-get update -qq
  apt-get install -y --no-install-recommends docker.io docker-compose-v2 2>/dev/null     || apt-get install -y --no-install-recommends docker.io docker-compose
  systemctl enable --now docker
fi
docker compose version >/dev/null 2>&1 || { echo "docker compose missing"; exit 1; }

if [ ! -f .env ]; then
  log "writing .env (fresh master key)"
  echo "SSLOTH_MASTER_KEY = \"$(openssl rand -hex 32)\"" > .env
fi

log "build + up"
docker compose up -d --build



docker compose ps
echo "ssloth: http://localhost:8080 — create your first user in the UI"
