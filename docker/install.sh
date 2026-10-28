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
  apt-get install -y --no-install-recommends docker.io docker-cli docker-buildx 2>/dev/null \
    || apt-get install -y --no-install-recommends docker.io docker-cli 2>/dev/null \
    || apt-get install -y --no-install-recommends docker.io
  systemctl enable --now docker || true
fi
# Debian 13 splits the client into docker-cli — docker.io alone leaves
# the daemon installed but no `docker` binary.
if ! command -v docker >/dev/null 2>&1; then
  log "installing docker cli"
  apt-get update -qq
  apt-get install -y --no-install-recommends docker-cli 2>/dev/null || true
fi
command -v docker >/dev/null 2>&1 || { echo "docker CLI missing"; exit 1; }
docker info >/dev/null 2>&1 || { echo "docker daemon not running"; exit 1; }

if ! docker compose version >/dev/null 2>&1; then
  log "installing docker compose"
  apt-get update -qq
  apt-get install -y --no-install-recommends docker-compose-v2 2>/dev/null \
    || apt-get install -y --no-install-recommends docker-compose-plugin 2>/dev/null \
    || apt-get install -y --no-install-recommends docker-compose
fi
# Debian's docker-compose pkg is the standalone binary, not the CLI
# plugin — link it in so `docker compose` resolves.
if ! docker compose version >/dev/null 2>&1 && command -v docker-compose >/dev/null 2>&1; then
  mkdir -p /usr/libexec/docker/cli-plugins
  ln -sf "$(command -v docker-compose)" /usr/libexec/docker/cli-plugins/docker-compose
fi
docker compose version >/dev/null 2>&1 || { echo "docker compose missing"; exit 1; }
command -v openssl >/dev/null 2>&1 || { apt-get update -qq; apt-get install -y --no-install-recommends openssl; }

if [ ! -f .env ]; then
  log "writing .env (fresh master key)"
  echo "SSLOTH_MASTER_KEY = \"$(openssl rand -hex 32)\"" > .env
fi

log "build + up"
docker compose up -d --build



docker compose ps
echo "ssloth: http://localhost:8080 — create your first user in the UI"
