#!/usr/bin/env bash
# Docker install: build images + start the stack. Run from repo root.
#   bash docker/install.sh
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose up -d --build
docker compose ps
