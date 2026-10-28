#!/usr/bin/env bash
# Docker update: pull code, rebuild images, restart stack. From repo root.
#   bash docker/update.sh [--ref REF]
set -euo pipefail
cd "$(dirname "$0")/.."
REF=""
while [ $# -gt 0 ]; do case "$1" in
    --ref) REF=$2; shift 2;;
    *) shift;;
esac; done
if [ -n "$REF" ]; then git checkout "$REF"; else git pull --ff-only; fi
docker compose build
docker compose up -d
docker compose ps
