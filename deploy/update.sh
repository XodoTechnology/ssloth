#!/usr/bin/env bash
# ssloth — in-place update: git pull → npm install → restart service.
# Usage: bash deploy/update.sh [--dir PATH] [--no-restart]
set -euo pipefail
DIR=/srv/ssloth; RESTART=1; PULL=1
while [ $# -gt 0 ]; do case "$1" in
    --dir) DIR=$2; shift 2;;
    --no-restart) RESTART=0; shift;;
    --no-pull) PULL=0; shift;;
    *) echo "unknown flag: $1" >&2; exit 64;;
esac; done
[ "$(id -u)" -ne 0 ] && { echo "run as root"; exit 1; }
[ -d "$DIR/.git" ] || { echo "$DIR is not a git checkout"; exit 1; }
log() { printf '==> %s\n' "$*"; }
if [ "$PULL" = 1 ]; then
  log "pull"
  sudo -u ssloth git -C "$DIR" pull --ff-only
else
  log "pull skipped (--no-pull)"
fi
log "npm"
sudo -u ssloth npm ci --prefix "$DIR/server" 2>/dev/null || sudo -u ssloth npm install --prefix "$DIR/server"
[ "$RESTART" = 1 ] && { systemctl restart ssloth 2>/dev/null && log "restarted ssloth" || true; }
log "updated — $(sudo -u ssloth git -C "$DIR" log --oneline -1 2>/dev/null || echo unknown)"
