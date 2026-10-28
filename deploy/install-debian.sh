#!/usr/bin/env bash
# ssloth — full install on Debian 13 (trixie).
#   apt nodejs → user → checkout → npm build → systemd service on :8080.
# Usage (as root): bash deploy/install-debian.sh [--dir /srv/ssloth] [--port 8080]
set -euo pipefail
DIR=/srv/ssloth; PORT=8080
while [ $# -gt 0 ]; do case "$1" in
    --dir) DIR=$2; shift 2;;
    --port) PORT=$2; shift 2;;
    *) echo "unknown flag: $1" >&2; exit 64;;
esac; done
[ "$(id -u)" -ne 0 ] && { echo "run as root"; exit 1; }
log() { printf '==> %s\n' "$*"; }

log "apt node"
apt-get update -qq
apt-get install -y --no-install-recommends nodejs npm

id -u ssloth &>/dev/null || useradd -r -m -d "$DIR" -s /usr/sbin/nologin ssloth
SRC=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$DIR"; [ "$SRC" != "$DIR" ] && cp -a "$SRC/." "$DIR/"
chown -R ssloth:ssloth "$DIR"

log "npm install"
sudo -u ssloth npm ci --prefix "$DIR/server" 2>/dev/null || sudo -u ssloth npm install --prefix "$DIR/server"

log "systemd"
cat > /etc/systemd/system/ssloth.service <<UNIT
[Unit]
Description=ssloth SSH/desktop manager
After=network.target
[Service]
User=ssloth
WorkingDirectory=$DIR/server
Environment=PORT=$PORT
Environment=SSLOTH_MASTER_KEY=$(openssl rand -hex 32)
ExecStart=/usr/bin/node $DIR/server/src/index.js
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload; systemctl enable --now ssloth
log "done — ssloth on :$PORT (master key generated into the unit; rotate via systemctl edit)"
