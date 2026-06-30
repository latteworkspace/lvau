#!/usr/bin/env bash
set -euo pipefail

REMOTE_BIN="${REMOTE_BIN:-/tmp/lvau-api}"
INSTALL_DIR="${INSTALL_DIR:-/opt/lvau-api}"
SERVICE_FILE="${SERVICE_FILE:-/etc/systemd/system/lvau-api.service}"
ENV_FILE="${ENV_FILE:-/etc/lvau-api.env}"

if [[ $# -lt 1 ]]; then
  echo "usage: $0 /path/to/lvau-api" >&2
  exit 2
fi

if [[ ! -x "$1" ]]; then
  echo "binary is missing or not executable: $1" >&2
  exit 2
fi

sudo useradd -r -s /usr/sbin/nologin lvau 2>/dev/null || true
sudo install -d -o lvau -g lvau -m 0750 "$INSTALL_DIR"
sudo install -m 0755 "$1" "$REMOTE_BIN"

if [[ -x "$INSTALL_DIR/lvau-api" ]]; then
  sudo cp "$INSTALL_DIR/lvau-api" "$INSTALL_DIR/lvau-api.previous"
fi

sudo install -o root -g root -m 0755 "$REMOTE_BIN" "$INSTALL_DIR/lvau-api"
sudo tee "$ENV_FILE" >/dev/null <<EOF_ENV
LVAU_BIND=127.0.0.1:8787
LVAU_ALLOWED_ORIGIN=${LVAU_ALLOWED_ORIGIN:-https://lattee.jp}
LVAU_MAX_UPLOAD_MB=${LVAU_MAX_UPLOAD_MB:-50}
LVAU_MAX_CONCURRENT_JOBS=${LVAU_MAX_CONCURRENT_JOBS:-2}
LVAU_RATE_LIMIT_HEALTH_PER_MIN=${LVAU_RATE_LIMIT_HEALTH_PER_MIN:-60}
LVAU_RATE_LIMIT_INSPECT_PER_MIN=${LVAU_RATE_LIMIT_INSPECT_PER_MIN:-20}
LVAU_RATE_LIMIT_ENCRYPT_PER_MIN=${LVAU_RATE_LIMIT_ENCRYPT_PER_MIN:-3}
LVAU_RATE_LIMIT_DECRYPT_PER_MIN=${LVAU_RATE_LIMIT_DECRYPT_PER_MIN:-3}
LVAU_API_KEYS=${LVAU_API_KEYS:-}
RUST_LOG=lvau_api=info,tower_http=info
EOF_ENV
sudo chmod 0600 "$ENV_FILE"

sudo tee "$SERVICE_FILE" >/dev/null <<'EOF_SERVICE'
[Unit]
Description=Lvau API Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=lvau
Group=lvau
WorkingDirectory=/opt/lvau-api
ExecStart=/opt/lvau-api/lvau-api
EnvironmentFile=/etc/lvau-api.env
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/tmp /opt/lvau-api
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOF_SERVICE

sudo systemctl daemon-reload
sudo systemctl enable lvau-api
sudo systemctl restart lvau-api

if ! curl -fsS http://127.0.0.1:8787/lvau/health >/dev/null; then
  if [[ -x "$INSTALL_DIR/lvau-api.previous" ]]; then
    sudo cp "$INSTALL_DIR/lvau-api.previous" "$INSTALL_DIR/lvau-api"
    sudo systemctl restart lvau-api
  fi
  echo "health check failed; previous binary restored when available" >&2
  exit 1
fi

echo "lvau-api deployed and healthy"
