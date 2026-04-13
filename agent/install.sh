#!/bin/bash
# labwatch agent installer
# Usage:
#   curl -fsSL https://labwatch.dev/install.sh | sudo bash
#   curl -fsSL https://labwatch.dev/install.sh | sudo bash -s uninstall
#
# Installs (or removes) the labwatch monitoring agent as a systemd service.
# Works on any Linux system with systemd.

set -euo pipefail

BASE_URL="${LABWATCH_URL:-https://labwatch.dev}"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/labwatch"
SERVICE_FILE="/etc/systemd/system/labwatch.service"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
AMBER='\033[0;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[labwatch]${NC} $*"; }
warn() { echo -e "${AMBER}[labwatch]${NC} $*"; }
error() { echo -e "${RED}[labwatch]${NC} $*" >&2; }

# Handle 'uninstall' subcommand before any install-time checks (arch detection,
# download, etc.) so it works even when those would fail.
if [ "${1:-}" = "uninstall" ] || [ "${1:-}" = "remove" ]; then
    if [ "$(id -u)" -ne 0 ]; then
        error "Uninstall must be run as root (use sudo)"
        exit 1
    fi
    info "Uninstalling labwatch agent..."
    if systemctl list-unit-files labwatch.service >/dev/null 2>&1; then
        systemctl disable --now labwatch.service 2>/dev/null || true
    fi
    rm -f "$SERVICE_FILE"
    rm -f "${INSTALL_DIR}/labwatch"
    rm -rf "$CONFIG_DIR"
    systemctl daemon-reload 2>/dev/null || true
    systemctl reset-failed labwatch.service 2>/dev/null || true
    info "labwatch removed."
    echo ""
    echo "Reinstall with:"
    echo "  curl -fsSL ${BASE_URL}/install.sh | sudo bash"
    exit 0
fi

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    armv7l)  ARCH="armv7" ;;
    *)       error "Unsupported architecture: $ARCH"; exit 1 ;;
esac

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
if [ "$OS" != "linux" ]; then
    error "labwatch currently only supports Linux"
    exit 1
fi

info "Installing labwatch for ${OS}/${ARCH}..."

# Check for root
if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run as root (use sudo)"
    exit 1
fi

# Download latest release
LATEST_URL="${BASE_URL}/download/labwatch-${OS}-${ARCH}"
info "Downloading from ${LATEST_URL}..."
TMP_BIN=$(mktemp)
trap 'rm -f "$TMP_BIN"' EXIT
if ! curl -fsSL -o "$TMP_BIN" "$LATEST_URL"; then
    error "Download failed. Check your internet connection."
    exit 1
fi
chmod +x "$TMP_BIN"
mv "$TMP_BIN" "${INSTALL_DIR}/labwatch"
trap - EXIT

# Create config directory
mkdir -p "$CONFIG_DIR"

# Write default config if it doesn't exist
if [ ! -f "${CONFIG_DIR}/config.yaml" ]; then
cat > "${CONFIG_DIR}/config.yaml" << CONF
# labwatch agent config — edit these values after registration
api_endpoint: "${BASE_URL}/api/v1"
token: ""
lab_id: ""
# admin_secret: ""  # Only needed for registration
interval: 60s
hostname: "$(hostname)"
docker:
  enabled: true
  socket: /var/run/docker.sock
gpu:
  enabled: true
smart:
  enabled: true
CONF
    chmod 600 "${CONFIG_DIR}/config.yaml"
    info "Default config written to ${CONFIG_DIR}/config.yaml"
else
    info "Existing config preserved at ${CONFIG_DIR}/config.yaml"
fi

# Create systemd service
cat > /etc/systemd/system/labwatch.service << EOF
[Unit]
Description=labwatch monitoring agent
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/labwatch --config ${CONFIG_DIR}/config.yaml
Restart=always
RestartSec=10
MemoryMax=64M

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${CONFIG_DIR}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

info "Installation complete!"
echo ""
echo "Next steps:"
echo "  1. Edit config:  sudo nano ${CONFIG_DIR}/config.yaml"
echo "     Set admin_secret, then run:  labwatch --register"
echo "     Copy the returned lab_id and token into your config."
echo "  2. Start:        sudo systemctl enable --now labwatch"
echo ""
echo "  Status:          systemctl status labwatch"
echo "  Logs:            journalctl -u labwatch -f"
echo ""
info "Documentation: ${BASE_URL}/docs"


# ╭───────────────────────────────────────────────╮
# │                                               │
# │                    .                          │
# │                   .o.                         │
# │                  .ooo.                        │
# │                 .oo*oo.        ember          │
# │                .oo***oo.       lives          │
# │                 :*****:        here.          │
# │                  '***'                        │
# │                                               │
# │   one curious soul gets a year of pro free.   │
# │   /ember?via=install                          │
# │                                               │
# ╰───────────────────────────────────────────────╯
