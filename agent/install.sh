#!/usr/bin/env bash
# ============================================================================
# AEGIS EDR-lite Agent Installer
# ============================================================================
# Usage:
#   curl -sSL https://your-server/install.sh | bash -s -- \
#       --api-url http://your-server:8000/api/v1 \
#       --api-key c6_your_api_key_here
#
# Or set environment variables:
#   AEGIS_API_URL=http://your-server:8000/api/v1 \
#   AEGIS_API_KEY=c6_xxx \
#   bash install.sh
# ============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${CYAN}[aegis]${NC} $*"; }
ok()   { echo -e "${GREEN}[aegis]${NC} $*"; }
warn() { echo -e "${YELLOW}[aegis]${NC} $*"; }
err()  { echo -e "${RED}[aegis]${NC} $*" >&2; }

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
API_URL="${AEGIS_API_URL:-}"
API_KEY="${AEGIS_API_KEY:-}"
INSTALL_MODE="docker"   # docker | native

while [[ $# -gt 0 ]]; do
    case "$1" in
        --api-url)  API_URL="$2";      shift 2 ;;
        --api-key)  API_KEY="$2";      shift 2 ;;
        --native)   INSTALL_MODE="native"; shift ;;
        *)          err "Unknown arg: $1"; exit 1 ;;
    esac
done

if [[ -z "$API_URL" ]]; then
    err "AEGIS_API_URL is required. Use --api-url or set the env var."
    exit 1
fi
if [[ -z "$API_KEY" ]]; then
    err "AEGIS_API_KEY is required. Use --api-key or set the env var."
    exit 1
fi

log "AEGIS EDR-lite Agent Installer"
log "API URL: $API_URL"
log "Mode:    $INSTALL_MODE"
echo ""

# ---------------------------------------------------------------------------
# Docker install
# ---------------------------------------------------------------------------
install_docker() {
    if ! command -v docker &>/dev/null; then
        err "Docker is not installed. Install Docker first or use --native."
        exit 1
    fi

    log "Stopping existing aegis-agent container (if any)..."
    docker rm -f aegis-agent 2>/dev/null || true

    log "Building agent image..."
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    docker build -t aegis/agent:latest "$SCRIPT_DIR"

    log "Starting aegis-agent container..."
    docker run -d \
        --name aegis-agent \
        --restart unless-stopped \
        -e AEGIS_API_URL="$API_URL" \
        -e AEGIS_API_KEY="$API_KEY" \
        -e AEGIS_LOG_LEVEL="INFO" \
        -e AEGIS_BREADCRUMBS_ENABLED="true" \
        -v /etc:/host/etc:ro \
        -v /var/log:/host/logs:ro \
        --pid=host \
        --net=host \
        aegis/agent:latest

    ok "Agent container started successfully."
    log "View logs: docker logs -f aegis-agent"
    log "Stop:      docker stop aegis-agent"
    log "Remove:    docker rm -f aegis-agent"
}

# ---------------------------------------------------------------------------
# Native install (no Docker)
# ---------------------------------------------------------------------------
install_native() {
    log "Installing agent natively..."

    # Check Python 3.10+
    if ! command -v python3 &>/dev/null; then
        err "Python 3 is required."
        exit 1
    fi

    PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    log "Python version: $PYTHON_VERSION"

    INSTALL_DIR="/opt/aegis-agent"
    log "Installing to $INSTALL_DIR..."

    sudo mkdir -p "$INSTALL_DIR"
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    sudo cp "$SCRIPT_DIR/aegis_agent.py" "$INSTALL_DIR/"
    sudo cp "$SCRIPT_DIR/config.py" "$INSTALL_DIR/"
    sudo cp "$SCRIPT_DIR/requirements.txt" "$INSTALL_DIR/"

    log "Installing Python dependencies..."
    sudo pip3 install --break-system-packages -r "$INSTALL_DIR/requirements.txt" 2>/dev/null || \
    sudo pip3 install -r "$INSTALL_DIR/requirements.txt"

    # Create systemd service
    log "Creating systemd service..."
    sudo tee /etc/systemd/system/aegis-agent.service > /dev/null <<EOSVC
[Unit]
Description=AEGIS EDR-lite Endpoint Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
Environment="AEGIS_API_URL=$API_URL"
Environment="AEGIS_API_KEY=$API_KEY"
Environment="AEGIS_LOG_LEVEL=INFO"
Environment="AEGIS_BREADCRUMBS_ENABLED=true"
ExecStart=/usr/bin/python3 $INSTALL_DIR/aegis_agent.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOSVC

    sudo systemctl daemon-reload
    sudo systemctl enable aegis-agent
    sudo systemctl start aegis-agent

    ok "Agent installed and started as systemd service."
    log "Status: sudo systemctl status aegis-agent"
    log "Logs:   sudo journalctl -u aegis-agent -f"
    log "Stop:   sudo systemctl stop aegis-agent"
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
if [[ "$INSTALL_MODE" == "docker" ]]; then
    install_docker
else
    install_native
fi

echo ""
ok "AEGIS EDR-lite agent installation complete."
