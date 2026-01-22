#!/bin/bash
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== SelfTunnel Signaling Server Installation ===${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (sudo)${NC}"
    exit 1
fi

# Detect architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64)
        BINARY_ARCH="amd64"
        ;;
    aarch64|arm64)
        BINARY_ARCH="arm64"
        ;;
    *)
        echo -e "${RED}Unsupported architecture: $ARCH${NC}"
        exit 1
        ;;
esac

echo -e "${YELLOW}Detected architecture: $ARCH ($BINARY_ARCH)${NC}"

# Variables
INSTALL_DIR="/usr/local/bin"
SERVICE_FILE="/etc/systemd/system/selftunnel-signaling.service"
BINARY_NAME="signaling-server"
GITHUB_REPO="asd412id/selftunnel"
USER="selftunnel"

# Create user if not exists
if ! id "$USER" &>/dev/null; then
    echo -e "${YELLOW}Creating user $USER...${NC}"
    useradd -r -s /bin/false $USER
fi

# Download latest release
echo -e "${YELLOW}Downloading latest signaling-server...${NC}"
LATEST_URL=$(curl -s "https://api.github.com/repos/$GITHUB_REPO/releases/latest" | grep "browser_download_url.*signaling-server-linux-$BINARY_ARCH" | cut -d '"' -f 4)

if [ -z "$LATEST_URL" ]; then
    echo -e "${RED}Could not find download URL. Please download manually.${NC}"
    echo "Visit: https://github.com/$GITHUB_REPO/releases"
    exit 1
fi

curl -L -o /tmp/$BINARY_NAME "$LATEST_URL"
chmod +x /tmp/$BINARY_NAME
mv /tmp/$BINARY_NAME $INSTALL_DIR/$BINARY_NAME

echo -e "${GREEN}Binary installed to $INSTALL_DIR/$BINARY_NAME${NC}"

# Create systemd service
echo -e "${YELLOW}Creating systemd service...${NC}"
cat > $SERVICE_FILE << 'EOF'
[Unit]
Description=SelfTunnel Signaling Server
Documentation=https://github.com/asd412id/selftunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=selftunnel
Group=selftunnel
ExecStart=/usr/local/bin/signaling-server -port 8080
Restart=always
RestartSec=5
LimitNOFILE=65535

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictNamespaces=true

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=selftunnel-signaling

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and enable service
systemctl daemon-reload
systemctl enable selftunnel-signaling
systemctl start selftunnel-signaling

echo ""
echo -e "${GREEN}=== Installation Complete ===${NC}"
echo ""
echo "Service status:"
systemctl status selftunnel-signaling --no-pager
echo ""
echo -e "${YELLOW}Commands:${NC}"
echo "  Check status:  sudo systemctl status selftunnel-signaling"
echo "  View logs:     sudo journalctl -u selftunnel-signaling -f"
echo "  Restart:       sudo systemctl restart selftunnel-signaling"
echo "  Stop:          sudo systemctl stop selftunnel-signaling"
echo ""
echo -e "${YELLOW}Server running at:${NC} http://localhost:8080"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "  1. Set up reverse proxy (nginx/caddy) for HTTPS"
echo "  2. Or use Cloudflare Tunnel: cloudflared tunnel --url http://localhost:8080"
echo ""
