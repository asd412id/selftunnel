#!/bin/bash
# SelfTunnel Installation Script for Ubuntu/Debian
# Usage: curl -sSL https://raw.githubusercontent.com/youruser/selftunnel/main/scripts/install.sh | sudo bash -s -- <network_id> <network_secret> [node_name]

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

NETWORK_ID="${1:-}"
NETWORK_SECRET="${2:-}"
NODE_NAME="${3:-$(hostname)}"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="$HOME/.selftunnel"
SERVICE_FILE="/etc/systemd/system/selftunnel.service"

print_status() {
    echo -e "${GREEN}[*]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "Please run as root (sudo)"
        exit 1
    fi
}

check_args() {
    if [ -z "$NETWORK_ID" ] || [ -z "$NETWORK_SECRET" ]; then
        echo "SelfTunnel Installation Script"
        echo ""
        echo "Usage: $0 <network_id> <network_secret> [node_name]"
        echo ""
        echo "Arguments:"
        echo "  network_id      Network ID from 'selftunnel init'"
        echo "  network_secret  Network secret from 'selftunnel init'"
        echo "  node_name       Optional name for this node (default: hostname)"
        echo ""
        echo "Example:"
        echo "  $0 abc123xyz secretkey123 my-server"
        exit 1
    fi
}

install_dependencies() {
    print_status "Installing dependencies..."
    apt-get update -qq
    apt-get install -y -qq curl wget git golang-go > /dev/null 2>&1
}

build_selftunnel() {
    print_status "Building SelfTunnel from source..."
    
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"
    
    # Clone repository
    git clone --depth 1 https://github.com/youruser/selftunnel.git > /dev/null 2>&1 || {
        print_warning "Could not clone from GitHub, using local build..."
        # For local testing, copy from current directory
        return 1
    }
    
    cd selftunnel
    go build -o selftunnel ./cmd/selftunnel
    
    mv selftunnel "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/selftunnel"
    
    cd /
    rm -rf "$TEMP_DIR"
    
    print_status "SelfTunnel installed to $INSTALL_DIR/selftunnel"
}

join_network() {
    print_status "Joining network as '$NODE_NAME'..."
    
    # Create config directory for root
    mkdir -p /root/.selftunnel
    
    "$INSTALL_DIR/selftunnel" join \
        --network "$NETWORK_ID" \
        --secret "$NETWORK_SECRET" \
        --name "$NODE_NAME" &
    
    # Wait a bit for registration
    sleep 3
    pkill -f "selftunnel join" 2>/dev/null || true
    
    print_status "Joined network successfully"
}

create_systemd_service() {
    print_status "Creating systemd service..."
    
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=SelfTunnel P2P Mesh VPN
Documentation=https://github.com/youruser/selftunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=$INSTALL_DIR/selftunnel up
Restart=always
RestartSec=5
LimitNOFILE=65535

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=selftunnel

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    print_status "Systemd service created"
}

enable_service() {
    print_status "Enabling and starting service..."
    
    systemctl enable selftunnel > /dev/null 2>&1
    systemctl start selftunnel
    
    sleep 2
    
    if systemctl is-active --quiet selftunnel; then
        print_status "Service started successfully"
    else
        print_warning "Service may not have started correctly. Check: journalctl -u selftunnel"
    fi
}

configure_firewall() {
    if command -v ufw &> /dev/null; then
        print_status "Configuring UFW firewall..."
        ufw allow 51820/udp comment "SelfTunnel" > /dev/null 2>&1 || true
        ufw allow from 10.99.0.0/24 comment "SelfTunnel VPN" > /dev/null 2>&1 || true
    fi
}

load_tun_module() {
    print_status "Loading TUN kernel module..."
    modprobe tun 2>/dev/null || true
    
    # Make it persistent
    if ! grep -q "^tun$" /etc/modules 2>/dev/null; then
        echo "tun" >> /etc/modules
    fi
}

print_summary() {
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}        SelfTunnel Installation Complete!              ${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Node Name:    $NODE_NAME"
    echo ""
    echo "Useful commands:"
    echo "  Check status:    sudo systemctl status selftunnel"
    echo "  View logs:       sudo journalctl -u selftunnel -f"
    echo "  List peers:      selftunnel peers"
    echo "  Restart:         sudo systemctl restart selftunnel"
    echo ""
    
    # Show current status
    "$INSTALL_DIR/selftunnel" status 2>/dev/null || true
}

main() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════╗"
    echo "║           SelfTunnel Installer for Ubuntu             ║"
    echo "╚═══════════════════════════════════════════════════════╝"
    echo ""
    
    check_root
    check_args
    
    install_dependencies
    build_selftunnel || print_warning "Using manual installation"
    load_tun_module
    join_network
    create_systemd_service
    configure_firewall
    enable_service
    print_summary
}

main "$@"
