#!/bin/bash
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}=== Uninstalling SelfTunnel Signaling Server ===${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (sudo)${NC}"
    exit 1
fi

# Stop and disable service
if systemctl is-active --quiet selftunnel-signaling; then
    echo "Stopping service..."
    systemctl stop selftunnel-signaling
fi

if systemctl is-enabled --quiet selftunnel-signaling 2>/dev/null; then
    echo "Disabling service..."
    systemctl disable selftunnel-signaling
fi

# Remove files
echo "Removing files..."
rm -f /etc/systemd/system/selftunnel-signaling.service
rm -f /usr/local/bin/signaling-server

# Reload systemd
systemctl daemon-reload

# Optionally remove user
read -p "Remove selftunnel user? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    userdel selftunnel 2>/dev/null || true
    echo "User removed."
fi

echo -e "${GREEN}=== Uninstallation Complete ===${NC}"
