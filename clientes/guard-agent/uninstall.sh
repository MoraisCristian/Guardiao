#!/bin/bash

# Guard-Agent Uninstall Script
# This script completely removes the Guard-Agent installation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Function to print colored messages
print_message() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    print_error "This script must be run as root"
    exit 1
fi

# Installation directory
INSTALL_DIR="/var/guardiao"
SERVICE_NAME="guardiao"
MECHANIC_SERVICE_NAME="guardiao-mecanico"

# Stop and disable services
print_message "Stopping and disabling services..."
systemctl stop $SERVICE_NAME || true
systemctl disable $SERVICE_NAME || true
systemctl stop $MECHANIC_SERVICE_NAME || true
systemctl disable $MECHANIC_SERVICE_NAME || true

# Remove service files
print_message "Removing service files..."
rm -f /etc/systemd/system/$SERVICE_NAME.service
rm -f /etc/systemd/system/$MECHANIC_SERVICE_NAME.service
systemctl daemon-reload

# Remove installation directory
print_message "Removing installation directory..."
rm -rf $INSTALL_DIR

# Remove OSSEC related files
print_message "Removing OSSEC related files..."
rm -rf /var/ossec/*
rm -rf /var/ossec/


# Remove any remaining temporary files
print_message "Cleaning up temporary files..."
rm -f /tmp/guardiao.tar
rm -f /tmp/guardiao.md5
rm -f /tmp/guard_config.json.backup

apt remove -y psad

print_message "Guard-Agent has been completely uninstalled!"