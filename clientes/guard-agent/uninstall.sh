#!/bin/bash

# Guard-Agent Uninstall Script
# This script completely removes the Guard-Agent installation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Function to print colored messages
print_message() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[AVISO]${NC} $1"
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

# Uninstall Wazuh agent
print_message "Uninstalling Wazuh agent..."
if command -v wazuh-agent > /dev/null 2>&1 || [ -d "/var/ossec" ]; then
    # Stop Wazuh service first
    if [ -f "/var/ossec/bin/wazuh-control" ]; then
        print_message "Stopping Wazuh service..."
        /var/ossec/bin/wazuh-control stop || true
    elif [ -f "/var/ossec/bin/ossec-control" ]; then
        print_message "Stopping OSSEC service..."
        /var/ossec/bin/ossec-control stop || true
    fi
    
    # Detect package manager and uninstall
    if command -v apt > /dev/null 2>&1; then
        print_message "Removing Wazuh agent package using apt..."
        apt-get remove --purge -y wazuh-agent || true
    elif command -v yum > /dev/null 2>&1; then
        print_message "Removing Wazuh agent package using yum..."
        yum remove -y wazuh-agent || true
    elif command -v dnf > /dev/null 2>&1; then
        print_message "Removing Wazuh agent package using dnf..."
        dnf remove -y wazuh-agent || true
    else
        print_warning "Could not detect package manager. Proceeding with manual removal."
    fi
    
    # Remove OSSEC/Wazuh related files
    print_message "Removing Wazuh/OSSEC related files..."
    rm -rf /var/ossec
    rm -rf /etc/ossec-init.conf
    rm -rf /etc/systemd/system/wazuh-agent.service
    systemctl daemon-reload
else
    print_message "Wazuh agent not found. Skipping uninstallation."
fi

# Remove any remaining temporary files
print_message "Cleaning up temporary files..."
rm -f /tmp/guardiao.tar
rm -f /tmp/guardiao.md5
rm -f /tmp/guard_config.json.backup
rm -f /tmp/wazuh-agent.deb

# Remove psad
print_message "Removing psad..."
apt remove -y psad || true

print_message "Guard-Agent has been completely uninstalled!"