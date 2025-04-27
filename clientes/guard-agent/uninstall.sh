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

# Uninstall OSSEC agent
print_message "Desinstalando agente OSSEC..."
if [ -d "/var/ossec" ]; then
    # Stop OSSEC service first
    if [ -f "/var/ossec/bin/ossec-control" ]; then
        print_message "Parando serviço OSSEC..."
        /var/ossec/bin/ossec-control stop || true
    fi
    
    # Detect package manager and uninstall
    if command -v apt > /dev/null 2>&1; then
        print_message "Removendo pacote ossec-hids-agent usando apt..."
        apt-get remove --purge -y ossec-hids-agent || true
    elif command -v yum > /dev/null 2>&1; then
        print_message "Removendo pacote ossec-hids-agent usando yum..."
        yum remove -y ossec-hids-agent || true
    elif command -v dnf > /dev/null 2>&1; then
        print_message "Removendo pacote ossec-hids-agent usando dnf..."
        dnf remove -y ossec-hids-agent || true
    else
        print_warning "Não foi possível detectar o gerenciador de pacotes. Prosseguindo com remoção manual."
    fi
    
    # Remove OSSEC related files
    print_message "Removendo arquivos relacionados ao OSSEC..."
    rm -rf /var/ossec
    rm -rf /etc/ossec-init.conf
    systemctl daemon-reload
else
    print_message "Agente OSSEC não encontrado. Pulando desinstalação."
fi

# Remove any remaining temporary files
print_message "Limpando arquivos temporários..."
rm -f /tmp/guardiao.tar
rm -f /tmp/guardiao.md5
rm -f /tmp/guard_config.json.backup
rm -f /tmp/ossec-hids-agent.deb

# Remove psad
print_message "Removendo psad..."
apt remove -y psad || true

print_message "Guard-Agent foi completamente desinstalado!"