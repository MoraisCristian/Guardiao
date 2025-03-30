#!/bin/bash

# Guard-Agent Installation/Update Script
# This script downloads and installs/updates the Guard-Agent from the configured server

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Server information - will be replaced during packaging
SERVER_IP="SERVER_IP_PLACEHOLDER"
SERVER_PORT="SERVER_PORT_PLACEHOLDER"

# Function to print colored messages
print_message() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[AVISO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERRO]${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    print_error "This script must be run as root"
    exit 1
fi

# Installation directory
INSTALL_DIR="/var/guardiao/guard-agent"
AGENT_DIR="$INSTALL_DIR"
CONFIG_FILE="/var/guardiao/guard-agent/guard_config.json"
SERVICE_NAME="guardiao"
MD5_FILE="/var/guardiao/guardiao.md5"

# Detect distribution
if [ -f /etc/debian_version ]; then
    DISTRO="debian"
    print_message "Detected Debian-based system"
elif [ -f /etc/redhat-release ]; then
    DISTRO="centos"
    print_message "Detected CentOS/RHEL-based system"
else
    print_warning "Could not determine Linux distribution. Assuming Debian-based."
    DISTRO="debian"
fi

# Install required packages
install_dependencies() {
    print_message "Installing required packages"
    
    # Detect distribution
    if [ -f /etc/debian_version ]; then
        DISTRO="debian"
        print_message "Detected Debian/Ubuntu system"
        
        # Only update packages if we need to install the agent
        if [ ! -d "$INSTALL_DIR" ] || check_for_update; then
            print_message "Update needed, updating package lists..."
            apt-get update -y
            apt-get install -y python3 python3-pip python3-venv curl tar
        else
            print_message "Agent already installed and up to date, skipping package updates"
        fi
    elif [ -f /etc/redhat-release ] || [ -f /etc/centos-release ]; then
        DISTRO="centos"
        print_message "Detected CentOS/RHEL system"
        
        # Only update packages if we need to install the agent
        if [ ! -d "$INSTALL_DIR" ] || check_for_update; then
            print_message "Update needed, updating packages..."
            yum update -y
            yum install -y python3 python3-pip python3-virtualenv curl tar 
        else
            print_message "Agent already installed and up to date, skipping package updates"
        fi
    fi
}

# Download configuration file
download_config() {
    print_message "Downloading configuration file from server"
    
    # Create installation directory if it doesn't exist
    if [ ! -d "$INSTALL_DIR" ]; then
        print_message "Creating installation directory at $INSTALL_DIR"
        mkdir -p "$INSTALL_DIR"
    fi
    
    # Download configuration file
    CONFIG_URL="http://${SERVER_IP}:${SERVER_PORT}/download/guard_config.json"
    print_message "Downloading configuration from $CONFIG_URL"
    
    if curl -s -f -o "$INSTALL_DIR/$CONFIG_FILE" "$CONFIG_URL"; then
        print_message "Configuration file downloaded successfully to $INSTALL_DIR/$CONFIG_FILE"
        # Read server information from the downloaded config
        SERVER_IP=$(grep -o '"server_ip": "[^"]*' "$INSTALL_DIR/$CONFIG_FILE" | cut -d'"' -f4)
        SERVER_PORT=$(grep -o '"server_port": "[^"]*' "$INSTALL_DIR/$CONFIG_FILE" | cut -d'"' -f4)
        print_message "Using server: ${SERVER_IP}:${SERVER_PORT}"
        return 0
    else
        print_warning "Failed to download configuration file from server"
        return 1
    fi
}

# Get server information
get_server_info() {
    # First try to download the config file
    if ! download_config; then
        # If download fails, check if config exists in current directory or install directory
        if [ -f "$CONFIG_FILE" ]; then
            print_message "Found configuration file in current directory"
            cp "$CONFIG_FILE" "$INSTALL_DIR/$CONFIG_FILE"
            SERVER_IP=$(grep -o '"server_ip": "[^"]*' "$CONFIG_FILE" | cut -d'"' -f4)
            SERVER_PORT=$(grep -o '"server_port": "[^"]*' "$CONFIG_FILE" | cut -d'"' -f4)
        elif [ -f "$INSTALL_DIR/$CONFIG_FILE" ]; then
            print_message "Found configuration file in installation directory"
            SERVER_IP=$(grep -o '"server_ip": "[^"]*' "$INSTALL_DIR/$CONFIG_FILE" | cut -d'"' -f4)
            SERVER_PORT=$(grep -o '"server_port": "[^"]*' "$INSTALL_DIR/$CONFIG_FILE" | cut -d'"' -f4)
        else
            print_warning "Configuration file not found. Using embedded server information."
            # If SERVER_IP is still the placeholder, prompt for input
            if [ "$SERVER_IP" == "SERVER_IP_PLACEHOLDER" ]; then
                print_warning "Server information not available. Please enter server information:"
                read -p "Server IP: " SERVER_IP
                read -p "Server Port: " SERVER_PORT
                
                # Create a basic config file
                cat > "$INSTALL_DIR/$CONFIG_FILE" << EOF
{
    "server_ip": "$SERVER_IP",
    "server_port": "$SERVER_PORT"
}
EOF
            fi
        fi
    fi
    
    print_message "Using server: ${SERVER_IP}:${SERVER_PORT}"
}

# Check if update is needed
check_for_update() {
    print_message "Checking for updates..."
    
    # Download MD5 file from server
    REMOTE_MD5_URL="http://${SERVER_IP}:${SERVER_PORT}/download/guardiao.md5"
    if ! curl -s -f -o /tmp/guardiao.md5 "$REMOTE_MD5_URL"; then
        print_error "Failed to download MD5 file from server"
        return 1
    fi
    
    # Read remote MD5
    REMOTE_MD5=$(cat /tmp/guardiao.md5)
    
    # Check if local installation exists and get its MD5
    if [ -d "$INSTALL_DIR" ] && [ -f "$INSTALL_DIR/$MD5_FILE" ]; then
        LOCAL_MD5=$(cat "$INSTALL_DIR/$MD5_FILE")
        print_message "Current version MD5: $LOCAL_MD5"
        print_message "Available version MD5: $REMOTE_MD5"
        
        if [ "$LOCAL_MD5" == "$REMOTE_MD5" ]; then
            print_message "You have the latest version. No update needed."
            return 1
        else
            print_message "Update available!"
            return 0
        fi
    else
        print_message "No existing installation found or MD5 file missing. Will perform fresh installation."
        return 0
    fi
}

# Download and install/update the package
download_and_install() {
    # Create installation directory if it doesn't exist
    if [ ! -d "$INSTALL_DIR" ]; then
        print_message "Creating installation directory at $INSTALL_DIR"
        mkdir -p "$INSTALL_DIR"
    fi
    
    # Create virtual environment
    print_message "Creating Python virtual environment"
    python3 -m venv "$INSTALL_DIR/venv"
    
    # Download the package
    DOWNLOAD_URL="http://${SERVER_IP}:${SERVER_PORT}/download/guardiao.tar"
    print_message "Downloading Guard-Agent from $DOWNLOAD_URL"
    if ! curl -L -o /tmp/guardiao.tar "$DOWNLOAD_URL"; then
        print_error "Failed to download Guard-Agent package"
        return 1
    fi
    
    # Download MD5 file
    REMOTE_MD5_URL="http://${SERVER_IP}:${SERVER_PORT}/download/guardiao.md5"
    curl -s -o /tmp/guardiao.md5 "$REMOTE_MD5_URL"
    
    # Backup existing configuration if this is an update
    if [ -f "$AGENT_DIR/$CONFIG_FILE" ]; then
        print_message "Backing up existing configuration"
        cp "$AGENT_DIR/$CONFIG_FILE" "/tmp/$CONFIG_FILE.backup"
    fi
    
    # Extract the package
    print_message "Extracting package to $INSTALL_DIR"
    tar -xf /tmp/guardiao.tar -C "$INSTALL_DIR"
    
    # Copy MD5 file to installation directory
    cp /tmp/guardiao.md5 "$INSTALL_DIR/$MD5_FILE"
    
    # Restore configuration if this was an update
    if [ -f "/tmp/$CONFIG_FILE.backup" ]; then
        print_message "Restoring configuration"
        cp "/tmp/$CONFIG_FILE.backup" "$AGENT_DIR/$CONFIG_FILE"
    fi
    
    # Install Python dependencies in virtual environment
    print_message "Installing Python dependencies in virtual environment"
    if [ -f "$AGENT_DIR/requirements.txt" ]; then
        "$INSTALL_DIR/venv/bin/pip" install -r "$AGENT_DIR/requirements.txt"
    else
        print_warning "requirements.txt not found. Installing basic dependencies."
        "$INSTALL_DIR/venv/bin/pip" install requests psutil
    fi
    
    return 0
}

# Create and configure service
setup_service() {
    print_message "Configurando serviço do sistema"
    
    # Use existing service file from local directory
    if [ -f "guardiao.service" ]; then
        print_message "Usando arquivo de serviço existente"
        cp guardiao.service /etc/systemd/system/$SERVICE_NAME.service
    else
        print_error "Arquivo guardiao.service não encontrado na pasta local"
        return 1
    fi
    
    # Reload systemd, enable and start service
    print_message "Ativando e iniciando serviço"
    systemctl daemon-reload
    systemctl enable $SERVICE_NAME
    
    # Check if service is already running
    if systemctl is-active --quiet $SERVICE_NAME; then
        print_message "Reiniciando serviço..."
        systemctl restart $SERVICE_NAME
    else
        print_message "Iniciando serviço..."
        systemctl start $SERVICE_NAME
    fi
    
    # Check service status
    if systemctl is-active --quiet $SERVICE_NAME; then
        print_message "Serviço Guard-Agent está em execução"
        return 0
    else
        print_error "Falha ao iniciar o serviço. Verifique os logs com: journalctl -u $SERVICE_NAME"
        return 1
    fi
}

function setup_mechanic_service() {
    print_message "Configurando serviço mecânico"
    
    # Use existing service file from local directory
    if [ -f "guardiao-mecanico.service" ]; then
        print_message "Usando arquivo de serviço mecânico existente"
        cp guardiao-mecanico.service /etc/systemd/system/guardiao-mecanico.service
    else
        print_error "Arquivo guardiao-mecanico.service não encontrado na pasta local"
        return 1
    fi
    
    # Reload systemd and enable/start services
    systemctl daemon-reload
    systemctl enable guardiao-mecanico
    systemctl start guardiao-mecanico
    
    return 0
}

# Clean up temporary files
cleanup() {
    print_message "Cleaning up temporary files"
    rm -f /tmp/guardiao.tar
    rm -f /tmp/guardiao.md5
    rm -f "/tmp/$CONFIG_FILE.backup"
}

# Main function
main() {
    print_message "Starting Guard-Agent installation/update process"
    
    # Install dependencies
    install_dependencies
    
    # Get server information
    get_server_info
    
    # Check if update is needed
    if check_for_update; then
        # Download and install/update
        if download_and_install; then
            # Setup service
            if setup_service; then
                print_message "Guard-Agent has been successfully installed/updated!"
                print_message "Service name: $SERVICE_NAME"
                print_message "You can check the status with: systemctl status $SERVICE_NAME"
            else
                print_error "Failed to setup service"
                exit 1
            fi
        else
            print_error "Failed to download and install Guard-Agent"
            exit 1
        fi
    else
        print_message "No installation/update needed"
    fi
    
    # Clean up
    cleanup
}

# Run main function
main


function setup_mechanic_service() {
    # Copy mechanic files to installation directory
    print_message "Setting up mechanic service"
    
    # Copy service files
    cp /var/guardiao/guard-agent/guardiao-mecanico.service /etc/systemd/system/
    cp /var/guardiao/guard-agent/guardiao.service /etc/systemd/system/
    
    # Reload systemd and enable/start services
    systemctl daemon-reload
    systemctl enable guardiao-mecanico
    systemctl start guardiao-mecanico
    systemctl enable guardiao
    systemctl start guardiao
    
    # Ensure services are running
    if ! systemctl is-active --quiet guardiao; then
        print_error "Failed to start guardiao service"
        return 1
    fi
    
    if ! systemctl is-active --quiet guardiao-mecanico; then
        print_error "Failed to start guardiao-mecanico service"
        return 1
    fi
    
    return 0
}

# In the main function, modify the service setup section:
if setup_service; then
    if setup_mechanic_service; then
        print_message "Guard-Agent has been successfully installed/updated!"
        print_message "Service name: $SERVICE_NAME"
        print_message "You can check the status with: systemctl status $SERVICE_NAME"
    else
        print_error "Failed to setup mechanic service"
        exit 1
    fi
else
    print_error "Failed to setup service"
    exit 1
fi