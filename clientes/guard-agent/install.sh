#!/bin/bash

# Guard-Agent Installation/Update Script
# This script downloads and installs/updates the Guard-Agent from the configured server

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
    echo -e "${YELLOW}[WARNING]${NC} $1"
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
CONFIG_FILE="guard_config.json"
SERVICE_NAME="guardiao"
MD5_FILE="guardiao.md5"

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

# Install dependencies
install_dependencies() {
    print_message "Installing dependencies"
    if [ "$DISTRO" == "debian" ]; then
        apt-get update
        apt-get install -y python3 python3-pip curl tar md5sum
    elif [ "$DISTRO" == "centos" ]; then
        yum update -y
        yum install -y python3 python3-pip curl tar md5sum
    fi
}

# Get server information
get_server_info() {
    # Get server information from config file if it exists in current directory or install directory
    if [ -f "$CONFIG_FILE" ]; then
        print_message "Found configuration file in current directory"
        SERVER_IP=$(grep -o '"server_ip": "[^"]*' "$CONFIG_FILE" | cut -d'"' -f4)
        SERVER_PORT=$(grep -o '"server_port": "[^"]*' "$CONFIG_FILE" | cut -d'"' -f4)
    elif [ -f "$INSTALL_DIR/$CONFIG_FILE" ]; then
        print_message "Found configuration file in installation directory"
        SERVER_IP=$(grep -o '"server_ip": "[^"]*' "$INSTALL_DIR/$CONFIG_FILE" | cut -d'"' -f4)
        SERVER_PORT=$(grep -o '"server_port": "[^"]*' "$INSTALL_DIR/$CONFIG_FILE" | cut -d'"' -f4)
    else
        print_warning "Configuration file not found. Please enter server information:"
        read -p "Server IP: " SERVER_IP
        read -p "Server Port: " SERVER_PORT
        
        # Create a basic config file
        cat > "$CONFIG_FILE" << EOF
{
    "server_ip": "$SERVER_IP",
    "server_port": "$SERVER_PORT"
}
EOF
    fi
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
    if [ -f "$INSTALL_DIR/$CONFIG_FILE" ]; then
        print_message "Backing up existing configuration"
        cp "$INSTALL_DIR/$CONFIG_FILE" "/tmp/$CONFIG_FILE.backup"
    fi
    
    # Extract the package
    print_message "Extracting package to $INSTALL_DIR"
    tar -xf /tmp/guardiao.tar -C "$INSTALL_DIR"
    
    # Copy MD5 file to installation directory
    cp /tmp/guardiao.md5 "$INSTALL_DIR/$MD5_FILE"
    
    # Restore configuration if this was an update
    if [ -f "/tmp/$CONFIG_FILE.backup" ]; then
        print_message "Restoring configuration"
        cp "/tmp/$CONFIG_FILE.backup" "$INSTALL_DIR/$CONFIG_FILE"
    # Copy new config file if it exists in current directory
    elif [ -f "$CONFIG_FILE" ]; then
        print_message "Copying configuration file to $INSTALL_DIR"
        cp "$CONFIG_FILE" "$INSTALL_DIR/"
    fi
    
    # Install Python dependencies
    print_message "Installing Python dependencies"
    if [ -f "$INSTALL_DIR/requirements.txt" ]; then
        pip3 install -r "$INSTALL_DIR/requirements.txt"
    else
        print_warning "requirements.txt not found. Installing basic dependencies."
        pip3 install requests psutil
    fi
    
    return 0
}

# Create and configure service
setup_service() {
    print_message "Creating system service"
    
    # Create service file
    if [ "$DISTRO" == "debian" ] || [ "$DISTRO" == "centos" ]; then
        cat > /etc/systemd/system/$SERVICE_NAME.service << EOF
[Unit]
Description=Guardian Agent Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    fi
    
    # Reload systemd, enable and start service
    print_message "Enabling and starting service"
    systemctl daemon-reload
    systemctl enable $SERVICE_NAME
    
    # Check if service is already running
    if systemctl is-active --quiet $SERVICE_NAME; then
        print_message "Restarting service..."
        systemctl restart $SERVICE_NAME
    else
        print_message "Starting service..."
        systemctl start $SERVICE_NAME
    fi
    
    # Check service status
    if systemctl is-active --quiet $SERVICE_NAME; then
        print_message "Guard-Agent service is running"
        return 0
    else
        print_error "Service failed to start. Please check logs with: journalctl -u $SERVICE_NAME"
        return 1
    fi
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