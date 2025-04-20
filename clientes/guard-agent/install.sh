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
ACTIVATION_KEY=""

# Installation directory
INSTALL_DIR="/var/guardiao"
AGENT_DIR="$INSTALL_DIR/guard-agent"
CONFIG_FILE="$INSTALL_DIR/guard_config.json"
SERVICE_NAME="guardiao"
MD5_FILE="$INSTALL_DIR/guardiao.md5"

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

# Install required dependencies
install_dependencies() {
    print_message "Checking required packages"
    
    # Check which packages are missing
    MISSING_PKGS=""
    command -v python3 >/dev/null 2>&1 || MISSING_PKGS="$MISSING_PKGS python3"
    command -v pip3 >/dev/null 2>&1 || MISSING_PKGS="$MISSING_PKGS python3-pip"
    command -v curl >/dev/null 2>&1 || MISSING_PKGS="$MISSING_PKGS curl"
    command -v tar >/dev/null 2>&1 || MISSING_PKGS="$MISSING_PKGS tar"
    
    if [ -n "$MISSING_PKGS" ]; then
        print_message "Installing missing packages: $MISSING_PKGS"
        
        # Detect distribution
        if [ -f /etc/debian_version ]; then
            apt-get update -y
            apt-get install -y $MISSING_PKGS python3-venv
        elif [ -f /etc/redhat-release ] || [ -f /etc/centos-release ]; then
            yum install -y $MISSING_PKGS python3-virtualenv
        fi
    else
        print_message "All required packages are already installed"
    fi
}

# Download configuration file
download_config() {
    print_message "Downloading configuration file from server"
    
    # Create installation directory if it doesn't exist
    mkdir -p "$INSTALL_DIR"
    chmod 755 "$INSTALL_DIR"
    
    # Download configuration file with retry logic
    CONFIG_URL="http://${SERVER_IP}:${SERVER_PORT}/download/guard_config.json"
    print_message "Downloading configuration from $CONFIG_URL"
    
    for i in {1..3}; do
        if curl -s -f -o "$CONFIG_FILE" "$CONFIG_URL"; then
            print_message "Configuration file downloaded successfully to $CONFIG_FILE"
            chmod 644 "$CONFIG_FILE"
            return 0
        else
            print_warning "Attempt $i: Failed to download configuration file (will retry in 2 seconds)"
            sleep 2
        fi
    done
    
    print_warning "Failed to download configuration file after 3 attempts"
    return 1
}

# Get server information from config
get_server_info() {
    # Try to download the config file first
    if ! download_config; then
        # If download fails, check if config exists locally
        if [ -f "$CONFIG_FILE" ]; then
            print_message "Using existing configuration file: $CONFIG_FILE"
        else
            print_warning "Configuration file not found. Using embedded server information."
            # If SERVER_IP is still the placeholder, prompt for input
            if [ "$SERVER_IP" == "SERVER_IP_PLACEHOLDER" ]; then
                print_warning "Server information not available. Please enter server information:"
                read -p "Server IP: " SERVER_IP
                read -p "Server Port: " SERVER_PORT
                
                # Create a basic config file
                mkdir -p "$INSTALL_DIR"
                cat > "$CONFIG_FILE" << EOF
{
    "server_ip": "$SERVER_IP",
    "server_port": "$SERVER_PORT"
}
EOF
            fi
        fi
    fi
    
    # Extract server info and activation key from config file
    if [ -f "$CONFIG_FILE" ]; then
        SERVER_IP=$(grep -o '"server_ip": "[^"]*' "$CONFIG_FILE" | cut -d'"' -f4)
        SERVER_PORT=$(grep -o '"server_port": "[^"]*' "$CONFIG_FILE" | cut -d'"' -f4)
        
        # Check for activation key (both possible names)
        if grep -q '"activation_key"' "$CONFIG_FILE"; then
            ACTIVATION_KEY=$(grep -o '"activation_key": "[^"]*' "$CONFIG_FILE" | cut -d'"' -f4)
            print_message "Found activation key ('activation_key') in configuration file"
        elif grep -q '"chave_ativacao"' "$CONFIG_FILE"; then
            ACTIVATION_KEY=$(grep -o '"chave_ativacao": "[^"]*' "$CONFIG_FILE" | cut -d'"' -f4)
            print_message "Found activation key ('chave_ativacao') in configuration file"
        fi
    fi
    
    # Log the final server info and activation key status
    print_message "Using server: ${SERVER_IP}:${SERVER_PORT}"
    if [ -n "$ACTIVATION_KEY" ]; then
        KEY_LENGTH=${#ACTIVATION_KEY}
        VISIBLE_CHARS=4
        MASKED_KEY="${ACTIVATION_KEY:0:$VISIBLE_CHARS}$(printf '%*s' $((KEY_LENGTH-VISIBLE_CHARS)) | tr ' ' '*')"
        print_message "Activation key loaded: $MASKED_KEY"
    else
        print_warning "Activation key not found in configuration."
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
    if [ -d "$INSTALL_DIR" ] && [ -f "$MD5_FILE" ]; then
        LOCAL_MD5=$(cat "$MD5_FILE")
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

# Test server connectivity
test_server_connectivity() {
    print_message "Testing server connectivity..."
    
    if curl -s -f -m 5 "http://${SERVER_IP}:${SERVER_PORT}/ping" > /dev/null; then
        print_message "Server connection test successful"
        return 0
    else
        print_warning "Server connection test failed. The agent may have trouble registering."
        print_warning "Continuing with installation, but registration might fail."
        return 1
    fi
}

# Download and install the agent
download_and_install() {
    # Create installation directories
    mkdir -p "$AGENT_DIR"
    
    # Backup existing configuration if this is an update
    if [ -f "$CONFIG_FILE" ]; then
        print_message "Backing up existing configuration"
        cp "$CONFIG_FILE" "/tmp/guard_config.json.backup"
    fi
    
    # Download the package with retry logic
    DOWNLOAD_URL="http://${SERVER_IP}:${SERVER_PORT}/download/guardiao.tar"
    print_message "Downloading Guard-Agent from $DOWNLOAD_URL"
    
    for i in {1..3}; do
        if curl -L -o /tmp/guardiao.tar "$DOWNLOAD_URL"; then
            break
        else
            print_warning "Attempt $i: Failed to download package (will retry in 2 seconds)"
            sleep 2
        fi
    done
    
    if [ ! -f "/tmp/guardiao.tar" ]; then
        print_error "Failed to download Guard-Agent package after 3 attempts"
        return 1
    fi
    
    # Extract the package
    print_message "Extracting package to $INSTALL_DIR"
    if ! tar -xf /tmp/guardiao.tar -C "$INSTALL_DIR"; then
        print_error "Failed to extract package to $INSTALL_DIR"
        return 1
    fi
    
    # Copy MD5 file to installation directory
    cp /tmp/guardiao.md5 "$MD5_FILE"
    
    # Restore configuration if this was an update
    if [ -f "/tmp/guard_config.json.backup" ]; then
        print_message "Restoring configuration"
        cp "/tmp/guard_config.json.backup" "$CONFIG_FILE"
    fi
    
    # Create virtual environment only if it doesn't exist
    if [ ! -d "$AGENT_DIR/venv" ]; then
        print_message "Creating Python virtual environment"
        python3 -m venv "$AGENT_DIR/venv"
        
        # Install Python dependencies in virtual environment
        if [ -f "$AGENT_DIR/requirements.txt" ]; then
            "$AGENT_DIR/venv/bin/pip" install -r "$AGENT_DIR/requirements.txt"
        else
            print_warning "requirements.txt not found. Installing basic dependencies."
            "$AGENT_DIR/venv/bin/pip" install requests psutil
        fi
    else
        print_message "Virtual environment already exists, skipping creation"
    fi
    
    # Test server connectivity before proceeding
    test_server_connectivity
    
    return 0
}

# Register agent with server
manual_register_agent() {
    # Check if the agent is already registered
    if [ -f "$AGENT_DIR/AGENTID" ]; then
        print_message "Agent already has an ID file. Skipping manual registration."
        return 0
    fi
    
    # Check if registration should be skipped
    if [ "$ACTIVATION_KEY" = "skip" ]; then
        print_warning "Registration was skipped by user request."
        return 1
    fi
    
    # Check if ACTIVATION_KEY is set
    if [ -z "$ACTIVATION_KEY" ]; then
        print_error "Activation key is missing. Cannot proceed with registration."
        return 1
    fi
    
    print_message "Attempting manual agent registration..."
    
    # Get system information
    HOSTNAME=$(hostname)
    OS_NAME=$(uname -s)
    OS_VERSION=$(uname -r)
    
    # Get IP address
    if [ "$OS_NAME" = "Darwin" ]; then
        IP_ADDRESS=$(ifconfig en0 | grep inet | grep -v inet6 | awk '{print $2}')
    else
        IP_ADDRESS=$(hostname -I 2>/dev/null | awk '{print $1}' || 
                    ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | head -n 1)
    fi
    
    # Get MAC address
    if [ "$OS_NAME" = "Darwin" ]; then
        MAC_ADDRESS=$(ifconfig en0 | awk '/ether/{print $2}')
    else
        MAC_ADDRESS=$(cat /sys/class/net/$(ip route show default | awk '/default/ {print $5}')/address 2>/dev/null || 
                     ifconfig | grep -o -E '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | head -n 1 ||
                     echo "00:00:00:00:00:00")
    fi
    
    # Create registration payload
    PAYLOAD="{\"chave\":\"$ACTIVATION_KEY\",\"host\":\"$HOSTNAME\",\"sistema\":\"$OS_NAME\",\"versao\":\"$OS_VERSION\",\"ip\":\"$IP_ADDRESS\",\"mac\":\"$MAC_ADDRESS\"}"
    
    print_message "Sending registration request to server..."
    print_message "Server URL: http://${SERVER_IP}:${SERVER_PORT}/registro"
    print_message "Registration payload: $PAYLOAD"
    
    # Create a temporary file for response logging
    RESPONSE_LOG="/tmp/guardiao_registration_response.log"
    echo "=== Guardião Registration Request $(date) ===" > "$RESPONSE_LOG"
    echo "REQUEST URL: http://${SERVER_IP}:${SERVER_PORT}/registro" >> "$RESPONSE_LOG"
    echo "REQUEST PAYLOAD: $PAYLOAD" >> "$RESPONSE_LOG"
    echo "REQUEST HEADERS: Content-Type: application/json" >> "$RESPONSE_LOG"
    echo "===" >> "$RESPONSE_LOG"
    
    # Send registration request
    curl -v -s -X POST -H "Content-Type: application/json" -d "$PAYLOAD" "http://${SERVER_IP}:${SERVER_PORT}/registro" >> "$RESPONSE_LOG" 2>&1
    CURL_EXIT=$?
    
    echo "===" >> "$RESPONSE_LOG"
    echo "CURL EXIT CODE: $CURL_EXIT" >> "$RESPONSE_LOG"
    
    # Log the complete response for debugging
    print_message "Complete curl response (from $RESPONSE_LOG):"
    cat "$RESPONSE_LOG"
    
    # Check curl exit code
    if [ $CURL_EXIT -ne 0 ]; then
        print_error "Curl command failed with exit code $CURL_EXIT"
        return 1
    fi
    
    # IMPROVED EXTRACTION: Use sed to extract the JSON response between the last pair of braces
    # This handles multi-line JSON responses better
    RESPONSE_BODY=$(sed -n '/{/,/}/p' "$RESPONSE_LOG" | tail -n +$(grep -n "Closing connection" "$RESPONSE_LOG" | cut -d: -f1) | grep -v "Closing connection")
    
    # If that fails, try a more aggressive approach
    if [ -z "$RESPONSE_BODY" ]; then
        # Try to extract any JSON-like content after the headers
        RESPONSE_BODY=$(sed -n '/^{/,/^}/p' "$RESPONSE_LOG")
    fi
    
    # If still empty, report error
    if [ -z "$RESPONSE_BODY" ]; then
        print_error "Failed to extract JSON response body from server."
        return 1
    fi
    
    print_message "Extracted response body: $RESPONSE_BODY"
    
    # Check response for agent ID
    if echo "$RESPONSE_BODY" | grep -q '"id_agente"'; then
        print_message "Registration successful based on server response containing 'id_agente'"
        
        # Extract agent ID
        AGENT_ID=$(echo "$RESPONSE_BODY" | grep -o '"id_agente":[^,}]*' | grep -o '[0-9]\+')
        
        if [ -n "$AGENT_ID" ]; then
            print_message "Successfully extracted agent ID: $AGENT_ID"
            echo "$AGENT_ID" > "$AGENT_DIR/AGENTID"
            chmod 644 "$AGENT_DIR/AGENTID"
            return 0
        else
            print_warning "Could not extract agent ID value from successful response. Creating placeholder."
            echo "${HOSTNAME}_registered_$(date +%s)" > "$AGENT_DIR/AGENTID"
            chmod 644 "$AGENT_DIR/AGENTID"
            return 0
        fi
    else
        print_error "Manual registration failed. Response did not contain 'id_agente'."
        print_error "Response body: $RESPONSE_BODY"
        return 1
    fi
}

# Setup system service
setup_service() {
    print_message "Configurando serviço do sistema"
    
    # Check if service file exists in agent directory
    if [ -f "$AGENT_DIR/guardiao.service" ]; then
        print_message "Copiando arquivo de serviço para /etc/systemd/system/"
        cp "$AGENT_DIR/guardiao.service" "/etc/systemd/system/$SERVICE_NAME.service"
    else
        print_error "Arquivo guardiao.service não encontrado em $AGENT_DIR"
        return 1
    fi
    
    # Prompt for activation key only if it wasn't found in the config file
    if [ -z "$ACTIVATION_KEY" ]; then
        print_message "Activation key not found in config, required for registration"
        
        read -p "Enter activation key (or type 'skip' to continue without registration): " USER_INPUT_KEY
        
        if [ "$USER_INPUT_KEY" = "skip" ]; then
            print_warning "Skipping registration. The agent will not be registered with the server."
            ACTIVATION_KEY="skip"
        elif [ -n "$USER_INPUT_KEY" ]; then
            ACTIVATION_KEY="$USER_INPUT_KEY"
            
            # Save activation key to config file
            if [ -f "$CONFIG_FILE" ]; then
                if grep -q -e '"chave_ativacao"' -e '"activation_key"' "$CONFIG_FILE"; then
                    sed -i "s/\"chave_ativacao\":[^,}]*/\"chave_ativacao\": \"$ACTIVATION_KEY\"/" "$CONFIG_FILE" 2>/dev/null || 
                    sed -i "" "s/\"chave_ativacao\":[^,}]*/\"chave_ativacao\": \"$ACTIVATION_KEY\"/" "$CONFIG_FILE"
                else
                    sed -i "s/}$/,\n    \"chave_ativacao\": \"$ACTIVATION_KEY\"\n}/" "$CONFIG_FILE" 2>/dev/null || 
                    sed -i "" "s/}$/,\n    \"chave_ativacao\": \"$ACTIVATION_KEY\"\n}/" "$CONFIG_FILE"
                fi
            fi
            print_message "Activation key accepted and saved."
        else
            print_warning "Empty activation key. Continuing without registration."
            ACTIVATION_KEY="skip"
        fi
    fi
    
    # Try manual registration before starting the service
    if [ "$ACTIVATION_KEY" != "skip" ]; then
        manual_register_agent || print_warning "Registration failed, but continuing with service setup"
    fi
    
    # Start service
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
    
    # Check service status with retry
    for i in {1..3}; do
        if systemctl is-active --quiet $SERVICE_NAME; then
            print_message "Serviço Guard-Agent está em execução"
            return 0
        else
            print_warning "Serviço não iniciou corretamente. Tentativa $i de 3..."
            sleep 5
            systemctl restart $SERVICE_NAME
        fi
    done
    
    print_error "Falha ao iniciar o serviço. Verifique os logs com: journalctl -u $SERVICE_NAME"
    return 1
}

# Setup mechanic service
setup_mechanic_service() {
    print_message "Setting up mechanic service"
    
    if [ -f "$AGENT_DIR/guardiao-mecanico.service" ]; then
        cp "$AGENT_DIR/guardiao-mecanico.service" /etc/systemd/system/
        
        systemctl daemon-reload
        systemctl enable guardiao-mecanico
        systemctl start guardiao-mecanico
        
        if systemctl is-active --quiet guardiao-mecanico; then
            print_message "Mechanic service started successfully"
            return 0
        else
            print_error "Failed to start guardiao-mecanico service"
            return 1
        fi
    else
        print_error "Arquivo guardiao-mecanico.service não encontrado no diretório do agente"
        return 1
    fi
}

# Clean up temporary files
cleanup() {
    print_message "Cleaning up temporary files"
    rm -f /tmp/guardiao.tar
    rm -f /tmp/guardiao.md5
    rm -f "/tmp/guard_config.json.backup"
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
                # Setup mechanic service
                setup_mechanic_service
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
        
        # Even if no update is needed, check if registration is working
        if [ ! -f "$AGENT_DIR/AGENTID" ]; then
            print_message "Agent is not registered. Attempting registration..."
            manual_register_agent
            
            # Restart service to apply registration
            systemctl restart $SERVICE_NAME
        fi
    fi
    
    # Clean up
    cleanup
}

# Run main function
main

