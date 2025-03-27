#!/bin/bash

# Script to package guard-agent folder and generate MD5 hash
# This script creates guardiao.tar and guardiao.md5 files

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Function to print colored messages
print_message() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Source directory
SOURCE_DIR="clientes/guard-agent"
# Destination directory
DEST_DIR="apps/downloads"

# Check if source directory exists
if [ ! -d "$SOURCE_DIR" ]; then
    print_error "Source directory $SOURCE_DIR does not exist!"
    exit 1
fi

# Create destination directory if it doesn't exist
if [ ! -d "$DEST_DIR" ]; then
    print_message "Creating destination directory $DEST_DIR"
    mkdir -p "$DEST_DIR"
fi

# Package the guard-agent folder
print_message "Creating guardiao.tar from $SOURCE_DIR"
tar -cf "$DEST_DIR/guardiao.tar" -C "$(dirname "$SOURCE_DIR")" "$(basename "$SOURCE_DIR")"

# Read server IP and port from guard_config.json
CONFIG_FILE="clientes/guard-agent/guard_config.json"
if [ -f "$CONFIG_FILE" ]; then
    print_message "Reading server information from $CONFIG_FILE"
    SERVER_IP=$(grep -o '"server_ip": "[^"]*' "$CONFIG_FILE" | cut -d'"' -f4)
    SERVER_PORT=$(grep -o '"server_port": "[^"]*' "$CONFIG_FILE" | cut -d'"' -f4)
    print_message "Using server IP: $SERVER_IP and port: $SERVER_PORT"
else
    print_warning "Configuration file not found. Using default values."
    SERVER_IP="10.0.10.233"
    SERVER_PORT="5002"
fi

# Copy and modify the install.sh file
print_message "Preparing install.sh with server information"
cp "clientes/guard-agent/install.sh" "$DEST_DIR/install.sh.tmp"

# Replace placeholders in the install script with actual values
# Check OS type to use the correct sed syntax
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS version
    sed -i '' "s/SERVER_IP_PLACEHOLDER/$SERVER_IP/g" "$DEST_DIR/install.sh.tmp"
    sed -i '' "s/SERVER_PORT_PLACEHOLDER/$SERVER_PORT/g" "$DEST_DIR/install.sh.tmp"
else
    # Linux version
    sed -i "s/SERVER_IP_PLACEHOLDER/$SERVER_IP/g" "$DEST_DIR/install.sh.tmp"
    sed -i "s/SERVER_PORT_PLACEHOLDER/$SERVER_PORT/g" "$DEST_DIR/install.sh.tmp"
fi

# Move the modified file to the final location
mv "$DEST_DIR/install.sh.tmp" "$DEST_DIR/install.sh"
chmod +x "$DEST_DIR/install.sh"

# Copy the configuration file to the downloads directory
print_message "Copying guard_config.json to $DEST_DIR"
cp "$CONFIG_FILE" "$DEST_DIR/guard_config.json"

# Generate MD5 hash - check for md5 or md5sum command
print_message "Generating MD5 hash"
if command -v md5 &> /dev/null; then
    # macOS uses md5 command
    md5_hash=$(md5 -q "$DEST_DIR/guardiao.tar")
elif command -v md5sum &> /dev/null; then
    # Linux uses md5sum command
    md5_hash=$(md5sum "$DEST_DIR/guardiao.tar" | awk '{print $1}')
else
    print_warning "Neither md5 nor md5sum commands found. Using openssl for MD5 calculation."
    # Fallback to openssl which is available on most systems
    md5_hash=$(openssl md5 "$DEST_DIR/guardiao.tar" | awk '{print $2}')
fi

echo "$md5_hash" > "$DEST_DIR/guardiao.md5"

print_message "Package created: $DEST_DIR/guardiao.tar"
print_message "MD5 hash file created: $DEST_DIR/guardiao.md5"
print_message "MD5 hash: $md5_hash"

print_message "Done!"