#!/bin/bash

# Script to package guard-agent folder and generate MD5 hash
# This script creates guardiao.tar and guardiao.md5 files

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to print colored messages
print_message() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
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

# Generate MD5 hash
print_message "Generating MD5 hash"
md5_hash=$(md5 -q "$DEST_DIR/guardiao.tar")
echo "$md5_hash" > "$DEST_DIR/guardiao.md5"

print_message "Package created: $DEST_DIR/guardiao.tar"
print_message "MD5 hash file created: $DEST_DIR/guardiao.md5"
print_message "MD5 hash: $md5_hash"

print_message "Done!"