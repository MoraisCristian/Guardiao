#!/bin/bash

# Only install dependencies if they don't exist
if ! command -v python3 &> /dev/null || ! pip3 list | grep -q Flask; then
  echo "Installing Python and dependencies..."
  apt-get update
  apt-get install -y python3 python3-pip lsof
  pip3 install flask
else
  echo "Dependencies already installed, skipping..."
fi

# Function to check if a process is running on a port
is_api_running() {
  netstat -tuln | grep ":59347 " > /dev/null
  return $?
}

# Start Wazuh manager if not already running
if ! pgrep -f "wazuh-manager" > /dev/null; then
  echo "Starting Wazuh manager..."
  /entrypoint.sh wazuh-manager &
  WAZUH_PID=$!
  
  # Wait for Wazuh to fully start
  echo "Waiting for Wazuh to start..."
  sleep 15
else
  echo "Wazuh manager already running"
  WAZUH_PID=$(pgrep -f "wazuh-manager")
fi

# Only start API connector if not already running
if ! is_api_running; then
  cd /opt/conector
  echo "Starting API connector..."
  python3 /opt/conector/ossec_api.py &
  echo "API connector started"
else
  echo "API connector already running on port 59347"
fi

echo "Services started successfully"

# Keep container running without constant monitoring
echo "Container is now running in service mode"
tail -f /var/ossec/logs/ossec.log