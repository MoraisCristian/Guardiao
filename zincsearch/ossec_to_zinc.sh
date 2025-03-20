#!/bin/bash

# Install required dependencies
pip install requests

# Wait for ZincSearch to be ready
echo "Waiting for ZincSearch to be ready..."

python3 /app/check_zinc.py

# Run the Python script regardless of check result
echo "Starting OSSEC to ZincSearch connector..."
python3 /app/ossec_to_zincsearch.py