#!/bin/bash

# Install required dependencies
pip install requests

# Wait for ZincSearch to be ready
echo "Waiting for ZincSearch to be ready..."
until $(curl --output /dev/null --silent --head --fail http://zincsearch:4080); do
    printf '.'
    sleep 5
done
echo "ZincSearch is ready!"

# Run the Python script
echo "Starting OSSEC to ZincSearch connector..."
python3 /app/ossec_to_zincsearch.py