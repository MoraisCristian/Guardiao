#!/bin/bash

# Install required dependencies
pip install requests

# Wait for ZincSearch to be ready
echo "Waiting for ZincSearch to be ready..."
cat > /tmp/check_zinc.py << 'EOF'
import requests
import time
import sys

def check_zinc_ready():
    try:
        response = requests.head("http://zincsearch:4080", timeout=2)
        return response.status_code < 400
    except:
        return False

while not check_zinc_ready():
    sys.stdout.write('.')
    sys.stdout.flush()
    time.sleep(2)

print("\nZincSearch is ready!")
EOF

python3 /tmp/check_zinc.py

# Run the Python script
echo "Starting OSSEC to ZincSearch connector..."
python3 /app/ossec_to_zincsearch.py