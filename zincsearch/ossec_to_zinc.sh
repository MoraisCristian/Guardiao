#!/bin/bash

# Install required dependencies
pip install requests

# Wait for ZincSearch to be ready
echo "Waiting for ZincSearch to be ready..."
cat > /tmp/check_zinc.py << 'EOF'
import requests
import time
import sys
import json

def check_zinc_ready():
    try:
        # Try to access the healthcheck endpoint instead of just the base URL
        response = requests.get("http://zincsearch:4080/api/healthz", timeout=5)
        if response.status_code == 200:
            print(f"\nZincSearch health check response: {response.text}")
            return True
            
        # Fallback: try to list indices which should work if the API is up
        auth = ("admin", "#Pascho7095")
        headers = {"Content-Type": "application/json"}
        response = requests.get("http://zincsearch:4080/api/index", 
                               auth=auth, 
                               headers=headers,
                               timeout=5)
        return response.status_code < 400
    except Exception as e:
        print(f"\nError checking ZincSearch: {str(e)}")
        return False

# Initial delay to give ZincSearch time to start
print("Waiting 10 seconds for initial startup...")
time.sleep(10)

attempts = 0
max_attempts = 30
while not check_zinc_ready():
    attempts += 1
    if attempts >= max_attempts:
        print(f"\nFailed to connect to ZincSearch after {max_attempts} attempts. Continuing anyway...")
        break
        
    sys.stdout.write('.')
    sys.stdout.flush()
    time.sleep(5)

print("\nZincSearch is ready or max attempts reached!")
EOF

python3 /tmp/check_zinc.py

# Run the Python script regardless of check result
echo "Starting OSSEC to ZincSearch connector..."
python3 /app/ossec_to_zincsearch.py