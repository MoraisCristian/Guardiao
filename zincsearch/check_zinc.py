import requests
import time
import sys
import json

def check_zinc_ready():
    try:
        auth = ("admin", "#Pascho7095")
        headers = {"Content-Type": "application/json"}
        response = requests.get("http://10.0.10.233:4080/api/index", 
                               auth=auth, 
                               headers=headers,
                               timeout=5)
        return response.status_code == 200
    except Exception as e:
        print(f"\nError checking ZincSearch: {str(e)}")
        return False

# Initial delay to give ZincSearch time to start
print("Waiting 3 seconds for initial startup...")
time.sleep(3)

attempts = 0
max_attempts = 30
while not check_zinc_ready():
    attempts += 1
    if attempts >= max_attempts:
        print(f"\nFailed to connect to ZincSearch after {max_attempts} attempts. Continuing anyway...")
        break
        
    sys.stdout.write('.')
    sys.stdout.flush()
    time.sleep(1)

print("\nZincSearch is ready or max attempts reached!")