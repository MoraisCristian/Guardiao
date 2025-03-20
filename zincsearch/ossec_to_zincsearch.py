import time
import json
import requests
import sys
from datetime import datetime

# Configurações
OSSEC_LOG_PATH = "/ossec/alerts.json/alerts.json"
ZINCSEARCH_BASE_URL = "http://zincsearch:4080"
ZINCSEARCH_INDEX_URL = f"{ZINCSEARCH_BASE_URL}/api/index"
ZINCSEARCH_BULK_URL = f"{ZINCSEARCH_BASE_URL}/api/_bulk"
ZINCSEARCH_AUTH = ("admin", "#Pascho7095")
INDEX_NAME = "ossec-alerts"

def ensure_index_exists():
    """Check if the index exists and create it if it doesn't"""
    # Check if index exists
    headers = {"Content-Type": "application/json"}
    response = requests.get(
        f"{ZINCSEARCH_INDEX_URL}/{INDEX_NAME}",
        auth=ZINCSEARCH_AUTH,
        headers=headers
    )
    
    # If index doesn't exist (404), create it
    if response.status_code == 404:
        print(f"Index {INDEX_NAME} not found. Creating...")
        
        # Define index mapping
        index_config = {
            "name": INDEX_NAME,
            "storage_type": "disk",
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date", "format": "2006-01-02 15:04:05"},
                    "rule": {"type": "text"},
                    "level": {"type": "keyword"},
                    "description": {"type": "text"},
                    "src_ip": {"type": "ip"},
                    "full_log": {"type": "text"}
                }
            }
        }
        
        # Create the index
        create_response = requests.post(
            ZINCSEARCH_INDEX_URL,
            auth=ZINCSEARCH_AUTH,
            headers=headers,
            json=index_config
        )
        
        if create_response.status_code == 200:
            print(f"Successfully created index {INDEX_NAME}")
            return True
        else:
            print(f"Failed to create index: {create_response.status_code} - {create_response.text}")
            return False
    elif response.status_code == 200:
        print(f"Index {INDEX_NAME} already exists")
        return True
    else:
        print(f"Error checking index: {response.status_code} - {response.text}")
        return False

def format_timestamp(timestamp_str):
    """Convert timestamp from OSSEC format to ZincSearch format"""
    try:
        # Parse the OSSEC timestamp format (e.g., "2025 Mar 20 14:28:20")
        dt = datetime.strptime(timestamp_str, "%Y %b %d %H:%M:%S")
        # Format it to ZincSearch expected format (e.g., "2025-03-20 14:28:20")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception as e:
        print(f"Error formatting timestamp '{timestamp_str}': {str(e)}")
        return timestamp_str  # Return original if parsing fails

def send_to_zincsearch(alert):
    """Send an alert to ZincSearch"""
    headers = {"Content-Type": "application/json"}
    
    # Create a copy of the alert to avoid modifying the original
    processed_alert = alert.copy()
    
    # Format timestamp if present
    if "timestamp" in processed_alert:
        processed_alert["timestamp"] = format_timestamp(processed_alert["timestamp"])
    
    # Prepare document for indexing
    # ZincSearch expects each document to have a unique _id field
    if "_id" not in processed_alert:
        # Generate a unique ID if not present
        import uuid
        processed_alert["_id"] = str(uuid.uuid4())
    
    # Format for document API instead of bulk API
    document_url = f"{ZINCSEARCH_BASE_URL}/api/{INDEX_NAME}/_doc"
    
    try:
        response = requests.post(
            document_url,
            headers=headers,
            auth=ZINCSEARCH_AUTH,
            json=processed_alert
        )
        
        if response.status_code == 200:
            print(f"Alert sent to ZincSearch successfully: {processed_alert.get('rule', 'unknown rule')}")
        else:
            print(f"Failed to send alert to ZincSearch: {response.status_code} - {response.text}")
            print(f"Alert data: {json.dumps(processed_alert)[:100]}...")  # Print first 100 chars of alert for debugging
    except Exception as e:
        print(f"Exception while sending to ZincSearch: {str(e)}")

def monitor_ossec_log():
    """Monitor the OSSEC log file and send alerts to ZincSearch"""
    # Ensure the index exists before starting
    if not ensure_index_exists():
        print("Failed to ensure index exists. Exiting.")
        sys.exit(1)
        
    print(f"Starting to monitor {OSSEC_LOG_PATH} for alerts...")
    
    with open(OSSEC_LOG_PATH, "r") as log_file:
        log_file.seek(0, 2)  # Vai para o final do arquivo
        while True:
            line = log_file.readline()
            if line:
                try:
                    alert = json.loads(line)
                    send_to_zincsearch(alert)
                except json.JSONDecodeError:
                    print(f"Failed to decode JSON alert: {line[:50]}...")  # Print first 50 chars for debugging
            else:
                time.sleep(1)  # Espera por novos logs

if __name__ == "__main__":
    monitor_ossec_log()