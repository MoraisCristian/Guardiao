import time
import json
import requests
import sys
import os
import traceback
from datetime import datetime

# Configurações
OSSEC_LOG_PATH = "/ossec/alerts.json/alerts.json"
ZINCSEARCH_BASE_URL = "http://zincsearch:4080"
ZINCSEARCH_INDEX_URL = f"{ZINCSEARCH_BASE_URL}/api/index"
ZINCSEARCH_BULK_URL = f"{ZINCSEARCH_BASE_URL}/api/_bulk"
ZINCSEARCH_AUTH = ("admin", "#Pascho7095")
INDEX_NAME = "ossec-alerts"

# Add a log file for better debugging
LOG_FILE = "/var/log/ossec_to_zinc.log"

def log_message(message, level="INFO"):
    """Log a message to both console and log file"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [{level}] {message}"
    print(log_entry)
    
    # Ensure log directory exists
    log_dir = os.path.dirname(LOG_FILE)
    if not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir)
        except Exception as e:
            print(f"Failed to create log directory: {str(e)}")
    
    try:
        with open(LOG_FILE, "a") as f:
            f.write(log_entry + "\n")
    except Exception as e:
        print(f"Failed to write to log file: {str(e)}")

def ensure_index_exists():
    """Check if the index exists and create it if it doesn't"""
    # Check if index exists
    headers = {"Content-Type": "application/json"}
    try:
        response = requests.get(
            f"{ZINCSEARCH_INDEX_URL}/{INDEX_NAME}",
            auth=ZINCSEARCH_AUTH,
            headers=headers,
            timeout=10
        )
        
        # If index doesn't exist (404), create it
        if response.status_code == 404:
            log_message(f"Index {INDEX_NAME} not found. Creating...", "INFO")
            
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
                json=index_config,
                timeout=10
            )
            
            if create_response.status_code == 200:
                log_message(f"Successfully created index {INDEX_NAME}", "INFO")
                return True
            else:
                log_message(f"Failed to create index: {create_response.status_code} - {create_response.text}", "ERROR")
                return False
        elif response.status_code == 200:
            log_message(f"Index {INDEX_NAME} already exists", "INFO")
            return True
        else:
            log_message(f"Error checking index: {response.status_code} - {response.text}", "ERROR")
            return False
    except Exception as e:
        log_message(f"Exception in ensure_index_exists: {str(e)}", "ERROR")
        log_message(traceback.format_exc(), "DEBUG")
        return False

def format_timestamp(timestamp_str):
    """Convert timestamp from OSSEC format to ZincSearch format"""
    try:
        # Parse the OSSEC timestamp format (e.g., "2025 Mar 20 14:28:20")
        dt = datetime.strptime(timestamp_str, "%Y %b %d %H:%M:%S")
        # Format it to ZincSearch expected format (e.g., "2025-03-20 14:28:20")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception as e:
        log_message(f"Error formatting timestamp '{timestamp_str}': {str(e)}", "WARNING")
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
            json=processed_alert,
            timeout=10
        )
        
        if response.status_code == 200:
            log_message(f"Alert sent to ZincSearch successfully: {processed_alert.get('rule', 'unknown rule')}", "INFO")
            return True
        else:
            log_message(f"Failed to send alert to ZincSearch: {response.status_code} - {response.text}", "ERROR")
            log_message(f"Alert data: {json.dumps(processed_alert)[:100]}...", "DEBUG")  # Print first 100 chars of alert for debugging
            return False
    except Exception as e:
        log_message(f"Exception while sending to ZincSearch: {str(e)}", "ERROR")
        log_message(traceback.format_exc(), "DEBUG")
        return False

def monitor_ossec_log():
    """Monitor the OSSEC log file and send alerts to ZincSearch"""
    # Ensure the index exists before starting
    if not ensure_index_exists():
        log_message("Failed to ensure index exists. Will retry in the main loop.", "WARNING")
    
    log_message(f"Starting to monitor {OSSEC_LOG_PATH} for alerts...", "INFO")
    
    # Keep track of file position
    file_position = 0
    
    while True:
        try:
            # Check if file exists
            if not os.path.exists(OSSEC_LOG_PATH):
                log_message(f"Log file {OSSEC_LOG_PATH} does not exist. Waiting...", "WARNING")
                time.sleep(10)
                continue
                
            with open(OSSEC_LOG_PATH, "r") as log_file:
                # If we have a saved position, go there
                if file_position > 0:
                    log_file.seek(file_position)
                else:
                    # First run, go to end of file
                    log_file.seek(0, 2)
                    file_position = log_file.tell()
                    log_message(f"Initial file position: {file_position}", "DEBUG")
                
                # Read new lines
                while True:
                    line = log_file.readline()
                    if not line:
                        # Save current position
                        file_position = log_file.tell()
                        break
                        
                    # Skip empty lines
                    line = line.strip()
                    if not line:
                        continue
                        
                    try:
                        # Try to parse JSON
                        alert = json.loads(line)
                        send_to_zincsearch(alert)
                    except json.JSONDecodeError as e:
                        # Log the error and the problematic line
                        log_message(f"JSON decode error: {str(e)}", "ERROR")
                        log_message(f"Problematic line: {line[:200]}...", "DEBUG")
                        
                        # Try to recover by finding the next valid JSON object
                        # This is a simple approach - we just skip this line
                        continue
                    except Exception as e:
                        log_message(f"Unexpected error processing line: {str(e)}", "ERROR")
                        log_message(traceback.format_exc(), "DEBUG")
                        continue
            
            # Wait before checking for new logs
            time.sleep(1)
            
        except Exception as e:
            log_message(f"Error in monitor loop: {str(e)}", "ERROR")
            log_message(traceback.format_exc(), "DEBUG")
            # Don't exit on error, just wait and retry
            time.sleep(10)
            
            # Reset file position to force re-reading from the beginning if needed
            if "No such file" in str(e):
                file_position = 0

if __name__ == "__main__":
    try:
        log_message("Starting OSSEC to ZincSearch connector", "INFO")
        monitor_ossec_log()
    except KeyboardInterrupt:
        log_message("Received keyboard interrupt. Exiting.", "INFO")
        sys.exit(0)
    except Exception as e:
        log_message(f"Fatal error: {str(e)}", "CRITICAL")
        log_message(traceback.format_exc(), "DEBUG")
        sys.exit(1)