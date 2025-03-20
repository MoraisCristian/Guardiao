import time
import json
import requests

# Configurações
OSSEC_LOG_PATH = "/ossec/alerts.json"
ZINCSEARCH_URL = "http://zincsearch:4080/api/default/_json"
ZINCSEARCH_AUTH = ("admin", "#Pascho7095")

def send_to_zincsearch(alert):
    headers = {
        "Content-Type": "application/json",
    }
    response = requests.post(ZINCSEARCH_URL, headers=headers, auth=ZINCSEARCH_AUTH, data=json.dumps(alert))
    if response.status_code == 200:
        print("Alert sent to ZincSearch successfully")
    else:
        print(f"Failed to send alert to ZincSearch: {response.status_code} - {response.text}")

def monitor_ossec_log():
    with open(OSSEC_LOG_PATH, "r") as log_file:
        log_file.seek(0, 2)  # Vai para o final do arquivo
        while True:
            line = log_file.readline()
            if line:
                try:
                    alert = json.loads(line)
                    send_to_zincsearch(alert)
                except json.JSONDecodeError:
                    print("Failed to decode JSON alert")
            else:
                time.sleep(1)  # Espera por novos logs

if __name__ == "__main__":
    monitor_ossec_log()