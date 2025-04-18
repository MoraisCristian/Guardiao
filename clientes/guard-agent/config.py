import socket
import json
import os
import sys
from logger import log_info, log_warning, log_error, log_debug, log_exception

# Global configuration variables
ram = {}
# Ensure hostname is not empty
try:
    nome = socket.gethostname()
    if not nome or nome.strip() == '':
        import platform
        nome = platform.node()
        if not nome or nome.strip() == '':
            nome = "unknown-host"
    log_debug(f"Hostname detected: {nome}")
except Exception as e:
    log_warning(f"Error getting hostname: {str(e)}")
    nome = "unknown-host"

codigos = {'registro': 1, 'ping': 2, 'upload': 3, 'ossec-register': 4}
OSSEC_LOG_PATH = "/ossec/alerts.json"

# Load configuration from file
def load_config():
    config_path = 'guard_config.json'
    try:
        if os.path.exists(config_path):
            with open(config_path, 'r') as config_file:
                config = json.load(config_file)
                log_info("Configuration loaded successfully from file")
                return config
        else:
            log_error(f"Configuration file {config_path} not found.")
            log_info("Please create a guard_config.json file with server_ip, server_port, and activation_key.")
            sys.exit(1)
    except Exception as e:
        log_exception(f"Error loading configuration file")
        log_error("Please ensure guard_config.json is properly formatted.")
        sys.exit(1)

# Load configuration
config = load_config()

# Set configuration values
chave_ativacao = config.get("activation_key", "")
if not chave_ativacao:
    log_error("No activation key found in configuration file.")
    log_info("Please add an activation_key to guard_config.json.")
    sys.exit(1)

server_ip = config.get("server_ip", "")
if not server_ip:
    log_error("No server IP found in configuration file.")
    log_info("Please add a server_ip to guard_config.json.")
    sys.exit(1)

server_port = config.get("server_port", "")
if not server_port:
    log_error("No server port found in configuration file.")
    log_info("Please add a server_port to guard_config.json.")
    sys.exit(1)

# Server URL
SERVER_URL = f'http://{server_ip}:{server_port}'