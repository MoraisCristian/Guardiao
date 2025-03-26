import socket
import json
import os
from logger import log_info, log_warning, log_error, log_debug, log_exception

# Default configuration values
DEFAULT_CONFIG = {
    "server_ip": "localhost",
    "server_port": "5002",
    "activation_key": "KOAUBDFDOEOER1EQLKZQQQ5COTTQFLO1ZI1TYHDZVPLDEDA0"
}

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
            log_warning(f"Configuration file {config_path} not found. Using default values.")
            # Create default config file
            with open(config_path, 'w') as config_file:
                json.dump(DEFAULT_CONFIG, config_file, indent=4)
            log_info(f"Default configuration file created at {config_path}")
            return DEFAULT_CONFIG
    except Exception as e:
        log_exception(f"Error loading configuration file")
        return DEFAULT_CONFIG

# Load configuration
config = load_config()

# Set configuration values
chave_ativacao = config.get("activation_key", DEFAULT_CONFIG["activation_key"])
server_ip = config.get("server_ip", DEFAULT_CONFIG["server_ip"])
server_port = config.get("server_port", DEFAULT_CONFIG["server_port"])

# Server URL
SERVER_URL = f'http://{server_ip}:{server_port}'