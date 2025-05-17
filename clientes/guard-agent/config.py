import socket
import json
import os
import sys
import shutil
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

def force_config_sync():
    """Força a sincronização do arquivo de configuração local com o principal"""
    main_config_path = '/var/guardiao/guard_config.json'
    local_config_path = os.path.join(os.path.dirname(__file__), 'guard_config.json')
    
    try:
        if os.path.exists(main_config_path):
            log_info(f"Arquivo de configuração principal encontrado: {main_config_path}")
            
            # Ler configuração do arquivo principal
            with open(main_config_path, 'r') as f:
                config = json.load(f)
            
            # Garantir que o diretório local existe
            os.makedirs(os.path.dirname(local_config_path), exist_ok=True)
            
            # Sobrescrever arquivo local com a configuração principal
            with open(local_config_path, 'w') as f:
                json.dump(config, f, indent=4)
            
            log_info(f"Arquivo de configuração local atualizado com sucesso: {local_config_path}")
            return config
        else:
            log_error(f"Arquivo de configuração principal não encontrado: {main_config_path}")
            return None
    except Exception as e:
        log_exception(f"Erro ao sincronizar arquivos de configuração: {str(e)}")
        return None

# Load configuration from file
def load_config():
    """Carrega a configuração do arquivo principal e sincroniza com o local"""
    # Forçar sincronização dos arquivos de configuração
    config = force_config_sync()
    
    if not config:
        log_error("Falha ao carregar configuração. Verifique os logs para mais detalhes.")
        sys.exit(1)
    
    return config

# Load configuration
config = load_config()

# Set configuration values
chave_ativacao = config.get("activation_key", "")
if not chave_ativacao:
    log_error("Chave de ativação não encontrada no arquivo de configuração.")
    log_info("Por favor, adicione uma activation_key ao guard_config.json.")
    sys.exit(1)

server_ip = config.get("server_ip", "")
if not server_ip:
    log_error("IP do servidor não encontrado no arquivo de configuração.")
    log_info("Por favor, adicione um server_ip ao guard_config.json.")
    sys.exit(1)

server_port = config.get("server_port", "")
if not server_port:
    log_error("Porta do servidor não encontrada no arquivo de configuração.")
    log_info("Por favor, adicione um server_port ao guard_config.json.")
    sys.exit(1)

# Construir URL base com prefixo /api/
BASE_URL = f"http://{server_ip}:{server_port}"
API_URL = f"{BASE_URL}/api"  # Adicionar prefixo /api/
SERVER_URL = API_URL  # Para compatibilidade com código existente

# Outras configurações
ram = "512M"