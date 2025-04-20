from math import log
import os
import subprocess
import requests
import re
import json
import platform
import socket
import uuid
import tempfile
from typing import Optional, Dict, Any, List, Tuple
from network import carregar_id
from system_utils import os_update, os_install, detect_os_distribution, verificar_sudo_disponivel
from config import SERVER_URL
from logger import log_info, log_warning, log_error, log_critical, log_exception

# Core Wazuh verification functions
def verificar_wazuh_instalado() -> bool:
    """Verify Wazuh agent installation status"""
    try:
        installed = os.path.exists('/var/ossec/bin/wazuh-control') or os.path.exists('/var/ossec/bin/ossec-control')
        log_info(f'Verificação de instalação do Wazuh: {installed}')
        return installed
    except Exception as e:
        log_exception('Erro ao verificar instalação do Wazuh')
        return False

def verificar_chave_wazuh_importada() -> bool:
    """Verify if Wazuh agent key is properly imported"""
    client_keys_path = "/var/ossec/etc/client.keys"
    try:
        if not os.path.exists(client_keys_path):
            log_warning("Arquivo client.keys não encontrado.")
            return False
            
        with open(client_keys_path, 'r') as f:
            content = f.read().strip()
            if not content:
                log_warning("Arquivo client.keys está vazio.")
                return False
                
            # Valid key format: ID NAME IP KEY
            if not re.search(r'^\d+\s+\S+\s+\S+\s+\S+$', content, re.MULTILINE):
                log_warning("Arquivo client.keys não contém uma chave válida.")
                return False
                
        log_info("Chave do Wazuh já importada e válida.")
        return True
    except Exception as e:
        log_exception(f"Erro ao verificar chave do Wazuh: {str(e)}")
        return False

def reiniciar_wazuh() -> bool:
    """Restart Wazuh service with proper error handling"""
    try:
        # Find appropriate control script
        control_script = '/var/ossec/bin/wazuh-control'
        if not os.path.exists(control_script):
            control_script = '/var/ossec/bin/ossec-control'
        
        comando_base = [control_script, 'restart']
        
        if os.geteuid() != 0 and verificar_sudo_disponivel():
            comando_base.insert(0, 'sudo')
        
        log_info("Reiniciando serviço do Wazuh...")
        subprocess.run(comando_base, check=True, capture_output=True)
        log_info("Serviço do Wazuh reiniciado com sucesso.")
        return True
    except subprocess.CalledProcessError as e:
        log_error(f"Erro ao reiniciar o serviço do Wazuh: {str(e)}")
        return False
    except Exception as e:
        log_exception(f"Erro inesperado ao reiniciar Wazuh: {str(e)}")
        return False

def verificar_wazuh_running() -> bool:
    """Check if Wazuh agent is currently running"""
    try:
        control_script = '/var/ossec/bin/wazuh-control'
            
        usar_sudo = os.geteuid() != 0 and verificar_sudo_disponivel()
        
        comando = [control_script, 'status']
        if usar_sudo:
            comando.insert(0, 'sudo')
        
        resultado = subprocess.run(comando, capture_output=True, text=True)
        
        is_running = "wazuh-agentd is running" in resultado.stdout or "ossec-agentd is running" in resultado.stdout
        if is_running:
            log_info("Wazuh está em execução.")
        else:
            log_warning("Wazuh não está em execução.")
        return is_running
    except Exception as e:
        log_error(f"Erro ao verificar status do Wazuh: {str(e)}")
        return False

def get_wazuh_manager_ip() -> Optional[str]:
    """Extract Wazuh manager IP from configuration file"""
    config_file = "/var/guardiao/guard_config.json"
    try:
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                config = json.load(f)
                if "server_ip" in config:
                    log_info(f"Usando IP do servidor: {config['server_ip']}")
                    return config['server_ip']
        
        log_warning("IP do servidor não encontrado no arquivo de configuração")
        return None
    except Exception as e:
        log_exception(f"Erro ao obter IP do servidor: {str(e)}")
        return None

def generate_curl_command(url: str, method: str = "GET", headers: Optional[Dict] = None, data: Optional[Dict] = None) -> str:
    """Generate curl command for debugging API requests"""
    curl_cmd = f"curl -X {method} '{url}'"
    
    if headers:
        for key, value in headers.items():
            curl_cmd += f" -H '{key}: {value}'"
    
    if data:
        json_data = json.dumps(data).replace("'", "\\'")
        curl_cmd += f" -d '{json_data}'"
    
    return curl_cmd

def get_system_info() -> Tuple[str, str, str, str, str]:
    """Collect system information for agent registration"""
    # Get hostname and IP
    hostname = socket.gethostname()
    try:
        ip = socket.gethostbyname(socket.gethostname())
    except:
        ip = "any"
    
    # Get OS information
    sistema = f"{platform.system()} {platform.release()}"
    versao = "1.0"  # Agent version
    
    # Get MAC address
    try:
        mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                       for elements in range(0, 8*6, 8)][::-1])
    except:
        mac = "00:00:00:00:00:00"
        
    return hostname, ip, sistema, versao, mac

def get_activation_key() -> Optional[str]:
    """Get activation key from configuration file"""
    config_file = "/var/guardiao/guard_config.json"
    try:
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                config = json.load(f)
                return config.get('activation_key')
    except Exception as e:
        log_warning(f"Erro ao ler chave de ativação: {str(e)}")
    return None

def instalar_wazuh(wazuh_manager: Optional[str] = None) -> bool:
    """Install Wazuh agent with proper configuration"""
    try:
        if verificar_wazuh_instalado():
            log_info("Wazuh já está instalado.")
            return True

        distro = detect_os_distribution()
        if not distro:
            log_error("Distribuição do sistema não detectada.")
            return False
        
        if not wazuh_manager:
            wazuh_manager = get_wazuh_manager_ip()
            if not wazuh_manager:
                log_warning("IP do servidor não encontrado. Usando localhost.")
                wazuh_manager = "localhost"
        
        # Download configuration file
        ossec_conf_path = "/tmp/ossec.conf.downloaded"
        ossec_conf_url = f"http://{wazuh_manager}:5002/download/ossec.conf"
        
        try:
            response = requests.get(ossec_conf_url, timeout=10)
            if response.status_code == 200:
                with open(ossec_conf_path, 'wb') as f:
                    f.write(response.content)
                log_info("Arquivo ossec.conf baixado com sucesso.")
            else:
                log_warning(f"Falha ao baixar ossec.conf: {response.status_code}")
        except Exception as e:
            log_warning(f"Erro ao baixar ossec.conf: {str(e)}")
        
        # Install based on distribution
        if distro in ["debian", "ubuntu"]:
            try:
                # Check if installed during process
                if verificar_wazuh_instalado():
                    return True
                
                # Add GPG key
                log_info("Adicionando chave GPG do Wazuh...")
                gpg_cmd = "curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg"
                if os.geteuid() != 0 and verificar_sudo_disponivel():
                    gpg_cmd = "sudo " + gpg_cmd
                
                subprocess.run(gpg_cmd, shell=True, check=True)
                
                if verificar_wazuh_instalado():
                    return True
                
                # Add repository
                log_info("Adicionando repositório do Wazuh...")
                repo_cmd = 'echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list'
                if os.geteuid() != 0 and verificar_sudo_disponivel():
                    repo_cmd = "sudo " + repo_cmd
                
                subprocess.run(repo_cmd, shell=True, check=True)
                
                if verificar_wazuh_instalado():
                    return True
                
                # Update repositories
                log_info("Atualizando repositórios...")
                update_cmd = "apt-get update"
                if os.geteuid() != 0 and verificar_sudo_disponivel():
                    update_cmd = "sudo " + update_cmd
                
                subprocess.run(update_cmd, shell=True, check=True)
                
                if verificar_wazuh_instalado():
                    return True
                
                # Install Wazuh agent
                log_info(f"Instalando agente Wazuh com manager: {wazuh_manager}")
                install_cmd = f'WAZUH_MANAGER="{wazuh_manager}" apt-get install -y wazuh-agent'
                if os.geteuid() != 0 and verificar_sudo_disponivel():
                    install_cmd = "sudo " + install_cmd
                
                subprocess.run(install_cmd, shell=True, check=True)
                
                # Find control script
                control_paths = [
                    '/var/ossec/bin/wazuh-control',
                    '/usr/bin/wazuh-control'
                ]
                
                control_script = next((path for path in control_paths if os.path.exists(path)), None)
                
                if not control_script:
                    log_error("Script de controle não encontrado após instalação")
                    return False
                
                # Copy downloaded config if available
                if os.path.exists(ossec_conf_path):
                    ossec_dest_path = "/var/ossec/etc/ossec.conf"
                    ossec_etc_dir = "/var/ossec/etc"
                    
                    if os.path.exists(ossec_etc_dir):
                        try:
                            copy_cmd = f"cp {ossec_conf_path} {ossec_dest_path}"
                            if os.geteuid() != 0 and verificar_sudo_disponivel():
                                copy_cmd = "sudo " + copy_cmd
                            
                            subprocess.run(copy_cmd, shell=True, check=True)
                            
                            chmod_cmd = f"chmod 640 {ossec_dest_path}"
                            if os.geteuid() != 0 and verificar_sudo_disponivel():
                                chmod_cmd = "sudo " + chmod_cmd
                            
                            subprocess.run(chmod_cmd, shell=True, check=True)
                            log_info("Arquivo ossec.conf configurado.")
                        except Exception as e:
                            log_warning(f"Erro ao configurar ossec.conf: {str(e)}")
                
                # Start agent
                log_info("Iniciando agente Wazuh...")
                activate_cmd = f"{control_script} start"
                if os.geteuid() != 0 and verificar_sudo_disponivel():
                    activate_cmd = "sudo " + activate_cmd
                
                subprocess.run(activate_cmd, shell=True, check=True)
                return True
                
            except subprocess.CalledProcessError as e:
                log_error(f"Erro na instalação: {str(e)}")
                return False
            except Exception as e:
                log_exception(f"Erro inesperado: {str(e)}")
                return False
            finally:
                if os.path.exists(ossec_conf_path):
                    try:
                        os.remove(ossec_conf_path)
                    except:
                        pass
        else:
            log_error(f"Sistema não suportado: {distro}")
            return False
    except Exception as e:
        log_exception(f"Falha na instalação: {str(e)}")
        return False

def registrar_wazuh_no_guardiao(wazuh_manager: Optional[str] = None, api_token: Optional[str] = None) -> bool:
    """Register Wazuh agent with Guardian server"""
    try:
        log_info("Registrando agente Wazuh no servidor Guardião...")
        
        if not verificar_wazuh_instalado():
            log_error("Wazuh não instalado.")
            return False
        
        if not wazuh_manager:
            wazuh_manager = get_wazuh_manager_ip()
            if not wazuh_manager:
                wazuh_manager = "localhost"
                log_warning(f"Usando IP padrão: {wazuh_manager}")
        
        # Get system information
        hostname, ip, sistema, versao, mac = get_system_info()
        
        # Get activation key
        activation_key = get_activation_key()
        if not activation_key:
            log_error("Chave de ativação não encontrada.")
            return False
        
        # Prepare data payload - formato simplificado conforme especificação
        data = {
            "chave": activation_key,
            "name": hostname,
            "id": carregar_id()
        }
        
        # Build server URL
        server_url = SERVER_URL if SERVER_URL else f"http://{wazuh_manager}:5002"
        endpoint = "/registro-ossec"
        request_url = f"{server_url}{endpoint}"
        
        headers = {'Content-Type': 'application/json'}
        if api_token:
            headers['Authorization'] = api_token

        # Gerar comando curl para debug
        curl_cmd = generate_curl_command(request_url, method="POST", headers=headers, data=data)
        log_info(f"CURL_DEBUG: {curl_cmd}")
        
        try:
            response = requests.post(
                request_url,
                json=data,
                headers=headers,
                timeout=30
            )
            
            log_info(f"Resposta: Status {response.status_code}")
            
            if response.status_code == 200:
                try:
                    response_data = response.json()
                    
                    if response_data.get('status') != 'sucesso':
                        log_error(f"Erro do servidor: {response_data.get('mensagem')}")
                        log_error(f"Comando curl: {curl_cmd}")
                        return False
                    
                    agent_key = response_data.get('activation_key')
                    if not agent_key:
                        log_error("Chave do agente não retornada.")
                        log_error(f"Comando curl: {curl_cmd}")
                        return False
                    
                    log_info(f"Agente registrado com hostname: {response_data.get('ossec_hostname')}")
                    return importar_chave_wazuh(agent_key)
                    
                except json.JSONDecodeError:
                    log_warning(f"Resposta não é JSON válido: {response.text[:100]}...")
                    log_error(f"Headers: {headers}")
                    log_error(f"Dados: {data}")
                    log_error(f"Comando curl: {curl_cmd}")
                    return False
            else:
                log_error(f"Erro de registro: {response.status_code}")
                log_error(f"Comando curl: {curl_cmd}")
                return False
                
        except requests.RequestException as e:
            log_error(f"Erro HTTP para {endpoint}: {str(e)}")
            log_error(f"Comando curl: {curl_cmd}")
            return False
            
    except Exception as e:
        log_exception(f"Erro no registro: {str(e)}")
        return False

def importar_chave_wazuh(agent_key: str) -> bool:
    """Import Wazuh agent key"""
    try:
        log_info("Importando chave do agente...")
        
        if verificar_chave_wazuh_importada():
            log_info("Chave já importada.")
            return True
        
        # Log da chave para debug
        log_info(f"Chave a ser importada: {agent_key}")
        
        manage_agents = '/var/ossec/bin/manage_agents'
        if not os.path.exists(manage_agents):
            log_error("Script manage_agents não encontrado.")
            return False
        
        # Extrai apenas a parte Base64 da chave
        key_match = re.search(r'([A-Za-z0-9+/=]+)$', agent_key)
        if not key_match:
            log_error("Formato de chave inválido")
            return False
            
        key_base64 = key_match.group(1)
        
        # Importa a chave usando echo
        import_cmd = f"echo 'y' | {manage_agents} -i {key_base64}"
        if os.geteuid() != 0 and verificar_sudo_disponivel():
            import_cmd = f"sudo {import_cmd}"
        
        log_info(f"Executando: {import_cmd}")
        result = subprocess.run(import_cmd, shell=True, capture_output=True, text=True)
        
        # Log completo do resultado para debug
        log_info(f"Saída do comando: {result.stdout}")
        if result.stderr:
            log_warning(f"Erro do comando: {result.stderr}")
        
        success_indicators = ["Added successfully", "successfully added"]
        if not any(indicator in result.stdout.lower() for indicator in success_indicators):
            log_error(f"Erro na importação. Saída: {result.stdout}")
            log_error(f"Erro: {result.stderr}")
            return False
        
        log_info("Chave importada com sucesso.")
        return reiniciar_wazuh()
            
    except Exception as e:
        log_exception(f"Erro na importação: {str(e)}")
        return False

def configurar_wazuh(wazuh_manager: Optional[str] = None) -> bool:
    """Configure Wazuh agent with server connection"""
    try:
        log_info("Configurando agente Wazuh...")
        
        if not verificar_wazuh_instalado():
            log_error("Wazuh não instalado.")
            return False
        
        if not wazuh_manager:
            wazuh_manager = get_wazuh_manager_ip()
            if not wazuh_manager:
                wazuh_manager = "localhost"
                log_warning(f"Usando IP padrão: {wazuh_manager}")
        
        if verificar_chave_wazuh_importada():
            log_info("Agente já registrado.")
            
            if not verificar_wazuh_running():
                log_warning("Agente não está em execução.")
                reiniciar_wazuh()
            
            return True
        
        log_info("Iniciando registro do agente...")
        return registrar_wazuh_no_guardiao(wazuh_manager)
        
    except Exception as e:
        log_exception(f"Erro na configuração: {str(e)}")
        return False

def setup_wazuh(wazuh_manager: Optional[str] = None) -> bool:
    """Complete Wazuh setup process"""
    try:
        log_info("Iniciando setup do Wazuh...")
        
        if not wazuh_manager:
            wazuh_manager = get_wazuh_manager_ip()
        
        if not verificar_wazuh_instalado():
            log_info("Instalando Wazuh...")
            if not instalar_wazuh(wazuh_manager):
                log_error("Falha na instalação.")
                return False
        
        log_info("Configurando Wazuh...")
        if not configurar_wazuh(wazuh_manager):
            log_error("Falha na configuração.")
            return False
            
        log_info("Reiniciando serviço...")
        if not reiniciar_wazuh():
            log_error("Falha ao reiniciar serviço.")
            return False
            
        log_info("Setup concluído com sucesso.")
        return True
        
    except Exception as e:
        log_exception(f"Erro no setup: {str(e)}")
        return False

# Backward compatibility aliases
verificar_ossec_instalado = verificar_wazuh_instalado
verificar_chave_ossec_importada = verificar_chave_wazuh_importada
verificar_ossec_running = verificar_wazuh_running
reiniciar_ossec = reiniciar_wazuh
instalar_ossec = lambda manager=None: instalar_wazuh(manager)
setup_ossec = lambda activation_key=None: setup_wazuh(get_wazuh_manager_ip())