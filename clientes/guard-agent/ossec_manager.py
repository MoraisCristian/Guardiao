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

# Core OSSEC verification functions
def verificar_ossec_instalado() -> bool:
    """Verify OSSEC agent installation status"""
    try:
        installed = os.path.exists('/var/ossec/bin/ossec-control')
        log_info(f'Verificação de instalação do OSSEC: {installed}')
        return installed
    except Exception as e:
        log_exception('Erro ao verificar instalação do OSSEC')
        return False

def verificar_chave_ossec_importada() -> bool:
    """Verify if OSSEC agent key is properly imported"""
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
                
        log_info("Chave do OSSEC já importada e válida.")
        return True
    except Exception as e:
        log_exception(f"Erro ao verificar chave do OSSEC: {str(e)}")
        return False

def reiniciar_ossec() -> bool:
    """Restart OSSEC service with proper error handling"""
    try:
        # Find appropriate control script
        control_script = '/var/ossec/bin/ossec-control'
        
        comando_base = [control_script, 'restart']
        
        if os.geteuid() != 0 and verificar_sudo_disponivel():
            comando_base.insert(0, 'sudo')
        
        log_info("Reiniciando serviço do OSSEC...")
        subprocess.run(comando_base, check=True, capture_output=True)
        log_info("Serviço do OSSEC reiniciado com sucesso.")
        return True
    except subprocess.CalledProcessError as e:
        log_error(f"Erro ao reiniciar o serviço do OSSEC: {str(e)}")
        return False
    except Exception as e:
        log_exception(f"Erro inesperado ao reiniciar OSSEC: {str(e)}")
        return False

def verificar_ossec_running() -> bool:
    """Check if OSSEC agent is currently running"""
    try:
        control_script = '/var/ossec/bin/ossec-control'
            
        usar_sudo = os.geteuid() != 0 and verificar_sudo_disponivel()
        
        comando = [control_script, 'status']
        if usar_sudo:
            comando.insert(0, 'sudo')
        
        resultado = subprocess.run(comando, capture_output=True, text=True)
        
        is_running = "ossec-agentd is running" in resultado.stdout
        if is_running:
            log_info("OSSEC está em execução.")
        else:
            log_warning("OSSEC não está em execução.")
        return is_running
    except Exception as e:
        log_error(f"Erro ao verificar status do OSSEC: {str(e)}")
        return False

def get_ossec_manager_ip() -> Optional[str]:
    """Extract OSSEC manager IP from configuration file"""
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

def instalar_ossec(ossec_manager: Optional[str] = None) -> bool:
    """Install OSSEC agent with proper configuration"""
    try:
        if verificar_ossec_instalado():
            log_info("OSSEC já está instalado.")
            return True

        distro = detect_os_distribution()
        if not distro:
            log_error("Distribuição do sistema não detectada.")
            return False
        
        if not ossec_manager:
            ossec_manager = get_ossec_manager_ip()
            if not ossec_manager:
                log_warning("IP do servidor não encontrado. Usando localhost.")
                ossec_manager = "localhost"
        
        # Download configuration file
        ossec_conf_path = "/tmp/ossec.conf.downloaded"
        ossec_conf_url = f"http://{ossec_manager}:5002/download/ossec.conf"
        
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
        
        # Instalar dependências necessárias
        log_info("Instalando dependências necessárias...")
        if distro in ["debian", "ubuntu"]:
            try:
                # Instalar dependências
                deps_cmd = "apt-get update && apt-get install -y wget apt-transport-https gnupg"
                if os.geteuid() != 0 and verificar_sudo_disponivel():
                    deps_cmd = "sudo " + deps_cmd
                
                subprocess.run(deps_cmd, shell=True, check=True)
                log_info("Dependências instaladas com sucesso.")
                
                # Baixar o script atomic installer
                log_info("Baixando script do instalador Atomic...")
                with tempfile.TemporaryDirectory() as temp_dir:
                    atomic_script = os.path.join(temp_dir, "atomic_installer.sh")
                    
                    download_cmd = f"wget -q -O {atomic_script} https://updates.atomicorp.com/installers/atomic"
                    if os.geteuid() != 0 and verificar_sudo_disponivel():
                        download_cmd = "sudo " + download_cmd
                    
                    subprocess.run(download_cmd, shell=True, check=True)
                    
                    # Dar permissão de execução ao script
                    chmod_cmd = f"chmod +x {atomic_script}"
                    if os.geteuid() != 0 and verificar_sudo_disponivel():
                        chmod_cmd = "sudo " + chmod_cmd
                    
                    subprocess.run(chmod_cmd, shell=True, check=True)
                    
                    # Executar o script de instalação do repositório
                    log_info("Instalando repositório Atomicorp...")
                    install_repo_cmd = f"bash {atomic_script}"
                    if os.geteuid() != 0 and verificar_sudo_disponivel():
                        install_repo_cmd = "sudo " + install_repo_cmd
                    
                    # Usar echo para responder automaticamente às perguntas do script
                    install_repo_cmd = f"echo -e 'yes\nyes\n' | {install_repo_cmd}"
                    subprocess.run(install_repo_cmd, shell=True, check=True)
                
                # Atualizar repositórios
                log_info("Atualizando repositórios...")
                update_cmd = "apt-get update"
                if os.geteuid() != 0 and verificar_sudo_disponivel():
                    update_cmd = "sudo " + update_cmd
                
                subprocess.run(update_cmd, shell=True, check=True)
                
                # Instalar o agente OSSEC
                log_info(f"Instalando agente OSSEC com manager: {ossec_manager}")
                install_cmd = "apt-get install -y ossec-hids-agent"
                if os.geteuid() != 0 and verificar_sudo_disponivel():
                    install_cmd = "sudo " + install_cmd
                
                subprocess.run(install_cmd, shell=True, check=True)
                
                # Verificar se a instalação foi bem-sucedida
                if not os.path.exists('/var/ossec'):
                    log_warning("Diretório /var/ossec não encontrado após instalação. Tentando reinstalar...")
                    
                    # Reinstalar o pacote OSSEC
                    reinstall_cmd = "apt-get install --reinstall ossec-hids-agent"
                    if os.geteuid() != 0 and verificar_sudo_disponivel():
                        reinstall_cmd = "sudo " + reinstall_cmd
                    
                    subprocess.run(reinstall_cmd, shell=True, check=True)
                    
                    # Reparar pacotes quebrados
                    repair_cmd = "dpkg --configure -a"
                    if os.geteuid() != 0 and verificar_sudo_disponivel():
                        repair_cmd = "sudo " + repair_cmd
                    
                    subprocess.run(repair_cmd, shell=True, check=True)
                    
                    log_info("Tentativa de reinstalação do OSSEC concluída.")
                
                # Verificar se a instalação foi bem-sucedida
                if verificar_ossec_instalado():
                    log_info("OSSEC instalado com sucesso via repositório Atomicorp.")
                    
                    # Configurar o OSSEC com o IP do servidor
                    if os.path.exists('/var/ossec/etc/ossec.conf'):
                        log_info(f"Configurando OSSEC manager para: {ossec_manager}")
                        
                        # Criar um arquivo ossec.conf correto
                        ossec_conf_content = f"""<ossec_config>
  <client>
    <server-ip>{ossec_manager}</server-ip>
    <server-port>1514</server-port>
    <protocol>tcp</protocol>
    <config-profile>agent</config-profile>
    <notify_time>30</notify_time>
    <auto_restart>yes</auto_restart>
  </client>
</ossec_config>
"""
                        # Salvar o arquivo temporário
                        temp_conf = "/tmp/ossec_temp.conf"
                        with open(temp_conf, 'w') as f:
                            f.write(ossec_conf_content)
                        
                        # Copiar para o local correto
                        copy_cmd = f"cp {temp_conf} /var/ossec/etc/ossec.conf"
                        if os.geteuid() != 0 and verificar_sudo_disponivel():
                            copy_cmd = "sudo " + copy_cmd
                        
                        subprocess.run(copy_cmd, shell=True, check=True)
                        
                        # Ajustar permissões
                        chmod_cmd = "chmod 640 /var/ossec/etc/ossec.conf"
                        if os.geteuid() != 0 and verificar_sudo_disponivel():
                            chmod_cmd = "sudo " + chmod_cmd
                        
                        subprocess.run(chmod_cmd, shell=True, check=True)
                        
                        # Ajustar proprietário
                        chown_cmd = "chown root:ossec /var/ossec/etc/ossec.conf"
                        if os.geteuid() != 0 and verificar_sudo_disponivel():
                            chown_cmd = "sudo " + chown_cmd
                        
                        subprocess.run(chown_cmd, shell=True, check=True)
                    
                    # Iniciar o agente OSSEC
                    log_info("Iniciando agente OSSEC...")
                    start_cmd = "/var/ossec/bin/ossec-control start"
                    if os.geteuid() != 0 and verificar_sudo_disponivel():
                        start_cmd = "sudo " + start_cmd
                    
                    subprocess.run(start_cmd, shell=True, check=True)
                    return True
                else:
                    log_error("Falha na instalação do OSSEC via repositório Atomicorp.")
                    return False
                
            except subprocess.CalledProcessError as e:
                log_error(f"Erro na instalação: {str(e)}")
                return False
            except Exception as e:
                log_exception(f"Erro inesperado: {str(e)}")
                return False
            
        elif distro in ["centos", "rhel", "fedora", "almalinux", "rocky"]:
            try:
                # Instalar dependências
                deps_cmd = "yum install -y wget"
                if os.geteuid() != 0 and verificar_sudo_disponivel():
                    deps_cmd = "sudo " + deps_cmd
                
                subprocess.run(deps_cmd, shell=True, check=True)
                log_info("Dependências instaladas com sucesso.")
                
                # Baixar o script atomic installer
                log_info("Baixando script do instalador Atomic...")
                with tempfile.TemporaryDirectory() as temp_dir:
                    atomic_script = os.path.join(temp_dir, "atomic_installer.sh")
                    
                    download_cmd = f"wget -q -O {atomic_script} https://updates.atomicorp.com/installers/atomic"
                    if os.geteuid() != 0 and verificar_sudo_disponivel():
                        download_cmd = "sudo " + download_cmd
                    
                    subprocess.run(download_cmd, shell=True, check=True)
                    
                    # Dar permissão de execução ao script
                    chmod_cmd = f"chmod +x {atomic_script}"
                    if os.geteuid() != 0 and verificar_sudo_disponivel():
                        chmod_cmd = "sudo " + chmod_cmd
                    
                    subprocess.run(chmod_cmd, shell=True, check=True)
                    
                    # Executar o script de instalação do repositório
                    log_info("Instalando repositório Atomicorp...")
                    install_repo_cmd = f"bash {atomic_script}"
                    if os.geteuid() != 0 and verificar_sudo_disponivel():
                        install_repo_cmd = "sudo " + install_repo_cmd
                    
                    # Usar echo para responder automaticamente às perguntas do script
                    install_repo_cmd = f"echo -e 'yes\nyes\n' | {install_repo_cmd}"
                    subprocess.run(install_repo_cmd, shell=True, check=True)
                
                # Instalar o agente OSSEC
                log_info(f"Instalando agente OSSEC com manager: {ossec_manager}")
                install_cmd = "yum install -y ossec-hids-agent"
                if os.geteuid() != 0 and verificar_sudo_disponivel():
                    install_cmd = "sudo " + install_cmd
                
                subprocess.run(install_cmd, shell=True, check=True)
                
                # Verificar se a instalação foi bem-sucedida
                if verificar_ossec_instalado():
                    log_info("OSSEC instalado com sucesso via repositório Atomicorp.")
                    
                    # Configurar o OSSEC com o IP do servidor
                    if os.path.exists('/var/ossec/etc/ossec.conf'):
                        log_info(f"Configurando OSSEC manager para: {ossec_manager}")
                        
                        # Criar um arquivo ossec.conf correto
                        ossec_conf_content = f"""<ossec_config>
  <client>
    <server-ip>{ossec_manager}</server-ip>
    <server-port>1514</server-port>
    <protocol>tcp</protocol>
    <config-profile>agent</config-profile>
    <notify_time>30</notify_time>
    <auto_restart>yes</auto_restart>
  </client>
</ossec_config>
"""
                        # Salvar o arquivo temporário
                        temp_conf = "/tmp/ossec_temp.conf"
                        with open(temp_conf, 'w') as f:
                            f.write(ossec_conf_content)
                        
                        # Copiar para o local correto
                        copy_cmd = f"cp {temp_conf} /var/ossec/etc/ossec.conf"
                        if os.geteuid() != 0 and verificar_sudo_disponivel():
                            copy_cmd = "sudo " + copy_cmd
                        
                        subprocess.run(copy_cmd, shell=True, check=True)
                        
                        # Ajustar permissões
                        chmod_cmd = "chmod 640 /var/ossec/etc/ossec.conf"
                        if os.geteuid() != 0 and verificar_sudo_disponivel():
                            chmod_cmd = "sudo " + chmod_cmd
                        
                        subprocess.run(chmod_cmd, shell=True, check=True)
                        
                        # Ajustar proprietário
                        chown_cmd = "chown root:ossec /var/ossec/etc/ossec.conf"
                        if os.geteuid() != 0 and verificar_sudo_disponivel():
                            chown_cmd = "sudo " + chown_cmd
                        
                        subprocess.run(chown_cmd, shell=True, check=True)
                    
                    # Iniciar o agente OSSEC
                    log_info("Iniciando agente OSSEC...")
                    start_cmd = "/var/ossec/bin/ossec-control start"
                    if os.geteuid() != 0 and verificar_sudo_disponivel():
                        start_cmd = "sudo " + start_cmd
                    
                    subprocess.run(start_cmd, shell=True, check=True)
                    return True
                else:
                    log_error("Falha na instalação do OSSEC via repositório Atomicorp.")
                    return False
                
            except subprocess.CalledProcessError as e:
                log_error(f"Erro na instalação: {str(e)}")
                return False
            except Exception as e:
                log_exception(f"Erro inesperado: {str(e)}")
                return False
        else:
            log_error(f"Sistema não suportado: {distro}")
            return False
    except Exception as e:
        log_exception(f"Falha na instalação: {str(e)}")
        return False

def registrar_ossec_no_guardiao(ossec_manager: Optional[str] = None, api_token: Optional[str] = None) -> bool:
    """Register OSSEC agent with Guardian server"""
    try:
        log_info("Registrando agente OSSEC no servidor Guardião...")
        
        if not verificar_ossec_instalado():
            log_error("OSSEC não instalado.")
            return False
        
        if not ossec_manager:
            ossec_manager = get_ossec_manager_ip()
            if not ossec_manager:
                ossec_manager = "localhost"
                log_warning(f"Usando IP padrão: {ossec_manager}")
        
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
        server_url = SERVER_URL if SERVER_URL else f"http://{ossec_manager}:5002"
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
                    return importar_chave_ossec(agent_key)
                    
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

def importar_chave_ossec(agent_key: str) -> bool:
    """Import OSSEC agent key"""
    try:
        log_info("Importando chave do agente...")
        
        if verificar_chave_ossec_importada():
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
        return reiniciar_ossec()
            
    except Exception as e:
        log_exception(f"Erro na importação: {str(e)}")
        return False

def configurar_ossec(ossec_manager: Optional[str] = None) -> bool:
    """Configure OSSEC agent with server connection"""
    try:
        log_info("Configurando agente OSSEC...")
        
        if not verificar_ossec_instalado():
            log_error("OSSEC não instalado.")
            return False
        
        if not ossec_manager:
            ossec_manager = get_ossec_manager_ip()
            if not ossec_manager:
                ossec_manager = "localhost"
                log_warning(f"Usando IP padrão: {ossec_manager}")
        
        if verificar_chave_ossec_importada():
            log_info("Agente já registrado.")
            
            if not verificar_ossec_running():
                log_warning("Agente não está em execução.")
                reiniciar_ossec()
            
            return True
        
        log_info("Iniciando registro do agente...")
        return registrar_ossec_no_guardiao(ossec_manager)
        
    except Exception as e:
        log_exception(f"Erro na configuração: {str(e)}")
        return False

def setup_ossec(ossec_manager: Optional[str] = None) -> bool:
    """Complete OSSEC setup process"""
    try:
        log_info("Iniciando setup do OSSEC...")
        
        if not ossec_manager:
            ossec_manager = get_ossec_manager_ip()
        
        if not verificar_ossec_instalado():
            log_info("Instalando OSSEC...")
            if not instalar_ossec(ossec_manager):
                log_error("Falha na instalação.")
                return False
        
        log_info("Configurando OSSEC...")
        if not configurar_ossec(ossec_manager):
            log_error("Falha na configuração.")
            return False
            
        log_info("Reiniciando serviço...")
        if not reiniciar_ossec():
            log_error("Falha ao reiniciar serviço.")
            return False
            
        log_info("Setup concluído com sucesso.")
        return True
        
    except Exception as e:
        log_exception(f"Erro no setup: {str(e)}")
        return False

# Backward compatibility aliases for Wazuh
verificar_wazuh_instalado = verificar_ossec_instalado
verificar_chave_wazuh_importada = verificar_chave_ossec_importada
verificar_wazuh_running = verificar_ossec_running
reiniciar_wazuh = reiniciar_ossec
instalar_wazuh = lambda manager=None: instalar_ossec(manager)
setup_wazuh = lambda activation_key=None: setup_ossec(get_ossec_manager_ip())