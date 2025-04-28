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
from network import carregar_id, enviar_mensagem
from system_utils import os_update, os_install, detect_os_distribution, verificar_sudo_disponivel
from config import SERVER_URL
from logger import log_info, log_warning, log_error, log_debug, log_critical, log_exception

# Core OSSEC verification functions
def executar_comando(comando: List[str], usar_sudo: bool = False, check: bool = False) -> subprocess.CompletedProcess:
    """Executa um comando com ou sem sudo"""
    cmd_str = ' '.join(comando)
    if usar_sudo and os.geteuid() != 0 and verificar_sudo_disponivel():
        comando.insert(0, 'sudo')
        cmd_str = 'sudo ' + cmd_str
    
    log_info(f"Executando comando: {cmd_str}")
    resultado = subprocess.run(comando, capture_output=True, text=True, check=check)
    log_info(f"Resultado do comando: Código de saída={resultado.returncode}")
    if resultado.stdout:
        log_info(f"Saída do comando: {resultado.stdout.strip()}")
    if resultado.stderr:
        log_warning(f"Erro do comando: {resultado.stderr.strip()}")
    
    return resultado

def verificar_ossec_instalado() -> bool:
    """Verify OSSEC agent installation status"""
    try:
        # Verificar tanto o binário quanto o arquivo de configuração
        binario_existe = os.path.exists('/var/ossec/bin/ossec-control')
        config_existe = os.path.exists('/var/ossec/etc/ossec.conf')
        
        if binario_existe and config_existe:
            log_info('OSSEC instalado e configurado corretamente')
            return True
        elif binario_existe and not config_existe:
            log_warning('OSSEC instalado, mas arquivo de configuração ausente')
            return False
        else:
            log_info('OSSEC não está instalado')
            return False
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
        # Verificar se o arquivo client.keys existe
        if not os.path.exists("/var/ossec/etc/client.keys"):
            log_error("Arquivo client.keys não encontrado. Impossível reiniciar o OSSEC.")
            return False
            
        # Find appropriate control script
        control_script = '/var/ossec/bin/ossec-control'
        
        # Verificar status atual
        status_cmd = [control_script, 'status']
        if os.geteuid() != 0 and verificar_sudo_disponivel():
            status_cmd.insert(0, 'sudo')
            
        log_info(f"Verificando status atual: {' '.join(status_cmd)}")
        status_result = subprocess.run(status_cmd, capture_output=True, text=True)
        log_info(f"Status atual do OSSEC: {status_result.stdout}")
        
        # Parar o serviço primeiro
        stop_cmd = [control_script, 'stop']
        if os.geteuid() != 0 and verificar_sudo_disponivel():
            stop_cmd.insert(0, 'sudo')
            
        log_info(f"Parando serviço do OSSEC: {' '.join(stop_cmd)}")
        stop_result = subprocess.run(stop_cmd, capture_output=True, text=True)
        log_info(f"Resultado da parada: {stop_result.stdout}")
        if stop_result.stderr:
            log_warning(f"Erro ao parar: {stop_result.stderr}")
        
        # Aguardar um momento
        import time
        log_info("Aguardando 2 segundos...")
        time.sleep(2)
        
        # Iniciar o serviço
        start_cmd = [control_script, 'start']
        if os.geteuid() != 0 and verificar_sudo_disponivel():
            start_cmd.insert(0, 'sudo')
        
        log_info(f"Iniciando serviço do OSSEC: {' '.join(start_cmd)}")
        start_result = subprocess.run(start_cmd, capture_output=True, text=True)
        log_info(f"Resultado do início: {start_result.stdout}")
        if start_result.stderr:
            log_warning(f"Erro ao iniciar: {start_result.stderr}")
        
        # Verificar se o serviço está em execução
        log_info("Aguardando 2 segundos para verificar status...")
        time.sleep(2)
        
        log_info(f"Verificando status final: {' '.join(status_cmd)}")
        check_result = subprocess.run(status_cmd, capture_output=True, text=True)
        log_info(f"Status final: {check_result.stdout}")
        
        if "ossec-agentd is running" in check_result.stdout:
            log_info("Serviço do OSSEC reiniciado com sucesso.")
            return True
        else:
            log_error(f"Serviço não está em execução após reinício: {check_result.stdout}")
            return False
    except subprocess.CalledProcessError as e:
        log_error(f"Erro ao reiniciar o serviço do OSSEC: {str(e)}")
        log_error(f"Saída do comando: {e.stdout if hasattr(e, 'stdout') else 'N/A'}")
        log_error(f"Erro do comando: {e.stderr if hasattr(e, 'stderr') else 'N/A'}")
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
        
        resultado = subprocess.run(comando, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
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

def baixar_ossec_conf(ossec_manager: str) -> bool:
    """Download OSSEC configuration file from server"""
    try:
        log_info(f"Baixando arquivo de configuração do servidor {ossec_manager}...")
        ossec_conf_path = "/var/ossec/etc/ossec.conf"
        ossec_conf_temp = "/tmp/ossec.conf.downloaded"
        ossec_conf_url = f"http://{ossec_manager}:5002/download/ossec.conf"
        
        # Baixar o arquivo
        response = requests.get(ossec_conf_url, timeout=10)
        if response.status_code != 200:
            log_error(f"Falha ao baixar ossec.conf: {response.status_code}")
            return False
            
        # Salvar o arquivo temporário
        with open(ossec_conf_temp, 'wb') as f:
            f.write(response.content)
        
        # Copiar para o local correto
        usar_sudo = os.geteuid() != 0 and verificar_sudo_disponivel()
        copy_cmd = f"cp {ossec_conf_temp} {ossec_conf_path}"
        if usar_sudo:
            copy_cmd = "sudo " + copy_cmd
        
        subprocess.run(copy_cmd, shell=True, check=True)
        
        # Ajustar permissões
        chmod_cmd = f"chmod 640 {ossec_conf_path}"
        if usar_sudo:
            chmod_cmd = "sudo " + chmod_cmd
        
        subprocess.run(chmod_cmd, shell=True, check=True)
        
        # Ajustar proprietário
        chown_cmd = f"chown root:ossec {ossec_conf_path}"
        if usar_sudo:
            chown_cmd = "sudo " + chown_cmd
        
        subprocess.run(chown_cmd, shell=True, check=True)
        
        log_info("Arquivo ossec.conf baixado e configurado com sucesso.")
        return True
    except requests.RequestException as e:
        log_error(f"Erro de rede ao baixar ossec.conf: {str(e)}")
        return False
    except subprocess.CalledProcessError as e:
        log_error(f"Erro ao configurar ossec.conf: {str(e)}")
        return False
    except Exception as e:
        log_exception(f"Erro inesperado ao baixar ossec.conf: {str(e)}")
        return False

def instalar_ossec(ossec_manager: Optional[str] = None) -> bool:
    """Install OSSEC agent with proper configuration"""
    try:
        # Verificar se o OSSEC já está instalado corretamente
        if verificar_ossec_instalado():
            log_info("OSSEC já está instalado e configurado.")
            return True

        # Detectar a distribuição do sistema
        distro = detect_os_distribution()
        if not distro:
            log_error("Distribuição do sistema não detectada.")
            return False
        
        # Obter o IP do servidor OSSEC
        if not ossec_manager:
            ossec_manager = get_ossec_manager_ip()
            if not ossec_manager:
                log_error("IP do servidor não encontrado. Impossível continuar.")
                return False
        
        # Instalar dependências e o agente OSSEC
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
                log_info(f"Instalando agente OSSEC...")
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
                
                # Baixar o arquivo de configuração do servidor
                if not baixar_ossec_conf(ossec_manager):
                    log_error("Falha ao baixar arquivo de configuração. Instalação incompleta.")
                    return False
                
                # Verificar se a instalação foi bem-sucedida
                if verificar_ossec_instalado():
                    log_info("OSSEC instalado e configurado com sucesso.")
                    
                    # Iniciar o agente OSSEC
                    log_info("Iniciando agente OSSEC...")
                    start_cmd = "/var/ossec/bin/ossec-control start"
                    if os.geteuid() != 0 and verificar_sudo_disponivel():
                        start_cmd = "sudo " + start_cmd
                    
                    subprocess.run(start_cmd, shell=True, check=True)
                    return True
                else:
                    log_error("Falha na instalação do OSSEC.")
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
                
                # Baixar o arquivo de configuração do servidor
                if not baixar_ossec_conf(ossec_manager):
                    log_error("Falha ao baixar arquivo de configuração. Instalação incompleta.")
                    return False
                
                # Verificar se a instalação foi bem-sucedida
                if verificar_ossec_instalado():
                    log_info("OSSEC instalado e configurado com sucesso.")
                    
                    # Iniciar o agente OSSEC
                    log_info("Iniciando agente OSSEC...")
                    start_cmd = "/var/ossec/bin/ossec-control start"
                    if os.geteuid() != 0 and verificar_sudo_disponivel():
                        start_cmd = "sudo " + start_cmd
                    
                    subprocess.run(start_cmd, shell=True, check=True)
                    return True
                else:
                    log_error("Falha na instalação do OSSEC.")
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

def registrar_ossec_no_guardiao(ossec_manager: str) -> bool:
    """Register OSSEC agent with Guardian server"""
    try:
        log_info("Registrando agente OSSEC no servidor Guardião...")
        
        # Carregar ID do agente
        id_agente = carregar_id()
        if not id_agente:
            log_error("ID do agente não encontrado. Impossível registrar OSSEC.")
            return False
        
        # Preparar dados para registro
        from config import nome, chave_ativacao
        
        message_ossec = {
            'name': nome,
            'id': id_agente,
            'chave': chave_ativacao
        }
        
        log_info(f"Enviando solicitação de registro OSSEC: {json.dumps(message_ossec)}")
        
        # Enviar solicitação para o endpoint de registro OSSEC
        resposta = enviar_mensagem(message_ossec, 'registro-ossec')
        
        # Registrar detalhes da resposta
        log_info(f"Resposta do servidor: Status={resposta.status_code}")
        
        # Verificar resposta
        if resposta.status_code == 200:
            dados_resposta = resposta.json()
            log_info(f"Conteúdo da resposta: {json.dumps(dados_resposta)}")
            
            if dados_resposta.get('status') == 'sucesso':
                ossec_server = dados_resposta.get('ossec_server', ossec_manager)
                activation_key = dados_resposta.get('activation_key')
                
                if not activation_key:
                    log_error("Chave de ativação não recebida do servidor.")
                    return False
                
                log_info(f"Registro no OSSEC bem-sucedido! Servidor: {ossec_server}")
                
                # Importar a chave recebida
                log_info("Importando chave OSSEC...")
                if not importar_chave_ossec(activation_key):
                    log_error("Falha ao importar chave OSSEC.")
                    return False
                
                # Reiniciar OSSEC
                log_info("Reiniciando serviço OSSEC...")
                if not reiniciar_ossec():
                    log_error("Falha ao reiniciar OSSEC.")
                    return False
                
                log_info("OSSEC registrado e configurado com sucesso.")
                return True
            else:
                log_error(f"Falha no registro OSSEC: {dados_resposta.get('mensagem', 'Erro desconhecido')}")
                return False
        else:
            log_error(f"Falha na comunicação com o servidor. Status: {resposta.status_code}")
            return False
    except Exception as e:
        log_exception(f"Erro ao registrar agente OSSEC: {str(e)}")
        return False

def registrar_ossec_no_guardiao(ossec_manager: Optional[str] = None, api_token: Optional[str] = None) -> bool:
    """Register OSSEC agent with Guardian server"""
    try:
        log_info("Registrando agente OSSEC no servidor Guardião...")
        
        # Carregar ID do agente
        id_agente = carregar_id()
        if not id_agente:
            log_error("ID do agente não encontrado. Impossível registrar no OSSEC.")
            return False
            
        # Preparar dados para registro
        from config import nome, chave_ativacao
        
        message_ossec = {
            'name': nome,  # Nome do agente (hostname)
            'id': id_agente,  # ID do agente no Guardian
            'chave': chave_ativacao  # Chave de ativação do Guardian
        }
        
        log_debug(f"Enviando solicitação de registro OSSEC: {json.dumps(message_ossec)}")
        
        # Enviar solicitação para o endpoint de registro OSSEC
        from network import enviar_mensagem
        resposta = enviar_mensagem(message_ossec, 'registro-ossec')
        
        # Verificar resposta
        if resposta.status_code == 200:
            dados_resposta = resposta.json()
            log_debug(f"Resposta do registro OSSEC: {json.dumps(dados_resposta)}")
            
            if dados_resposta.get('status') == 'sucesso':
                activation_key = dados_resposta.get('activation_key')
                ossec_hostname = dados_resposta.get('ossec_hostname')
                ossec_server = dados_resposta.get('ossec_server')
                
                log_info(f"Registro no OSSEC bem-sucedido! Servidor: {ossec_server}")
                
                # Importar a chave recebida
                if not importar_chave_ossec(activation_key, ossec_hostname):
                    log_error("Falha ao importar chave OSSEC.")
                    return False
                    
                # Salvar configuração
                config_dir = "/var/guardiao"
                if not os.path.exists(config_dir):
                    os.makedirs(config_dir, exist_ok=True)
                    
                config_file = f"{config_dir}/guard_config.json"
                config_data = {
                    "server_ip": ossec_server,
                    "activation_key": activation_key,
                    "ossec_hostname": ossec_hostname
                }
                
                with open(config_file, 'w') as f:
                    json.dump(config_data, f)
                    
                log_info("Configuração OSSEC salva com sucesso.")
                return True
            else:
                log_error(f"Falha no registro OSSEC: {dados_resposta.get('mensagem', 'Erro desconhecido')}")
                return False
        else:
            log_error(f"Falha na comunicação com o servidor para registro OSSEC. Status: {resposta.status_code}")
            return False
    except Exception as e:
        log_exception(f"Erro ao registrar agente OSSEC: {str(e)}")
        return False

def importar_chave_ossec(activation_key: str, ossec_hostname: str) -> bool:
    """Import OSSEC agent key"""
    try:
        log_info("Importando chave do agente OSSEC...")
        
        if not activation_key or not ossec_hostname:
            log_error("Chave de ativação ou hostname não fornecidos.")
            return False
            
        # Verificar se o arquivo client.keys já existe
        client_keys_path = "/var/ossec/etc/client.keys"
        if os.path.exists(client_keys_path) and verificar_chave_ossec_importada():
            log_info("Chave já importada anteriormente.")
            return True
            
        # Criar diretório temporário para o arquivo de importação
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_file:
            temp_file_path = temp_file.name
            temp_file.write(activation_key)
            
        log_debug(f"Arquivo temporário de chave criado: {temp_file_path}")
        
        # Comando para importar a chave
        import_cmd = ['/var/ossec/bin/manage_agents', '-i', temp_file_path]
        if os.geteuid() != 0 and verificar_sudo_disponivel():
            import_cmd.insert(0, 'sudo')
            
        log_info(f"Executando comando de importação: {' '.join(import_cmd)}")
        import_result = subprocess.run(import_cmd, 
                                      stdout=subprocess.PIPE, 
                                      stderr=subprocess.PIPE, 
                                      text=True, 
                                      input='\n\ny\n')  # Responder 'y' para confirmar
        
        # Remover arquivo temporário
        try:
            os.unlink(temp_file_path)
        except Exception as e:
            log_warning(f"Erro ao remover arquivo temporário: {str(e)}")
        
        if "successfully" in import_result.stdout:
            log_info("Chave importada com sucesso.")
            return True
        else:
            log_error(f"Falha ao importar chave: {import_result.stdout}")
            log_error(f"Erro: {import_result.stderr}")
            return False
            
    except Exception as e:
        log_exception(f"Erro ao importar chave OSSEC: {str(e)}")
        return False

def importar_chave_ossec(agent_key: str) -> bool:
    """Import OSSEC agent key"""
    try:
        log_info("Importando chave do agente...")
        
        if verificar_chave_ossec_importada():
            log_info("Chave já importada.")
            return True
        
        # Verificar se a chave é válida
        if not agent_key or len(agent_key.strip()) < 10:
            log_error(f"Chave de agente inválida ou muito curta: {agent_key}")
            return False
        
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
        
        # Salvar a chave em um arquivo temporário
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            temp_file.write(f"y\n{key_base64}\ny\n")
            temp_file_path = temp_file.name
        
        # Importa a chave usando o arquivo temporário
        import_cmd = f"cat {temp_file_path} | {manage_agents} -i {key_base64}"
        if os.geteuid() != 0 and verificar_sudo_disponivel():
            import_cmd = f"sudo {import_cmd}"
        
        log_info(f"Executando: {import_cmd}")
        result = subprocess.run(import_cmd, shell=True, capture_output=True, text=True)
        
        # Remover o arquivo temporário
        os.unlink(temp_file_path)
        
        # Log completo do resultado para debug
        log_info(f"Saída do comando: {result.stdout}")
        if result.stderr:
            log_warning(f"Erro do comando: {result.stderr}")
        
        # Verificar se a chave foi importada com sucesso
        if "Added successfully" in result.stdout or "successfully added" in result.stdout.lower():
            log_info("Chave importada com sucesso.")
            
            # Verificar se o arquivo client.keys foi criado
            if os.path.exists("/var/ossec/etc/client.keys"):
                log_info("Arquivo client.keys criado com sucesso.")
                
                # Ajustar permissões do arquivo client.keys
                chmod_cmd = "chmod 640 /var/ossec/etc/client.keys"
                if os.geteuid() != 0 and verificar_sudo_disponivel():
                    chmod_cmd = f"sudo {chmod_cmd}"
                
                subprocess.run(chmod_cmd, shell=True, check=True)
                
                # Ajustar proprietário do arquivo client.keys
                chown_cmd = "chown root:ossec /var/ossec/etc/client.keys"
                if os.geteuid() != 0 and verificar_sudo_disponivel():
                    chown_cmd = f"sudo {chown_cmd}"
                
                subprocess.run(chown_cmd, shell=True, check=True)
                
                return True
            else:
                log_error("Chave importada, mas arquivo client.keys não foi criado.")
                return False
        else:
            log_error("Falha ao importar a chave.")
            return False
    except Exception as e:
        log_exception(f"Erro ao importar chave do OSSEC: {str(e)}")
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
        
        # Verificar se já temos a chave importada
        if verificar_chave_ossec_importada():
            log_info("Agente já registrado com chave.")
            
            if not verificar_ossec_running():
                log_warning("Agente não está em execução. Tentando reiniciar...")
                reiniciar_ossec()
            
            return True
        
        # Se não temos chave, registrar o agente
        log_info("Chave não encontrada. Iniciando registro do agente...")
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