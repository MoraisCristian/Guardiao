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
import time
from typing import Optional, Dict, Any, List, Tuple
from network import carregar_id, enviar_mensagem
from system_utils import os_update, os_install, detect_os_distribution, verificar_sudo_disponivel
from config import SERVER_URL
from logger import log_info, log_warning, log_error, log_debug, log_critical, log_exception

# Constantes
OSSEC_BIN_PATH = '/var/ossec/bin'
OSSEC_ETC_PATH = '/var/ossec/etc'
OSSEC_CONTROL = f'{OSSEC_BIN_PATH}/ossec-control'
OSSEC_CONF = f'{OSSEC_ETC_PATH}/ossec.conf'
CLIENT_KEYS = f'{OSSEC_ETC_PATH}/client.keys'
GUARDIAO_CONFIG = '/var/guardiao/guard_config.json'

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
    """Verifica se o OSSEC está instalado e configurado"""
    try:
        # Verificar tanto o binário quanto o arquivo de configuração
        binario_existe = os.path.exists(OSSEC_CONTROL)
        config_existe = os.path.exists(OSSEC_CONF)
        
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
        log_exception(f'Erro ao verificar instalação do OSSEC: {str(e)}')
        return False

def verificar_chave_ossec_importada() -> bool:
    """Verifica se a chave do OSSEC está importada corretamente"""
    try:
        if not os.path.exists(CLIENT_KEYS):
            log_warning("Arquivo client.keys não encontrado.")
            return False
            
        with open(CLIENT_KEYS, 'r') as f:
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

def verificar_ossec_running() -> bool:
    """Verifica se o agente OSSEC está em execução"""
    try:
        usar_sudo = os.geteuid() != 0 and verificar_sudo_disponivel()
        
        comando = [OSSEC_CONTROL, 'status']
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

def reiniciar_ossec() -> bool:
    """Reinicia o serviço OSSEC com tratamento adequado de erros"""
    try:
        # Verificar se o arquivo client.keys existe
        if not os.path.exists(CLIENT_KEYS):
            log_error("Arquivo client.keys não encontrado. Impossível reiniciar o OSSEC.")
            return False
            
        usar_sudo = os.geteuid() != 0 and verificar_sudo_disponivel()
            
        # Verificar status atual
        status_cmd = [OSSEC_CONTROL, 'status']
        if usar_sudo:
            status_cmd.insert(0, 'sudo')
            
        log_info(f"Verificando status atual: {' '.join(status_cmd)}")
        status_result = subprocess.run(status_cmd, capture_output=True, text=True)
        log_info(f"Status atual do OSSEC: {status_result.stdout}")
        
        # Parar o serviço primeiro
        stop_cmd = [OSSEC_CONTROL, 'stop']
        if usar_sudo:
            stop_cmd.insert(0, 'sudo')
            
        log_info(f"Parando serviço do OSSEC: {' '.join(stop_cmd)}")
        stop_result = subprocess.run(stop_cmd, capture_output=True, text=True)
        log_info(f"Resultado da parada: {stop_result.stdout}")
        if stop_result.stderr:
            log_warning(f"Erro ao parar: {stop_result.stderr}")
        
        # Aguardar um momento
        log_info("Aguardando 2 segundos...")
        time.sleep(2)
        
        # Iniciar o serviço
        start_cmd = [OSSEC_CONTROL, 'start']
        if usar_sudo:
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

def get_ossec_manager_ip() -> Optional[str]:
    """Obtém o IP do servidor OSSEC do arquivo de configuração"""
    try:
        if os.path.exists(GUARDIAO_CONFIG):
            with open(GUARDIAO_CONFIG, 'r') as f:
                config = json.load(f)
                if "server_ip" in config:
                    log_info(f"Usando IP do servidor: {config['server_ip']}")
                    return config['server_ip']
        
        log_warning("IP do servidor não encontrado no arquivo de configuração")
        return None
    except Exception as e:
        log_exception(f"Erro ao obter IP do servidor: {str(e)}")
        return None

def get_system_info() -> Tuple[str, str, str, str, str]:
    """Coleta informações do sistema para registro do agente"""
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
    """Obtém a chave de ativação do arquivo de configuração"""
    try:
        if os.path.exists(GUARDIAO_CONFIG):
            with open(GUARDIAO_CONFIG, 'r') as f:
                config = json.load(f)
                return config.get('activation_key')
    except Exception as e:
        log_warning(f"Erro ao ler chave de ativação: {str(e)}")
    return None

def baixar_ossec_conf(ossec_manager: str) -> bool:
    """Baixa o arquivo de configuração do OSSEC do servidor"""
    try:
        log_info(f"Baixando arquivo de configuração do servidor {ossec_manager}...")
        ossec_conf_temp = "/tmp/ossec.conf.downloaded"
        
        # Obter a chave de ativação do arquivo de configuração
        chave_ativacao = get_activation_key()
        if not chave_ativacao:
            log_error("Chave de ativação não encontrada. Impossível baixar ossec.conf")
            return False
            
        # Construir URL com a chave de ativação
        ossec_conf_url = f"{SERVER_URL}/download/ossec.conf/{chave_ativacao}"
        
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
        copy_cmd = f"cp {ossec_conf_temp} {OSSEC_CONF}"
        if usar_sudo:
            copy_cmd = "sudo " + copy_cmd
        
        subprocess.run(copy_cmd, shell=True, check=True)
        
        # Ajustar permissões
        chmod_cmd = f"chmod 640 {OSSEC_CONF}"
        if usar_sudo:
            chmod_cmd = "sudo " + chmod_cmd
        
        subprocess.run(chmod_cmd, shell=True, check=True)
        
        # Ajustar proprietário
        chown_cmd = f"chown root:ossec {OSSEC_CONF}"
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

def importar_chave_ossec(activation_key: str) -> bool:
    """Importa a chave do agente OSSEC"""
    try:
        log_info("Importando chave do agente OSSEC...")
        
        if not activation_key:
            log_error("Chave de ativação não fornecida.")
            return False
            
        # Verificar se o arquivo client.keys já existe
        if os.path.exists(CLIENT_KEYS) and verificar_chave_ossec_importada():
            log_info("Chave já importada anteriormente.")
            return True
        
        # Verificar se o diretório pai existe
        client_keys_dir = os.path.dirname(CLIENT_KEYS)
        if not os.path.exists(client_keys_dir):
            log_warning(f"Diretório {client_keys_dir} não existe. Tentando criar...")
            try:
                usar_sudo = os.geteuid() != 0 and verificar_sudo_disponivel()
                if usar_sudo:
                    os.system(f"sudo mkdir -p {client_keys_dir}")
                else:
                    os.makedirs(client_keys_dir, exist_ok=True)
                log_info(f"Diretório {client_keys_dir} criado com sucesso.")
            except Exception as e:
                log_error(f"Falha ao criar diretório {client_keys_dir}: {str(e)}")
                return False
        
        # Extrair apenas a chave da resposta do servidor
        # A chave geralmente vem no formato "Agent key information for 'XXX' is: \nCHAVE_REAL"
        if "Agent key information for" in activation_key:
            # Extrair apenas a parte da chave após a quebra de linha
            parts = activation_key.split('\n')
            if len(parts) > 1:
                activation_key = parts[1].strip()
                log_info(f"Chave extraída: {activation_key[:10]}...")
        
        # Verificar se a chave está vazia após extração
        if not activation_key or activation_key.strip() == '':
            log_error("Chave extraída está vazia. Impossível importar.")
            return False
        
        # Comando para importar a chave diretamente como string
        usar_sudo = os.geteuid() != 0 and verificar_sudo_disponivel()
        
        # Usar shell=True para permitir o pipe
        cmd_str = f"echo 'y' | {OSSEC_BIN_PATH}/manage_agents -i {activation_key}"
        if usar_sudo:
            cmd_str = f"sudo {cmd_str}"
            
        log_info(f"Executando comando de importação: {cmd_str}")
        
        # Executar o comando com shell=True para permitir o pipe
        import_result = subprocess.run(cmd_str, 
                                      shell=True,
                                      stdout=subprocess.PIPE, 
                                      stderr=subprocess.PIPE, 
                                      text=True)
        
        # Verificar resultado
        log_info(f"Saída do comando: {import_result.stdout}")
        if import_result.stderr:
            log_warning(f"Erro do comando: {import_result.stderr}")
        
        if "Added" in import_result.stdout or "successfully" in import_result.stdout:
            log_info("Chave importada com sucesso.")
            # Verificar se o arquivo client.keys foi criado
            if os.path.exists(CLIENT_KEYS):
                log_info(f"Arquivo {CLIENT_KEYS} criado com sucesso.")
                return True
            else:
                log_error(f"Arquivo {CLIENT_KEYS} não foi criado após importação.")
                return False
        else:
            log_error(f"Falha ao importar chave: {import_result.stdout}")
            return False
            
    except Exception as e:
        log_exception(f"Erro ao importar chave OSSEC: {str(e)}")
        return False

def salvar_configuracao_ossec(ossec_server: str, activation_key: str, ossec_hostname: str) -> bool:
    """Salva a configuração do OSSEC no arquivo de configuração"""
    try:
        # Criar diretório de configuração se não existir
        config_dir = "/var/guardiao"
        if not os.path.exists(config_dir):
            os.makedirs(config_dir, exist_ok=True)
            
        # Salvar configuração
        config_data = {
            "server_ip": ossec_server,
            "activation_key": activation_key,
            "ossec_hostname": ossec_hostname
        }
        
        with open(GUARDIAO_CONFIG, 'w') as f:
            json.dump(config_data, f)
            
        log_info("Configuração OSSEC salva com sucesso.")
        return True
    except Exception as e:
        log_exception(f"Erro ao salvar configuração OSSEC: {str(e)}")
        return False

def registrar_ossec_no_guardiao():
    """Registra o agente OSSEC no servidor Guardian"""

    try:
        # Obter informações do sistema usando a função existente
        hostname, ip, sistema, versao, mac = get_system_info()

        # Obter a chave de ativação do arquivo de configuração
        chave_ativacao = get_activation_key()

        # Obter ID do agente    
        id_agente = carregar_id()
        
        if not id_agente:
            log_error("ID do agente não encontrado. Impossível registrar OSSEC.")
            return None
            
        # Garantir que o hostname não seja nulo
        if not hostname or hostname.strip() == '':
            # Fallback para o hostname do sistema se o valor estiver vazio
            hostname = socket.gethostname()
            log_warning(f"Hostname vazio, usando hostname do sistema: {hostname}")
        
        # Verificar se o hostname foi obtido corretamente
        if not hostname or hostname.strip() == '':
            log_error("Não foi possível obter o hostname do sistema.")
            # Último recurso: usar um nome fixo
            hostname = "agent_" + str(id_agente)
            log_warning(f"Usando hostname fixo: {hostname}")
        
        # Ajustar os dados para corresponder ao que a rota /registro-ossec espera
        data = {
            "chave": chave_ativacao,  # A chave de ativação
            "host": hostname,         # O hostname formatado
            "name": hostname,         # O nome do host
            "id": id_agente           # O ID do agente
        }
        
        # Verificar se algum campo está vazio ou None
        for key, value in data.items():
            if value is None or (isinstance(value, str) and value.strip() == ''):
                log_error(f"Campo '{key}' está vazio ou nulo. Valor: {value}")
                if key == 'name' or key == 'host':
                    # Forçar o uso do hostname do sistema ou um valor fixo
                    system_hostname = socket.gethostname()
                    if system_hostname and system_hostname.strip() != '':
                        data[key] = system_hostname
                        log_info(f"Forçando uso do hostname do sistema para '{key}': {system_hostname}")
                    else:
                        data[key] = "agent_" + str(id_agente)
                        log_info(f"Forçando uso de nome fixo para '{key}': {data[key]}")
        
        # Gerar comando curl para troubleshooting
        endpoint = 'registro-ossec'
        endpoint_url = f"{SERVER_URL}/{endpoint}"
        curl_cmd = f"curl -X POST -H 'Content-Type: application/json' -d '{json.dumps(data)}' {endpoint_url}"
        
        log_info(f"Registrando OSSEC no Guardian. Endpoint: {endpoint_url}")
        log_info(f"Payload: {json.dumps(data)}")
        log_info(f"Comando curl para troubleshooting: {curl_cmd}")
        
        # Usar o endpoint com prefixo /api/ já configurado na função enviar_mensagem
        response = enviar_mensagem(data, endpoint)
        
        # Log detalhado da resposta para diagnóstico
        if response:
            log_info(f"Resposta recebida. Status: {response.status_code}")
            log_info(f"Headers: {dict(response.headers)}")
            
            try:
                response_data = response.json()
                log_info(f"Corpo da resposta: {json.dumps(response_data)}")
                
                if response.status_code == 200:
                    # Verificar se a resposta contém os campos esperados
                    if 'id_agente' in response_data:
                        log_info(f"Registro OSSEC bem-sucedido. ID do agente: {response_data.get('id_agente')}")
                        
                        # Verificar se há uma chave de ativação na resposta
                        if 'chave_ossec' in response_data:
                            log_info(f"Chave OSSEC recebida: {response_data.get('chave_ossec')[:10]}...")
                        else:
                            log_warning("Resposta não contém chave OSSEC")
                            
                        return response_data
                    else:
                        log_error("Resposta não contém ID do agente")
                        log_error(f"Resposta completa: {json.dumps(response_data)}")
                        return None
                else:
                    log_error(f"Falha no registro OSSEC. Status: {response.status_code}")
                    log_error(f"Resposta: {json.dumps(response_data)}")
                    return None
            except ValueError as e:
                # A resposta não é um JSON válido
                log_error(f"Erro ao processar resposta JSON: {str(e)}")
                log_error(f"Corpo da resposta (texto): {response.text[:500]}")
                return None
        else:
            log_error("Nenhuma resposta recebida do servidor")
            log_error(f"Comando para troubleshooting: {curl_cmd}")
            return None
            
    except requests.exceptions.RequestException as e:
        log_error(f"Erro de rede ao registrar OSSEC: {str(e)}")
        return None
    except Exception as e:
        log_exception(f"Erro ao registrar OSSEC no Guardian: {str(e)}")
        log_error(f"Tipo de exceção: {type(e).__name__}")
        import traceback
        log_error(f"Traceback: {traceback.format_exc()}")
        return None

def instalar_ossec(ossec_manager: Optional[str] = None) -> bool:
    """Instala o agente OSSEC com a configuração adequada"""
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
        
        # Determinar comandos com base na distribuição
        if distro in ["debian", "ubuntu"]:
            # Instalar dependências
            deps_cmd = "apt-get update && apt-get install -y wget apt-transport-https gnupg"
            repo_install_cmd = "echo -e 'yes\nyes\n' | bash /tmp/atomic_installer.sh"
            update_cmd = "apt-get update"
            install_cmd = "apt-get install -y ossec-hids-agent"
            reinstall_cmd = "apt-get install --reinstall ossec-hids-agent"
            repair_cmd = "dpkg --configure -a"
        elif distro in ["centos", "rhel", "fedora", "almalinux", "rocky"]:
            # Instalar dependências
            deps_cmd = "yum install -y wget"
            repo_install_cmd = "echo -e 'yes\nyes\n' | bash /tmp/atomic_installer.sh"
            update_cmd = "yum clean all && yum makecache"
            install_cmd = "yum install -y ossec-hids-agent"
            reinstall_cmd = "yum reinstall -y ossec-hids-agent"
            repair_cmd = "yum check"
        else:
            log_error(f"Distribuição não suportada: {distro}")
            return False
            
        # Usar sudo se necessário
        usar_sudo = os.geteuid() != 0 and verificar_sudo_disponivel()
        if usar_sudo:
            deps_cmd = "sudo " + deps_cmd
            repo_install_cmd = "sudo " + repo_install_cmd
            update_cmd = "sudo " + update_cmd
            install_cmd = "sudo " + install_cmd
            reinstall_cmd = "sudo " + reinstall_cmd
            repair_cmd = "sudo " + repair_cmd
            
        try:
            # Instalar dependências
            log_info("Instalando dependências...")
            subprocess.run(deps_cmd, shell=True, check=True)
            
            # Baixar e instalar repositório Atomic
            log_info("Baixando script do instalador Atomic...")
            download_cmd = "wget -q -O /tmp/atomic_installer.sh https://updates.atomicorp.com/installers/atomic"
            if usar_sudo:
                download_cmd = "sudo " + download_cmd
                
            subprocess.run(download_cmd, shell=True, check=True)
            
            # Dar permissão de execução
            chmod_cmd = "chmod +x /tmp/atomic_installer.sh"
            if usar_sudo:
                chmod_cmd = "sudo " + chmod_cmd
                
            subprocess.run(chmod_cmd, shell=True, check=True)
            
            # Instalar repositório
            log_info("Instalando repositório Atomicorp...")
            subprocess.run(repo_install_cmd, shell=True, check=True)
            
            # Atualizar repositórios
            log_info("Atualizando repositórios...")
            subprocess.run(update_cmd, shell=True, check=True)
            
            # Instalar OSSEC
            log_info("Instalando agente OSSEC...")
            subprocess.run(install_cmd, shell=True, check=True)
            
            # Verificar instalação
            if not os.path.exists('/var/ossec'):
                log_warning("Diretório /var/ossec não encontrado. Tentando reinstalar...")
                subprocess.run(reinstall_cmd, shell=True, check=True)
                subprocess.run(repair_cmd, shell=True, check=True)
                
            # Baixar configuração
            if not baixar_ossec_conf(ossec_manager):
                log_error("Falha ao baixar configuração OSSEC.")
                return False
                
            # Verificar instalação final
            if verificar_ossec_instalado():
                log_info("OSSEC instalado e configurado com sucesso.")
                return True
            else:
                log_error("Falha na instalação do OSSEC.")
                return False
                
        except subprocess.CalledProcessError as e:
            log_error(f"Erro na instalação: {str(e)}")
            return False
        except Exception as e:
            log_exception(f"Erro inesperado na instalação: {str(e)}")
            return False
            
    except Exception as e:
        log_exception(f"Erro geral na instalação do OSSEC: {str(e)}")
        return False

def configurar_ossec(ossec_manager: Optional[str] = None) -> bool:
    """Configura o agente OSSEC com a conexão do servidor"""
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
        response_data = registrar_ossec_no_guardiao()
        
        # Verificar se obtivemos uma resposta válida
        if (response_data) and 'chave_ossec' in response_data:
            # Extrair a chave OSSEC da resposta
            ossec_key = response_data.get('chave_ossec')
            log_info(f"Chave OSSEC recebida do servidor. Importando...")
            
            # Importar a chave OSSEC
            if importar_chave_ossec(ossec_key):
                log_info("Chave OSSEC importada com sucesso.")
                return True
            else:
                log_error("Falha ao importar chave OSSEC.")
                return False
        else:
            log_error("Não foi possível obter a chave OSSEC do servidor.")
            return False
        
    except Exception as e:
        log_exception(f"Erro na configuração: {str(e)}")
        return False

def initialize_ossec() -> bool:
    """Inicializa o OSSEC completamente"""
    try:
        log_info("Inicializando OSSEC...")
        
        # Verificar se o OSSEC está instalado
        if not verificar_ossec_instalado():
            log_info("OSSEC não instalado. Iniciando instalação...")
            if not instalar_ossec():
                log_error("Falha na instalação do OSSEC.")
                return False
                
        # Configurar OSSEC
        log_info("Configurando OSSEC...")
        if not configurar_ossec():
            log_error("Falha na configuração do OSSEC.")
            return False
            
        # Verificar se o OSSEC está em execução
        if not verificar_ossec_running():
            log_info("OSSEC não está em execução. Reiniciando...")
            if not reiniciar_ossec():
                log_error("Falha ao reiniciar OSSEC.")
                return False
                
        log_info("OSSEC inicializado com sucesso.")
        return True
    except Exception as e:
        log_exception(f"Erro ao inicializar OSSEC: {str(e)}")
        return False