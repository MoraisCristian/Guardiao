import os
import subprocess
import requests
import re
import sys
from system_utils import os_update, os_install, detect_os_distribution, verificar_sudo_disponivel
from config import SERVER_URL
from logger import log_info, log_warning, log_error, log_info, log_critical, log_exception

def baixar_ossec_conf():
    """Download OSSEC configuration file"""
    try:
        url = f'{SERVER_URL}/download/ossec.conf'
        resposta = requests.get(url)
        if resposta.status_code == 200:
            with open('ossec.conf', 'wb') as file:
                file.write(resposta.content)
            log_info('Arquivo de configuração do OSSEC baixado com sucesso.')
            return True
        else:
            log_error(f'Falha ao baixar o arquivo de configuração do OSSEC. Status: {resposta.status_code}')
            return False
    except Exception as e:
        log_exception('Erro ao baixar configuração do OSSEC')
        return False

def configurar_ossec():
    """Configure OSSEC"""
    try:
        # Baixa o arquivo de configuração
        if not baixar_ossec_conf():
            log_error("Falha ao baixar arquivo de configuração do OSSEC")
            return False
            
        # Move o arquivo de configuração para o diretório correto
        usar_sudo = os.geteuid() != 0 and verificar_sudo_disponivel()
        
        # Primeiro, verifica se o diretório existe
        if not os.path.exists('/var/ossec/etc'):
            log_warning("Diretório /var/ossec/etc não encontrado")
            return False
        
        # Copia o arquivo para o local correto
        comando = ['cp', 'ossec.conf', '/var/ossec/etc/ossec.conf']
        
        # Verifica se precisa usar sudo
        if usar_sudo:
            comando.insert(0, 'sudo')
            
        log_info(f"Executando comando: {' '.join(comando)}")
        resultado = subprocess.run(comando, capture_output=True, text=True)
        
        if resultado.returncode != 0:
            log_error(f"Erro ao copiar arquivo de configuração: {resultado.stderr}")
            return False
            
        # Verifica se o arquivo foi copiado corretamente
        if not os.path.exists('/var/ossec/etc/ossec.conf'):
            log_error("Arquivo ossec.conf não foi copiado corretamente")
            return False
            
        # Ajusta as permissões do arquivo
        chmod_cmd = ['chmod', '640', '/var/ossec/etc/ossec.conf']
        chown_cmd = ['chown', 'root:ossec', '/var/ossec/etc/ossec.conf']
        
        if usar_sudo:
            chmod_cmd.insert(0, 'sudo')
            chown_cmd.insert(0, 'sudo')
            
        subprocess.run(chmod_cmd, check=False)
        subprocess.run(chown_cmd, check=False)
        
        log_info("Configuração do OSSEC concluída com sucesso.")
        return True
        
    except Exception as e:
        log_exception("Erro durante a configuração do OSSEC")
        return False

def verificar_ossec_instalado():
    """Check if OSSEC is already installed"""
    try:
        installed = os.path.exists('/var/ossec/bin/ossec-control')
        log_info(f'Verificação de instalação do OSSEC: {installed}')
        return installed
    except Exception as e:
        log_exception('Erro ao verificar instalação do OSSEC')
        return False

def verificar_chave_ossec_importada():
    """Check if OSSEC key is imported"""
    try:
        client_keys_path = "/var/ossec/etc/client.keys"
        if not os.path.exists(client_keys_path):
            log_warning("Arquivo client.keys não encontrado.")
            return False
            
        with open(client_keys_path, 'r') as f:
            content = f.read().strip()
            if not content:
                log_warning("Arquivo client.keys está vazio.")
                return False
                
            # Verify if the file contains a valid key entry
            if not re.search(r'^\d+\s+\S+\s+\S+\s+\S+$', content, re.MULTILINE):
                log_warning("Arquivo client.keys não contém uma chave válida.")
                return False
                
        log_info("Chave do OSSEC já importada e válida.")
        return True
    except Exception as e:
        log_exception("Erro ao verificar chave do OSSEC")
        return False

def reiniciar_ossec():
    """Restart OSSEC service"""
    comando_base = ['/var/ossec/bin/ossec-control', 'restart']
    
    if os.geteuid() != 0 and verificar_sudo_disponivel():
        comando_base.insert(0, 'sudo')
    
    try:
        log_info("Reiniciando serviço do OSSEC...")
        subprocess.run(comando_base, check=True)
        log_info("Serviço do OSSEC reiniciado com sucesso.")
        return True
    except subprocess.CalledProcessError as e:
        log_error(f"Erro ao reiniciar o serviço do OSSEC: {str(e)}")
        return False
    except Exception as e:
        log_exception("Erro inesperado ao reiniciar OSSEC")
        return False

def importar_chave_ossec(activation_key):
    """Import OSSEC key"""
    try:
        # Extract the actual key from the response
        key_match = re.search(r"Agent key information for '(\d+)':\s+(\S+)", activation_key)
        if key_match:
            agent_id = key_match.group(1).strip()
            actual_key = key_match.group(2).strip()
        else:
            lines = activation_key.split('\n')
            actual_key = lines[-1].strip() if lines else ''
        
        if not actual_key:
            log_error("Chave de ativação do OSSEC está vazia. Não é possível importar.")
            return False
        
        log_info(f"Chave a ser importada: {actual_key}")
        
        # Execute the import command
        try:
            
            command = "echo 'y' | /var/ossec/bin/manage_agents -i {key}".format(key=actual_key)
            log_info(f"Comando a ser executado: {command}")
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            output, error = process.communicate()
            
            # Set proper permissions
            subprocess.run("sudo chmod 640 /var/ossec/etc/client.keys", shell=True)
            subprocess.run("sudo chown root:ossec /var/ossec/etc/client.keys", shell=True)
            
            log_info("=== Import Command Output ===")
            log_info(f"Command executed: {command}")
            log_info(f"STDOUT:\n{output}")
            log_info(f"STDERR:\n{error}")
            log_info("=========================")
            
            if process.returncode != 0:
                log_error(f"Erro ao importar a chave. Retorno: {process.returncode}")
                log_error(f"Erro detalhado: {error}")
                return False
            
            if not verificar_chave_ossec_importada():
                log_error("A chave não foi escrita corretamente no arquivo client.keys")
                return False
            
            log_info("Chave do OSSEC importada com sucesso.")
            return True
            
        except Exception as e:
            log_exception(f"Erro ao importar a chave do OSSEC: {str(e)}")
            return False
            
    except Exception as e:
        log_exception("Erro geral ao processar chave do OSSEC")
        return False

def verificar_chave_ossec_importada():
    """Check if OSSEC key is imported"""
    try:
        client_keys_path = "/var/ossec/etc/client.keys"
        if not os.path.exists(client_keys_path):
            log_warning("Arquivo client.keys não encontrado.")
            return False
            
        with open(client_keys_path, 'r') as f:
            content = f.read().strip()
            if not content:
                log_warning("Arquivo client.keys está vazio.")
                return False
                
            # Verify if the file contains a valid key entry
            if not re.search(r'^\d+\s+\S+\s+\S+\s+\S+$', content, re.MULTILINE):
                log_warning("Arquivo client.keys não contém uma chave válida.")
                return False
                
        log_info("Chave do OSSEC já importada e válida.")
        return True
    except Exception as e:
        log_exception("Erro ao verificar chave do OSSEC")
        return False

def verificar_ossec_running():
    """Check if OSSEC is running"""
    try:
        # Verifica se precisa usar sudo
        usar_sudo = os.geteuid() != 0 and verificar_sudo_disponivel()
        
        # Comando para verificar o status do OSSEC
        comando = ['/var/ossec/bin/ossec-control', 'status']
        if usar_sudo:
            comando.insert(0, 'sudo')
        
        resultado = subprocess.run(comando, capture_output=True, text=True)
        
        # Verifica se o OSSEC está em execução
        if "ossec-agentd is running" in resultado.stdout:
            print("OSSEC está em execução.")
            return True
        else:
            print("OSSEC não está em execução. Tentando reiniciar...")
            return False
    except Exception as e:
        print(f"Erro ao verificar status do OSSEC: {str(e)}")
        return False

def instalar_ossec():
    """Install OSSEC"""
    try:
        # Verifica se o OSSEC já está instalado
        if verificar_ossec_instalado():
            log_info("OSSEC já está instalado. Pulando a instalação.")
            return True

        # Download agent configuration first
        log_info("Baixando configuração do agente OSSEC...")
        if not baixar_ossec_conf():
            log_error("Falha ao baixar configuração do agente OSSEC")
            return False

        # First, clean any existing OSSEC installation
        if os.path.exists('/var/ossec'):
            log_info("Removendo instalação anterior do OSSEC...")
            cleanup_cmd = "sudo rm -rf /var/ossec"
            subprocess.run(cleanup_cmd, shell=True, check=True)

        # Detecta a distribuição do sistema
        distro = detect_os_distribution()
        if not distro:
            log_error("Não foi possível detectar a distribuição do sistema.")
            return False
    
        # Instala dependências necessárias
        if distro == "debian":
            dependencies = ["build-essential",  # includes make, gcc, and other build tools
                          "libevent-dev", 
                          "libpcre2-dev", 
                          "libssl-dev",
                          "zlib1g-dev",
                          "wget"]
            
            # Update package list
            if not os_update():
                log_error("Falha ao atualizar lista de pacotes.")
                return False
    
            # Install dependencies one by one
            for package in dependencies:
                if not os_install(package):
                    log_error(f"Falha ao instalar dependência: {package}")
                    return False
                log_info(f"Pacote {package} instalado com sucesso.")

        # Download OSSEC source
        log_info("Baixando OSSEC...")
        ossec_url = 'https://github.com/ossec/ossec-hids/archive/refs/tags/3.7.0.tar.gz'
        try:
            response = requests.get(ossec_url, stream=True)
            if response.status_code == 200:
                with open('/tmp/ossec.tar.gz', 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
            else:
                log_error(f"Falha ao baixar OSSEC. Status code: {response.status_code}")
                return False
        except Exception as e:
            log_exception("Erro ao baixar OSSEC")
            return False
    
        # Extract and install OSSEC
        try:
            log_info("Extraindo e instalando OSSEC...")
            
            # Extract
            subprocess.run(['tar', 'xzf', '/tmp/ossec.tar.gz', '-C', '/tmp'], check=True)
            
            # Get current directory to return later
            current_dir = os.getcwd()
            
            # Prepare agent installation configuration
            os.chdir('/tmp/ossec-hids-3.7.0')
            
            # Ensure the downloaded config is properly copied to the installation directory
            log_info("Copiando configuração do agente para o diretório de instalação...")
            try:
                # Copy the downloaded config file to the preloaded-vars.conf location
                subprocess.run(['cp', f'{current_dir}/ossec.conf', 'etc/preloaded-vars.conf'], check=True)
                log_info("Arquivo de configuração copiado com sucesso.")
            except Exception as e:
                log_error(f"Erro ao copiar arquivo de configuração: {str(e)}")
                return False
            
            # Create a proper preloaded-vars.conf if it doesn't exist or is empty
            if not os.path.exists('etc/preloaded-vars.conf') or os.path.getsize('etc/preloaded-vars.conf') == 0:
                log_info("Criando arquivo preloaded-vars.conf padrão...")
                preloaded_vars = """
USER_LANGUAGE="pt"
USER_NO_STOP="s"
USER_INSTALL_TYPE="agent"
USER_DIR="/var/ossec"
USER_ENABLE_ACTIVE_RESPONSE="y"
USER_ENABLE_SYSCHECK="y"
USER_ENABLE_ROOTCHECK="y"
USER_UPDATE="n"
"""
                with open('etc/preloaded-vars.conf', 'w') as f:
                    f.write(preloaded_vars)
            
            # Run install script with automated responses
            log_info("Iniciando instalação do agente OSSEC...")
            install_cmd = "sudo ./install.sh"
            if os.geteuid() == 0:  # If already root
                install_cmd = "./install.sh"
            
            process = subprocess.Popen(
                install_cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            output, error = process.communicate()
            
            log_info("=== Installation Output ===")
            log_info(f"STDOUT:\n{output}")
            log_info(f"STDERR:\n{error}")
            log_info("=========================")
            
            if process.returncode != 0:
                log_error(f"Erro durante a instalação do OSSEC: {error}")
                return False
            
            # Return to original directory
            os.chdir(current_dir)
                
            log_info("OSSEC instalado com sucesso como agente.")
            return True
            
        except subprocess.CalledProcessError as e:
            log_error(f"Erro durante a instalação do OSSEC: {str(e)}")
            return False
        except Exception as e:
            log_exception("Erro inesperado durante a instalação do OSSEC")
            return False
        finally:
            # Cleanup
            try:
                os.remove('/tmp/ossec.tar.gz')
                subprocess.run(['rm', '-rf', '/tmp/ossec-hids-3.7.0'])
            except:
                pass
    except Exception as e:
        log_exception("Erro durante a instalação do OSSEC")
        return False

def configurar_ossec():
    """Configure OSSEC"""
    try:
        # Verifica se o OSSEC está instalado
        if not verificar_ossec_instalado():
            log_error("OSSEC não está instalado. Não é possível configurar.")
            return False
            
        # Baixa o arquivo de configuração
        if not baixar_ossec_conf():
            log_error("Falha ao baixar arquivo de configuração do OSSEC")
            return False
            
        # Move o arquivo de configuração para o diretório correto
        usar_sudo = os.geteuid() != 0 and verificar_sudo_disponivel()
        
        # Primeiro, verifica se o diretório existe
        if not os.path.exists('/var/ossec/etc'):
            log_warning("Diretório /var/ossec/etc não encontrado")
            return False
        
        # Copia o arquivo para o local correto
        comando = ['cp', 'ossec.conf', '/var/ossec/etc/ossec.conf']
        
        # Verifica se precisa usar sudo
        if usar_sudo:
            comando.insert(0, 'sudo')
            
        log_info(f"Executando comando: {' '.join(comando)}")
        resultado = subprocess.run(comando, capture_output=True, text=True)
        
        if resultado.returncode != 0:
            log_error(f"Erro ao copiar arquivo de configuração: {resultado.stderr}")
            return False
            
        # Verifica se o arquivo foi copiado corretamente
        if not os.path.exists('/var/ossec/etc/ossec.conf'):
            log_error("Arquivo ossec.conf não foi copiado corretamente")
            return False
            
        # Ajusta as permissões do arquivo
        chmod_cmd = ['chmod', '640', '/var/ossec/etc/ossec.conf']
        chown_cmd = ['chown', 'root:ossec', '/var/ossec/etc/ossec.conf']
        
        if usar_sudo:
            chmod_cmd.insert(0, 'sudo')
            chown_cmd.insert(0, 'sudo')
            
        subprocess.run(chmod_cmd, check=False)
        subprocess.run(chown_cmd, check=False)
        
        log_info("Configuração do OSSEC concluída com sucesso.")
        return True
        
    except Exception as e:
        log_exception("Erro durante a configuração do OSSEC")
        return False

def setup_ossec(activation_key=None):
    """Complete OSSEC setup"""
    try:
        log_info("Iniciando configuração do OSSEC...")
        
        # Instala o OSSEC se não estiver instalado
        if not verificar_ossec_instalado():
            log_info("OSSEC não está instalado. Iniciando instalação...")
            if not instalar_ossec():
                log_error("Falha na instalação do OSSEC.")
                return False
        else:
            log_info("OSSEC já está instalado.")
            
        # Configura o OSSEC
        log_info("Configurando OSSEC...")
        if not configurar_ossec():
            log_error("Falha na configuração do OSSEC.")
            return False
            
        # Importa a chave de ativação, se fornecida
        if activation_key:
            log_info("Importando chave de ativação...")
            if not importar_chave_ossec(activation_key):
                log_error("Falha ao importar chave de ativação.")
                return False
            
        # Reinicia o serviço
        log_info("Reiniciando serviço OSSEC...")
        if not reiniciar_ossec():
            log_error("Falha ao reiniciar o serviço OSSEC.")
            return False
            
        log_info("Configuração completa do OSSEC concluída com sucesso.")
        return True
        
    except Exception as e:
        log_exception("Erro durante a configuração completa do OSSEC")
        return False