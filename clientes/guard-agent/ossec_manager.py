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
        log_info(f"Baixando configuração do OSSEC de: {url}")
        resposta = requests.get(url)
        if resposta.status_code == 200:
            with open('ossec.conf', 'wb') as file:
                file.write(resposta.content)
            log_info('Arquivo de configuração do OSSEC baixado com sucesso.')
            
            # Verificar se o arquivo contém a configuração do servidor
            with open('ossec.conf', 'r') as file:
                content = file.read()
                # Verifica tanto o formato XML quanto o formato de variáveis
                if ("<server-ip>" not in content and "<server>" not in content and 
                    "USER_AGENT_SERVER_IP=" not in content):
                    log_warning("Arquivo de configuração não contém configuração de servidor válida!")
                    return False
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
        
        # Faz backup da configuração atual, se existir
        if os.path.exists('/var/ossec/etc/ossec.conf'):
            backup_cmd = ['cp', '/var/ossec/etc/ossec.conf', '/var/ossec/etc/ossec.conf.bak']
            if usar_sudo:
                backup_cmd.insert(0, 'sudo')
            try:
                subprocess.run(backup_cmd, check=True)
                log_info("Backup da configuração atual criado.")
            except Exception as e:
                log_warning(f"Não foi possível criar backup: {str(e)}")
        
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
        
        # Verifica se o arquivo contém a configuração do servidor
        with open('/var/ossec/etc/ossec.conf', 'r') as f:
            content = f.read()
            if ("<server-ip>" not in content and "<server>" not in content and 
                "USER_AGENT_SERVER_IP=" not in content):
                log_warning("Configuração do OSSEC não contém servidor válido!")
                return False
            
        # Ajusta as permissões do arquivo
        chmod_cmd = ['chmod', '640', '/var/ossec/etc/ossec.conf']
        chown_cmd = ['chown', 'root:ossec', '/var/ossec/etc/ossec.conf']
        
        if usar_sudo:
            chmod_cmd.insert(0, 'sudo')
            chown_cmd.insert(0, 'sudo')
            
        subprocess.run(chmod_cmd, check=True)
        subprocess.run(chown_cmd, check=True)
        
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
            
        # Download preloaded-vars.conf from server
        log_info("Baixando preloaded-vars.conf do servidor...")
        try:
            url = f'{SERVER_URL}/download/preloaded-vars.conf'
            log_info(f"Baixando de: {url}")
            resposta = requests.get(url)
            if resposta.status_code == 200:
                with open('preloaded-vars.conf', 'wb') as file:
                    file.write(resposta.content)
                log_info('Arquivo preloaded-vars.conf baixado com sucesso.')
            else:
                log_error(f'Falha ao baixar preloaded-vars.conf. Status: {resposta.status_code}')
                return False
        except Exception as e:
            log_exception('Erro ao baixar preloaded-vars.conf')
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
        if distro == "debian" or distro == "ubuntu":
            dependencies = ["build-essential",  # includes make, gcc, and other build tools
                          "libevent-dev", 
                          "libpcre2-dev", 
                          "libssl-dev",
                          "zlib1g-dev",
                          "wget",
                          "libsystemd-dev"]
            
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
            
            # Copy the downloaded preloaded-vars.conf to the correct location
            log_info("Copiando preloaded-vars.conf para o diretório de instalação...")
            try:
                # Copy the downloaded file to the installation directory
                subprocess.run(['cp', f'{current_dir}/preloaded-vars.conf', 'etc/preloaded-vars.conf'], check=True)
                log_info("preloaded-vars.conf copiado com sucesso.")
            except Exception as e:
                log_error(f"Erro ao copiar preloaded-vars.conf: {str(e)}")
                return False
            
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
            
            # Immediately configure OSSEC after installation
            log_info("Instalação concluída. Configurando OSSEC imediatamente...")
            if not configurar_ossec_pos_instalacao():
                log_error("Falha na configuração pós-instalação do OSSEC")
                return False
                
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

def configurar_ossec_pos_instalacao():
    """Configure OSSEC immediately after installation to ensure proper setup"""
    try:
        log_info("Configurando OSSEC após instalação...")
        
        # Verifica se o diretório existe
        if not os.path.exists('/var/ossec/etc'):
            log_error("Diretório /var/ossec/etc não encontrado após instalação")
            return False
        
        # Verifica se o arquivo ossec.conf foi baixado anteriormente
        if not os.path.exists('ossec.conf'):
            log_info("Arquivo ossec.conf não encontrado, baixando novamente...")
            if not baixar_ossec_conf():
                log_error("Falha ao baixar arquivo de configuração do OSSEC")
                return False
        
        # Baixa outros arquivos de configuração necessários
        arquivos_config = ['internal_options.conf', 'local_internal_options.conf']
        for arquivo in arquivos_config:
            log_info(f"Baixando {arquivo} do servidor...")
            try:
                url = f'{SERVER_URL}/download/{arquivo}'
                resposta = requests.get(url)
                if resposta.status_code == 200:
                    with open(arquivo, 'wb') as file:
                        file.write(resposta.content)
                    log_info(f'Arquivo {arquivo} baixado com sucesso.')
                    
                    # Copia o arquivo para o local correto
                    usar_sudo = os.geteuid() != 0 and verificar_sudo_disponivel()
                    comando = ['cp', arquivo, f'/var/ossec/etc/{arquivo}']
                    if usar_sudo:
                        comando.insert(0, 'sudo')
                    
                    subprocess.run(comando, check=True)
                    log_info(f"Arquivo {arquivo} copiado para /var/ossec/etc/{arquivo}")
                    
                    # Ajusta as permissões
                    chmod_cmd = ['chmod', '640', f'/var/ossec/etc/{arquivo}']
                    chown_cmd = ['chown', 'root:ossec', f'/var/ossec/etc/{arquivo}']
                    
                    if usar_sudo:
                        chmod_cmd.insert(0, 'sudo')
                        chown_cmd.insert(0, 'sudo')
                    
                    subprocess.run(chmod_cmd, check=True)
                    subprocess.run(chown_cmd, check=True)
                else:
                    log_warning(f'Não foi possível baixar {arquivo}. Status: {resposta.status_code}')
            except Exception as e:
                log_warning(f'Erro ao baixar/configurar {arquivo}: {str(e)}')
        
        # Verifica se o arquivo contém a configuração do servidor
        with open('ossec.conf', 'r') as f:
            content = f.read()
            if ("<server-ip>" not in content and "<server>" not in content and 
                "USER_AGENT_SERVER_IP=" not in content):
                log_warning("Configuração do OSSEC não contém servidor válido!")
                # Tenta corrigir adicionando um servidor padrão
                log_info("Tentando adicionar configuração de servidor padrão...")
                with open('ossec.conf', 'w') as f:
                    # Adiciona a configuração no formato apropriado
                    if "USER_LANGUAGE=" in content:
                        # Parece ser o formato de variáveis
                        if "USER_AGENT_SERVER_IP=" not in content:
                            # Adiciona a linha USER_AGENT_SERVER_IP
                            lines = content.split('\n')
                            new_lines = []
                            for line in lines:
                                new_lines.append(line)
                                if line.startswith("USER_AGENT_CONFIG_PROFILE=") or line.startswith("# USER_AGENT_CONFIG_PROFILE"):
                                    new_lines.append('USER_AGENT_SERVER_IP="ossec"')
                            content = '\n'.join(new_lines)
                        else:
                            # Tenta o formato XML
                            if "<client>" in content and "</client>" in content:
                                content = content.replace("</client>", "  <server-ip>ossec</server-ip>\n  </client>")
                            else:
                                content = f"<ossec_config>\n  <client>\n    <server-ip>ossec</server-ip>\n  </client>\n{content}</ossec_config>"
                        f.write(content)
        
        # Copia o arquivo para o local correto com sudo
        usar_sudo = os.geteuid() != 0 and verificar_sudo_disponivel()
        comando = ['cp', 'ossec.conf', '/var/ossec/etc/ossec.conf']
        if usar_sudo:
            comando.insert(0, 'sudo')
        
        log_info(f"Copiando configuração para /var/ossec/etc/ossec.conf: {' '.join(comando)}")
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
        
        log_info("Ajustando permissões do arquivo de configuração...")
        subprocess.run(chmod_cmd, check=True)
        subprocess.run(chown_cmd, check=True)
        
        # Verifica o conteúdo final do arquivo
        log_info("Verificando conteúdo final do arquivo de configuração...")
        cat_cmd = ['cat', '/var/ossec/etc/ossec.conf']
        if usar_sudo:
            cat_cmd.insert(0, 'sudo')
        
        resultado = subprocess.run(cat_cmd, capture_output=True, text=True)
        log_info(f"Conteúdo do arquivo ossec.conf:\n{resultado.stdout}")
        
        log_info("Configuração pós-instalação do OSSEC concluída com sucesso.")
        return True
        
    except Exception as e:
        log_exception(f"Erro durante a configuração pós-instalação do OSSEC: {str(e)}")
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
            
        # Configura o OSSEC novamente para garantir que a configuração esteja correta
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
                
            # Verifica novamente a configuração após importar a chave
            log_info("Verificando configuração após importação da chave...")
            if not configurar_ossec():
                log_error("Falha na configuração do OSSEC após importação da chave.")
                return False
            
        # Reinicia o serviço
        log_info("Reiniciando serviço OSSEC...")
        if not reiniciar_ossec():
            log_error("Falha ao reiniciar o serviço OSSEC.")
            
            # Verifica se o problema é falta de configuração de servidor
            log_info("Verificando problemas na configuração...")
            try:
                with open('/var/ossec/etc/ossec.conf', 'r') as f:
                    content = f.read()
                    if "<server-ip>" not in content and "<server>" not in content:
                        log_error("Configuração do OSSEC não contém servidor válido!")
                        
                        # Tenta corrigir o problema
                        log_info("Tentando corrigir configuração do servidor...")
                        with open('/var/ossec/etc/ossec.conf', 'w') as f:
                            if "<client>" in content and "</client>" in content:
                                content = content.replace("</client>", "  <server-ip>ossec</server-ip>\n  </client>")
                            else:
                                content = f"<ossec_config>\n  <client>\n    <server-ip>ossec</server-ip>\n  </client>\n{content}</ossec_config>"
                            f.write(content)
                        
                        # Tenta reiniciar novamente
                        log_info("Tentando reiniciar OSSEC após correção...")
                        if not reiniciar_ossec():
                            log_error("Falha ao reiniciar o serviço OSSEC após correção.")
                            return False
            except Exception as e:
                log_exception(f"Erro ao verificar/corrigir configuração: {str(e)}")
                return False
            
            return False
            
        log_info("Configuração completa do OSSEC concluída com sucesso.")
        return True
        
    except Exception as e:
        log_exception("Erro durante a configuração completa do OSSEC")
        return False