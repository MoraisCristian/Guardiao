import os
import subprocess
import requests
import re
import sys
from system_utils import os_update, os_install, detect_os_distribution, verificar_sudo_disponivel
from config import SERVER_URL
from logger import log_info, log_warning, log_error, log_debug, log_critical, log_exception

def baixar_ossec_conf():
    """Download OSSEC configuration file"""
    try:
        url = f'{SERVER_URL}/download/ossec.conf'
        resposta = requests.get(url)
        if resposta.status_code == 200:
            with open('preloaded-vars.conf', 'wb') as file:
                file.write(resposta.content)
            log_info('Arquivo de configuração do OSSEC baixado com sucesso.')
            return True
        else:
            log_error(f'Falha ao baixar o arquivo de configuração do OSSEC. Status: {resposta.status_code}')
            return False
    except Exception as e:
        log_exception('Erro ao baixar configuração do OSSEC')
        return False

def verificar_ossec_instalado():
    """Check if OSSEC is already installed"""
    try:
        installed = os.path.exists('/var/ossec/bin/ossec-agentd')
        log_debug(f'Verificação de instalação do OSSEC: {installed}')
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
        key_match = re.search(r"Agent key information for '\d+':\s+(\S+)", activation_key)
        if key_match:
            actual_key = key_match.group(1).strip()
        else:
            # If regex fails, try to get the last line that looks like a key
            lines = activation_key.split('\n')
            actual_key = lines[-1].strip() if lines else ''
        
        if not actual_key:
            log_error("Chave de ativação do OSSEC está vazia. Não é possível importar.")
            return False
        
        log_debug(f"Chave a ser importada: {actual_key}")
        
        # Execute the import command
        try:
            process = subprocess.Popen(['/var/ossec/bin/manage_agents', '-i'],
                                     stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     text=True)
            
            # Send 'y' and the key to the process
            output, error = process.communicate(input=f"y\n{actual_key}\n")
            
            if process.returncode != 0:
                log_error(f"Erro ao importar a chave: {error}")
                return False
                
            # Verify if the key was actually written to client.keys
            if not verificar_chave_ossec_importada():
                log_error("A chave não foi escrita corretamente no arquivo client.keys")
                return False
                
            log_info("Chave do OSSEC importada com sucesso.")
            return True
            
        except Exception as e:
            log_exception(f"Erro ao importar a chave do OSSEC")
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
    # Verifica se o OSSEC já está instalado
    if verificar_ossec_instalado():
        print("OSSEC já está instalado. Pulando a instalação.")
        return True
    
    # Baixa o pacote de instalação do OSSEC
    try:
        print("Baixando pacote de instalação do OSSEC...")
        url = f'{SERVER_URL}/download/ossec-agent.deb'
        response = requests.get(url)
        
        if response.status_code != 200:
            print("Falha ao baixar o pacote de instalação do OSSEC.")
            return False
            
        # Salva o pacote localmente
        with open('ossec-agent.deb', 'wb') as f:
            f.write(response.content)
            
        print("Pacote de instalação do OSSEC baixado com sucesso.")
        
        # Instala o pacote
        print("Instalando OSSEC...")
        comando = ['dpkg', '-i', 'ossec-agent.deb']
        
        # Verifica se precisa usar sudo
        if os.geteuid() != 0 and verificar_sudo_disponivel():
            comando.insert(0, 'sudo')
            
        resultado = subprocess.run(comando, capture_output=True, text=True)
        
        if resultado.returncode != 0:
            print(f"Erro durante a instalação do OSSEC: {resultado.stderr}")
            return False
            
        print("OSSEC instalado com sucesso.")
        return True
        
    except Exception as e:
        print(f"Erro durante a instalação do OSSEC: {str(e)}")
        return False

def configurar_ossec():
    """Configure OSSEC"""
    try:
        # Baixa o arquivo de configuração
        if not baixar_ossec_conf():
            return False
            
        # Move o arquivo de configuração para o diretório correto
        comando = ['mv', 'preloaded-vars.conf', '/var/ossec/etc/preloaded-vars.conf']
        comando = ['cp', '/var/ossec/etc/preloaded-vars.conf', '/var/ossec/etc/ossec.conf']
        
        # Verifica se precisa usar sudo
        if os.geteuid() != 0 and verificar_sudo_disponivel():
            comando.insert(0, 'sudo')
            
        resultado = subprocess.run(comando, capture_output=True, text=True)
        
        if resultado.returncode != 0:
            print(f"Erro ao mover arquivo de configuração: {resultado.stderr}")
            return False
            
        print("Configuração do OSSEC concluída com sucesso.")
        return True
        
    except Exception as e:
        print(f"Erro durante a configuração do OSSEC: {str(e)}")
        return False

def setup_ossec(activation_key=None):
    """Complete OSSEC setup"""
    try:
        # Instala o OSSEC
        if not instalar_ossec():
            return False
            
        # Configura o OSSEC
        if not configurar_ossec():
            return False
            
        # Importa a chave de ativação, se fornecida
        if activation_key and not importar_chave_ossec(activation_key):
            return False
            
        # Reinicia o serviço
        if not reiniciar_ossec():
            return False
            
        print("Configuração completa do OSSEC concluída com sucesso.")
        return True
        
    except Exception as e:
        print(f"Erro durante a configuração completa do OSSEC: {str(e)}")
        return False