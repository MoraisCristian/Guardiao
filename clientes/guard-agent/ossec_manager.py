import os
import subprocess
import requests
import re
import sys
from system_utils import os_update, os_install, detect_os_distribution, verificar_sudo_disponivel
from config import SERVER_URL

def baixar_ossec_conf():
    """Download OSSEC configuration file"""
    url = f'{SERVER_URL}/download/ossec.conf'
    resposta = requests.get(url)
    if resposta.status_code == 200:
        with open('preloaded-vars.conf', 'wb') as file:
            file.write(resposta.content)
        print('Arquivo de configuração do OSSEC baixado com sucesso.')
        return True
    else:
        print('Falha ao baixar o arquivo de configuração do OSSEC.')
        return False

def verificar_ossec_instalado():
    """Check if OSSEC is already installed"""
    return os.path.exists('/var/ossec/bin/ossec-agentd')

def verificar_chave_ossec_importada():
    """Check if OSSEC key is imported"""
    try:
        # Check if client.keys exists and is not empty
        client_keys_path = "/var/ossec/etc/client.keys"
        if not os.path.exists(client_keys_path):
            print("Arquivo client.keys não encontrado.")
            return False
            
        # Check if file is empty or contains only whitespace
        with open(client_keys_path, 'r') as f:
            content = f.read().strip()
            if not content:
                print("Arquivo client.keys está vazio.")
                return False
                
        print("Chave do OSSEC já importada.")
        return True
    except Exception as e:
        print(f"Erro ao verificar chave do OSSEC: {str(e)}")
        return False

def reiniciar_ossec():
    """Restart OSSEC service"""
    comando_base = ['/var/ossec/bin/ossec-control', 'restart']
    
    # Verifica se precisa usar sudo
    if os.geteuid() != 0 and verificar_sudo_disponivel():
        comando_base.insert(0, 'sudo')
    
    try:
        subprocess.run(comando_base, check=True)
        print("Serviço do OSSEC reiniciado com sucesso.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Erro ao reiniciar o serviço do OSSEC: {str(e)}")
        return False

def importar_chave_ossec(activation_key):
    """Import OSSEC key"""
    try:
        # Verifica se a chave é uma lista e extrai o valor correto
        if isinstance(activation_key, list):
            key_text = activation_key[0]
        else:
            key_text = activation_key
        
        # Extrai apenas a parte Base64 da chave
        match = re.search(r'([A-Za-z0-9+/=]{20,})', key_text)
        if not match:
            print("Formato de chave inválido. Não foi possível extrair a chave.")
            return False
            
        actual_key = match.group(1).strip()
        
        if not actual_key:
            print("Chave de ativação do OSSEC está vazia. Não é possível importar.")
            return False
        
        print(f"Chave a ser importada: {actual_key}")
        
        # Executa o comando de importação
        try:
            process = subprocess.Popen(['/var/ossec/bin/manage_agents', '-i'],
                                     stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     text=True)
            
            # Envia 'y' e a chave para o processo
            output, error = process.communicate(input=f"y\n{actual_key}\n")
            
            if process.returncode != 0:
                print(f"Erro ao importar a chave: {error}")
                return False
                
            print("Chave do OSSEC importada com sucesso.")
            return True
            
        except Exception as e:
            print(f"Erro ao importar a chave do OSSEC: {str(e)}")
            return False
            
    except Exception as e:
        print(f"Erro geral ao processar chave do OSSEC: {str(e)}")
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
    
    # Baixa o