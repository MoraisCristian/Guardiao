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
    """Check if OSSEC key is already imported"""
    try:
        with open('/var/ossec/etc/client.keys', 'r') as f:
            conteudo = f.read().strip()
            return len(conteudo) > 0
    except FileNotFoundError:
        return False
    except PermissionError:
        # Se não conseguir ler o arquivo por permissão, tenta verificar com sudo
        if verificar_sudo_disponivel():
            try:
                output = subprocess.check_output(['sudo', 'cat', '/var/ossec/etc/client.keys'], stderr=subprocess.PIPE).decode().strip()
                return len(output) > 0
            except subprocess.CalledProcessError:
                return False
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
    # Verifica se a chave é uma lista e extrai o valor correto
    if isinstance(activation_key, list):
        print(activation_key)
        # A chave está no primeiro elemento da lista
        key_text = activation_key[0]
    else:
        key_text = activation_key
    
    # Extrai apenas a parte Base64 da chave
    match = re.search(r'([A-Za-z0-9+/=]{20,})', key_text)
    if match:
        actual_key = match.group(1).strip()
    else:
        print("Formato de chave inválido. Não foi possível extrair a chave.")
        return False
    
    if not actual_key:
        print("Chave de ativação do OSSEC está vazia. Não é possível importar.")
        return False
    
    print(f"Chave a ser importada: {actual_key}")
    
    # Executa comandos necessários antes de importar a chave
    try:
        # Prepara os comandos com ou sem sudo conforme necessário
        usar_sudo = os.geteuid() != 0 and verificar_sudo_disponivel()
        
        # Cria os diretórios necessários se não existirem
        diretorios = [
            '/var/ossec/queue',
            '/var/ossec/queue/rids',
            '/var/ossec/queue/agent-info',
            '/var/ossec/queue/syscheck',
            '/var/ossec/queue/rootcheck',
            '/var/ossec/queue/diff'
        ]
        
        for diretorio in diretorios:
            if not os.path.exists(diretorio):
                comando_mkdir = ['mkdir', '-p', diretorio]
                if usar_sudo:
                    comando_mkdir.insert(0, 'sudo')
                subprocess.run(comando_mkdir, check=True)
                print(f"Diretório {diretorio} criado com sucesso.")
        
        # Cria o arquivo sender
        sender_path = '/var/ossec/queue/rids/sender'
        comando_touch = ['touch', sender_path]
        if usar_sudo:
            comando_touch.insert(0, 'sudo')
        subprocess.run(comando_touch, check=True)
        print(f"Arquivo {sender_path} criado com sucesso.")
        
        # Ajusta as permissões
        comando_chown = ['chown', '-R', 'ossec:ossec', '/var/ossec']
        if usar_sudo:
            comando_chown.insert(0, 'sudo')
        subprocess.run(comando_chown, check=True)
        
        print("Preparação do ambiente OSSEC concluída com sucesso.")
    except subprocess.CalledProcessError as e:
        print(f"Erro ao preparar o ambiente OSSEC: {str(e)}")
        # Continua mesmo com erro, pois pode ser que já esteja configurado
    
    try:
        # Importa a chave diretamente usando o comando echo para fornecer 'y' como resposta
        comando_completo = f"echo 'y' | "
        if usar_sudo:
            comando_completo += "sudo "
        comando_completo += f"/var/ossec/bin/manage_agents -i {actual_key}"
        
        print(f"Executando comando: {comando_completo}")
        resultado = subprocess.run(comando_completo, shell=True, capture_output=True, text=True)
        
        if resultado.returncode != 0:
            print(f"Erro ao importar a chave: {resultado.stderr}")
            return False
            
        print("Chave do OSSEC importada com sucesso.")
        print(f"Saída do comando: {resultado.stdout}")
        
        # Reinicia o serviço do OSSEC
        return reiniciar_ossec()
    except Exception as e:
        print(f"Erro ao importar a chave do OSSEC: {str(e)}")
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