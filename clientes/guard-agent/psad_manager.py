import os
import subprocess
import requests
import time
from system_utils import detect_os_distribution, verificar_sudo_disponivel
from config import SERVER_URL

def verificar_psad_instalado():
    """Check if PSAD is installed"""
    try:
        # Verifica se o binário do PSAD existe
        if os.path.exists('/usr/sbin/psad'):
            print("PSAD está instalado.")
            return True
        else:
            print("PSAD não está instalado.")
            return False
    except Exception as e:
        print(f"Erro ao verificar instalação do PSAD: {str(e)}")
        return False

def verificar_psad_running():
    """Check if PSAD is running"""
    try:
        # Verifica se precisa usar sudo
        usar_sudo = os.geteuid() != 0 and verificar_sudo_disponivel()
        
        # Comando para verificar o status do PSAD
        if os.path.exists('/bin/systemctl') or os.path.exists('/usr/bin/systemctl'):
            comando = ['systemctl', 'status', 'psad']
        else:
            comando = ['service', 'psad', 'status']
            
        if usar_sudo:
            comando.insert(0, 'sudo')
        
        resultado = subprocess.run(comando, capture_output=True, text=True)
        
        # Verifica se o PSAD está em execução
        if "active (running)" in resultado.stdout or "is running" in resultado.stdout:
            print("PSAD está em execução.")
            return True
        else:
            print("PSAD não está em execução.")
            return False
    except Exception as e:
        print(f"Erro ao verificar status do PSAD: {str(e)}")
        return False

def instalar_psad():
    """Install PSAD"""
    print("Instalando PSAD...")
    os_type = detect_os_distribution()
    
    try:
        if os_type in ['debian', 'ubuntu']:
            subprocess.run(['sudo', 'apt-get', 'update'], check=True)
            subprocess.run(['sudo', 'apt-get', 'install', '-y', 'psad'], check=True)
        elif os_type in ['centos', 'redhat']:
            subprocess.run(['sudo', 'yum', 'install', '-y', 'epel-release'], check=True)
            subprocess.run(['sudo', 'yum', 'install', '-y', 'psad'], check=True)
        elif os_type == 'darwin':
            subprocess.run(['brew', 'install', 'psad'], check=True)
        else:
            print(f"Instalação do PSAD não suportada para o sistema: {os_type}")
            return False
            
        print("PSAD instalado com sucesso.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Erro ao instalar o PSAD: {str(e)}")
        return False
    except Exception as e:
        print(f"Erro inesperado ao instalar o PSAD: {str(e)}")
        return False

def verificar_regras_iptables():
    """Verifica se as regras de log do iptables já existem"""
    try:
        # Verifica se precisa usar sudo
        usar_sudo = os.geteuid() != 0 and verificar_sudo_disponivel()
        
        # Comando para listar regras do INPUT
        comando = ['iptables', '-L', 'INPUT', '-n']
        if usar_sudo:
            comando.insert(0, 'sudo')
        
        resultado = subprocess.run(comando, capture_output=True, text=True)
        
        # Verifica se já existe regra LOG
        if "LOG" in resultado.stdout:
            print("Regras de log do iptables já configuradas.")
            return True
            
        return False
    except Exception as e:
        print(f"Erro ao verificar regras do iptables: {str(e)}")
        return False

def verificar_regra_iptables(regra):
    """Verifica se uma regra específica do iptables existe"""
    try:
        # Verifica se precisa usar sudo
        usar_sudo = os.geteuid() != 0 and verificar_sudo_disponivel()
        
        # Comando para verificar a regra
        comando = ['iptables', '-C'] + regra.split()
        if usar_sudo:
            comando.insert(0, 'sudo')
        
        subprocess.run(comando, check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        return False
    except Exception as e:
        print(f"Erro ao verificar regra do iptables: {str(e)}")
        return False

def verificar_configuracao_psad():
    """Verifica se o arquivo de configuração do PSAD existe e está atualizado"""
    try:
        if not os.path.exists("/etc/psad/psad.conf"):
            return False
            
        # Verifica a data de modificação do arquivo
        stat = os.stat("/etc/psad/psad.conf")
        # Se o arquivo foi modificado nas últimas 24 horas, considera atualizado
        return (time.time() - stat.st_mtime) < 86400
    except:
        return False

def executar_comando(comando):
    """Executa um comando no sistema"""
    try:
        resultado = subprocess.run(comando.split(), capture_output=True, text=True)
        return resultado.stdout
    except Exception as e:
        print(f"Erro ao executar comando: {str(e)}")
        raise

def baixar_configuracao_psad():
    """Baixa o arquivo de configuração do PSAD"""
    try:
        # Determinar qual arquivo de configuração baixar com base na estrutura do sistema
        arquivo_config = "psad-syslog.conf" if os.path.exists('/var/log/syslog') else "psad.conf"
        
        # Baixar o arquivo de configuração apropriado
        url = f'{SERVER_URL}/download/{arquivo_config}'
        resposta = requests.get(url)
        if resposta.status_code == 200:
            # Salvar temporariamente o arquivo
            with open('psad_temp.conf', 'wb') as file:
                file.write(resposta.content)
            
            # Mover o arquivo para o local correto
            comando_mv = ['mv', 'psad_temp.conf', '/etc/psad/psad.conf']
            if os.geteuid() != 0 and verificar_sudo_disponivel():
                comando_mv.insert(0, 'sudo')
            subprocess.run(comando_mv, check=True)
        else:
            print(f"Falha ao baixar o arquivo de configuração {arquivo_config}. Status Code: {resposta.status_code}")
            return False
    except Exception as e:
        print(f"Erro ao baixar arquivo de configuração do PSAD: {str(e)}")
        raise

def configurar_psad():
    """Configura o PSAD no sistema"""
    try:
        # Verifica se o PSAD já está instalado
        if not verificar_psad_instalado():
            print("PSAD não está instalado. Instalando...")
            if not instalar_psad():
                print("Falha ao instalar o PSAD.")
                return False
        else:
            print("PSAD já está instalado.")

        # Verifica se as regras de log já existem
        if not verificar_regras_iptables():
            print("Configurando regras de log do iptables...")
            
            # Adiciona regras de log apenas se não existirem
            if not verificar_regra_iptables("INPUT -j LOG"):
                executar_comando("iptables -A INPUT -j LOG")
                print("Regra de log adicionada ao INPUT")
            
            if not verificar_regra_iptables("FORWARD -j LOG"):
                executar_comando("iptables -A FORWARD -j LOG")
                print("Regra de log adicionada ao FORWARD")
        else:
            print("Regras de log do iptables já configuradas.")

        # Verifica se o arquivo de configuração já existe e está atualizado
        if not verificar_configuracao_psad():
            print("Atualizando configuração do PSAD...")
            baixar_configuracao_psad()
            print("Configuração do PSAD atualizada com sucesso.")
        else:
            print("Configuração do PSAD já está atualizada.")

        return True
    except Exception as e:
        print(f"Erro ao configurar PSAD: {str(e)}")
        return False

def verificar_e_configurar_psad():
    """Verify and configure PSAD"""
    try:
        # Check if PSAD is installed
        if not verificar_psad_instalado():
            print("PSAD não está instalado. Instalando...")
            if not instalar_psad():
                print("Falha ao instalar o PSAD.")
                return False
        
        # Configure PSAD
        if not configurar_psad():
            print("Falha ao configurar o PSAD.")
            return False
        
        # Verify if PSAD is running
        if not verificar_psad_running():
            print("PSAD não está em execução.")
            return False
        
        print("PSAD verificado e configurado com sucesso.")
        return True
    except Exception as e:
        print(f"Erro ao verificar e configurar PSAD: {str(e)}")
        return False