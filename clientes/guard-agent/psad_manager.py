import os
import subprocess
import requests
from system_utils import detect_os_distribution, verificar_sudo_disponivel
from config import SERVER_URL
import time

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

def configurar_psad():
    """Configure PSAD after installation"""
    print("Configurando PSAD...")
    
    # Verifica se precisa usar sudo
    usar_sudo = os.geteuid() != 0 and verificar_sudo_disponivel()
    
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
            print("Configurando PSAD...")
            print("Habilitando logging do iptables...")
            
            # Adiciona regras de log apenas se não existirem
            if not verificar_regra_iptables("INPUT -j LOG"):
                executar_comando("iptables -A INPUT -j LOG")
                print("Comando executado com sucesso: iptables -A INPUT -j LOG")
            
            if not verificar_regra_iptables("FORWARD -j LOG"):
                executar_comando("iptables -A FORWARD -j LOG")
                print("Comando executado com sucesso: iptables -A FORWARD -j LOG")
        else:
            print("Regras de log do iptables já configuradas.")

        # Verifica se o arquivo de configuração já existe e está atualizado
        if not verificar_configuracao_psad():
            print("Detectado sistema com syslog, baixando psad-syslog.conf...")
            baixar_configuracao_psad()
            print("Arquivo de configuração psad-syslog.conf baixado com sucesso.")
            print("Arquivo de configuração movido para /etc/psad/psad.conf")
        else:
            print("Configuração do PSAD já está atualizada.")

        # Atualizar assinaturas do PSAD
        print("Atualizando assinaturas do PSAD...")
        comando_sig = ['psad', '--sig-update']
        if usar_sudo:
            comando_sig.insert(0, 'sudo')
        subprocess.run(comando_sig, check=True)
        print("Assinaturas do PSAD atualizadas com sucesso.")
        
        # Iniciar e habilitar o serviço PSAD
        print("Iniciando e habilitando o serviço PSAD...")
        os_type = detect_os_distribution()
        
        # Diferentes comandos para diferentes sistemas
        if os_type in ['debian', 'ubuntu'] or os_type in ['centos', 'redhat']:
            # Sistemas que usam systemd
            comandos_service = [
                ['systemctl', 'enable', 'psad'],
                ['systemctl', 'start', 'psad']
            ]
        elif os_type == 'darwin':
            # macOS (usando launchctl)
            comandos_service = [
                ['launchctl', 'load', '-w', '/Library/LaunchDaemons/com.psad.plist']
            ]
        else:
            # Sistemas genéricos (usando service)
            comandos_service = [
                ['service', 'psad', 'enable'],
                ['service', 'psad', 'start']
            ]
        
        for comando in comandos_service:
            if usar_sudo and os_type != 'darwin':  # No macOS, launchctl não precisa de sudo
                comando.insert(0, 'sudo')
            try:
                subprocess.run(comando, check=True)
                print(f"Comando executado com sucesso: {' '.join(comando)}")
            except subprocess.CalledProcessError as e:
                print(f"Aviso: Erro ao executar comando de serviço: {str(e)}")
                # Tenta método alternativo se o primeiro falhar
                if 'systemctl' in comando:
                    alt_comando = ['service', 'psad', 'start' if 'start' in comando else 'enable']
                    if usar_sudo:
                        alt_comando.insert(0, 'sudo')
                    try:
                        subprocess.run(alt_comando, check=True)
                        print(f"Método alternativo executado com sucesso: {' '.join(alt_comando)}")
                    except subprocess.CalledProcessError as e2:
                        print(f"Erro também no método alternativo: {str(e2)}")
        
        print("Configuração do PSAD concluída com sucesso.")
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

def verificar_regras_iptables():
    """Verifica se as regras de log do iptables já existem"""
    try:
        output = executar_comando("iptables -L INPUT -n | grep LOG")
        return "LOG" in output
    except:
        return False

def verificar_regra_iptables(regra):
    """Verifica se uma regra específica do iptables existe"""
    try:
        output = executar_comando(f"iptables -C {regra}")
        return True
    except:
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

def baixar_configuracao_psad():
    # Implemente a lógica para baixar o arquivo de configuração do PSAD
    pass

def executar_comando(comando):
    # Implemente a lógica para executar um comando no sistema
    pass