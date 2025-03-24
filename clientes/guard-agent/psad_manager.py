import os
import subprocess
import requests
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

def configurar_psad():
    """Configure PSAD after installation"""
    print("Configurando PSAD...")
    
    # Verifica se precisa usar sudo
    usar_sudo = os.geteuid() != 0 and verificar_sudo_disponivel()
    
    try:
        # Habilitar logging do iptables
        print("Habilitando logging do iptables...")
        comandos_iptables = [
            ['iptables', '-A', 'INPUT', '-j', 'LOG'],
            ['iptables', '-A', 'FORWARD', '-j', 'LOG']
        ]
        
        for comando in comandos_iptables:
            if usar_sudo:
                comando.insert(0, 'sudo')
            try:
                subprocess.run(comando, check=True)
                print(f"Comando executado com sucesso: {' '.join(comando)}")
            except subprocess.CalledProcessError as e:
                print(f"Erro ao executar comando iptables: {str(e)}")
        
        # Determinar qual arquivo de configuração baixar com base na estrutura do sistema
        arquivo_config = "psad-syslog.conf" if os.path.exists('/var/log/syslog') else "psad.conf"
        print(f"Detectado sistema com {'syslog' if os.path.exists('/var/log/syslog') else 'messages'}, baixando {arquivo_config}...")
        
        # Baixar o arquivo de configuração apropriado
        url = f'{SERVER_URL}/download/{arquivo_config}'
        resposta = requests.get(url)
        if resposta.status_code == 200:
            # Salvar temporariamente o arquivo
            with open('psad_temp.conf', 'wb') as file:
                file.write(resposta.content)
            print(f"Arquivo de configuração {arquivo_config} baixado com sucesso.")
            
            # Mover o arquivo para o local correto
            comando_mv = ['mv', 'psad_temp.conf', '/etc/psad/psad.conf']
            if usar_sudo:
                comando_mv.insert(0, 'sudo')
            subprocess.run(comando_mv, check=True)
            print("Arquivo de configuração movido para /etc/psad/psad.conf")
        else:
            print(f"Falha ao baixar o arquivo de configuração {arquivo_config}. Status Code: {resposta.status_code}")
            return False
        
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
    """Check and configure PSAD"""
    # Verifica se o PSAD está instalado
    if not verificar_psad_instalado():
        # Instala o PSAD se não estiver instalado
        if not instalar_psad():
            print("Falha ao instalar o PSAD.")    
            # Configura o PSAD
            configurar_psad()
            return False
    
    # Verifica se o PSAD está em execução
    if not verificar_psad_running():
        # Inicia o serviço PSAD
        try:
            usar_sudo = os.geteuid() != 0 and verificar_sudo_disponivel()
            os_type = detect_os_distribution()
            
            if os_type in ['debian', 'ubuntu'] or os_type in ['centos', 'redhat']:
                if os.path.exists('/bin/systemctl') or os.path.exists('/usr/bin/systemctl'):
                    comando_start = ['systemctl', 'start', 'psad']
                    comando_enable = ['systemctl', 'enable', 'psad']
                else:
                    comando_start = ['service', 'psad', 'start']
                    comando_enable = ['service', 'psad', 'enable']
            elif os_type == 'darwin':
                comando_start = ['launchctl', 'load', '-w', '/Library/LaunchDaemons/com.psad.plist']
                comando_enable = ['launchctl', 'load', '-w', '/Library/LaunchDaemons/com.psad.plist']
            else:
                print(f"Inicialização do PSAD não suportada para o sistema: {os_type}")
                return False
                
            if usar_sudo and os_type != 'darwin':
                comando_start.insert(0, 'sudo')
                comando_enable.insert(0, 'sudo')
                
            subprocess.run(comando_enable, check=True)
            subprocess.run(comando_start, check=True)
            print("Serviço PSAD iniciado e habilitado com sucesso.")
            return True
        except Exception as e:
            print(f"Erro ao iniciar o serviço PSAD: {str(e)}")
            return False
    
    return True