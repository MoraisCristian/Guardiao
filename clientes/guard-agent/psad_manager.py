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
    """Verify if PSAD is installed and properly configured"""
    from logger import log_info, log_warning, log_error, log_debug
    import subprocess
    import os
    from system_utils import detect_os_distribution, os_install
    import requests
    from config import SERVER_URL

    log_info("Verificando PSAD...")
    
    # Check if PSAD is installed
    try:
        subprocess.run(["which", "psad"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        log_info("PSAD já está instalado.")
    except subprocess.CalledProcessError:
        log_info("PSAD não encontrado. Instalando...")
        
        # Install PSAD based on distribution
        distro = detect_os_distribution()
        if distro in ['debian', 'ubuntu']:
            subprocess.run(["apt-get", "update"], check=True)
            subprocess.run(["apt-get", "install", "-y", "psad"], check=True)
        elif distro in ['centos', 'redhat']:
            subprocess.run(["yum", "install", "-y", "psad"], check=True)
        else:
            log_error(f"Distribuição {distro} não suportada para instalação do PSAD.")
            return False
    
    # Ensure iptables is installed and configured for logging
    log_info("Configurando iptables para logging...")
    
    try:
        # Check if iptables is installed
        subprocess.run(["which", "iptables"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Configure iptables for logging if not already configured
        # First check if logging rules exist
        iptables_output = subprocess.check_output(["iptables", "-L", "-v"], universal_newlines=True)
        
        # Check if LOG targets are present
        if "LOG" not in iptables_output:
            log_info("Adicionando regras de logging ao iptables...")
            
            # Add logging rules for TCP, UDP, and ICMP
            subprocess.run(["iptables", "-A", "INPUT", "-j", "LOG", "--log-level", "4", "--log-prefix", "IPTABLES:"], check=True)
            subprocess.run(["iptables", "-A", "FORWARD", "-j", "LOG", "--log-level", "4", "--log-prefix", "IPTABLES:"], check=True)
            
            # Save iptables rules
            distro = detect_os_distribution()
            if distro in ['debian', 'ubuntu']:
                # For Debian/Ubuntu
                if os.path.exists("/etc/iptables"):
                    subprocess.run("iptables-save > /etc/iptables/rules.v4", shell=True, check=True)
                else:
                    subprocess.run("mkdir -p /etc/iptables", shell=True, check=True)
                    subprocess.run("iptables-save > /etc/iptables/rules.v4", shell=True, check=True)
                    # Add persistence on boot
                    with open("/etc/network/if-pre-up.d/iptables", "w") as f:
                        f.write("#!/bin/sh\niptables-restore < /etc/iptables/rules.v4\nexit 0\n")
                    subprocess.run("chmod +x /etc/network/if-pre-up.d/iptables", shell=True, check=True)
            elif distro in ['centos', 'redhat']:
                # For CentOS/RHEL
                subprocess.run(["service", "iptables", "save"], check=True)
            
            log_info("Regras de logging do iptables configuradas com sucesso.")
        else:
            log_info("Regras de logging do iptables já estão configuradas.")
    except subprocess.CalledProcessError as e:
        log_error(f"Erro ao configurar iptables: {str(e)}")
        # Continue even if iptables configuration fails
    
    # Configure PSAD for OSSEC integration
    log_info("Configurando PSAD para integração com OSSEC...")
    
    try:
        # Backup original psad.conf
        if os.path.exists("/etc/psad/psad.conf"):
            subprocess.run(["cp", "/etc/psad/psad.conf", "/etc/psad/psad.conf.bak"], check=True)
        
        # Determine which configuration file to download
        arquivo_config = "psad-syslog.conf" if os.path.exists('/var/log/syslog') else "psad.conf"
        log_info(f"Detectado sistema com {'syslog' if os.path.exists('/var/log/syslog') else 'messages'}, baixando {arquivo_config}...")
        
        # Download the appropriate configuration file
        url = f'{SERVER_URL}/download/{arquivo_config}'
        resposta = requests.get(url)
        if resposta.status_code == 200:
            # Save temporarily
            with open('psad_temp.conf', 'wb') as file:
                file.write(resposta.content)
            log_info(f"Arquivo de configuração {arquivo_config} baixado com sucesso.")
            
            # Move to correct location
            comando_mv = ['mv', 'psad_temp.conf', '/etc/psad/psad.conf']
            if os.geteuid() != 0:
                comando_mv.insert(0, 'sudo')
            subprocess.run(comando_mv, check=True)
            log_info("Arquivo de configuração movido para /etc/psad/psad.conf")
        else:
            log_error(f"Falha ao baixar o arquivo de configuração {arquivo_config}. Status Code: {resposta.status_code}")
            return False

        # Update PSAD configuration
        psad_config_updates = [
            "sed -i 's/^EMAIL_ADDRESSES.*/EMAIL_ADDRESSES             root@localhost;/' /etc/psad/psad.conf",
            "sed -i 's/^HOSTNAME.*/HOSTNAME                   $HOSTNAME;/' /etc/psad/psad.conf",
            "sed -i 's/^ALERTING_METHODS.*/ALERTING_METHODS             syslog;/' /etc/psad/psad.conf",
            "sed -i 's/^ENABLE_SYSLOG_FILE.*/ENABLE_SYSLOG_FILE          Y;/' /etc/psad/psad.conf",
            "sed -i 's/^IPT_SYSLOG_FILE.*/IPT_SYSLOG_FILE             \\/var\\/log\\/syslog;/' /etc/psad/psad.conf",
            "sed -i 's/^EXPECT_TCP_OPTIONS.*/EXPECT_TCP_OPTIONS          Y;/' /etc/psad/psad.conf",
            "sed -i 's/^ENABLE_AUTO_IDS.*/ENABLE_AUTO_IDS             N;/' /etc/psad/psad.conf",
            "sed -i 's/^DANGER_LEVEL1.*/DANGER_LEVEL1               5;/' /etc/psad/psad.conf",
            "sed -i 's/^DANGER_LEVEL2.*/DANGER_LEVEL2               10;/' /etc/psad/psad.conf",
            "sed -i 's/^DANGER_LEVEL3.*/DANGER_LEVEL3               15;/' /etc/psad/psad.conf",
            "sed -i 's/^DANGER_LEVEL4.*/DANGER_LEVEL4               50;/' /etc/psad/psad.conf",
            "sed -i 's/^DANGER_LEVEL5.*/DANGER_LEVEL5               100;/' /etc/psad/psad.conf",
            "sed -i 's/^PORT_RANGE_SCAN_THRESHOLD.*/PORT_RANGE_SCAN_THRESHOLD   5;/' /etc/psad/psad.conf",
            "sed -i 's/^ENABLE_PERSISTENCE.*/ENABLE_PERSISTENCE          Y;/' /etc/psad/psad.conf",
            "sed -i 's/^MAX_SCAN_IP_PAIRS.*/MAX_SCAN_IP_PAIRS           10000;/' /etc/psad/psad.conf"
        ]
        
        # Apply configuration updates
        for cmd in psad_config_updates:
            subprocess.run(cmd, shell=True, check=True)
        
        # Configure syslog for PSAD
        distro = detect_os_distribution()
        if distro in ['debian', 'ubuntu']:
            # For Debian/Ubuntu, check if rsyslog is used
            if os.path.exists("/etc/rsyslog.d"):
                # Create or update rsyslog configuration for iptables
                with open("/etc/rsyslog.d/10-iptables.conf", "w") as f:
                    f.write(":msg, contains, \"IPTABLES:\" -/var/log/iptables.log\n")
                    f.write("& ~\n")  # Stop processing this message
                
                # Restart rsyslog
                subprocess.run(["systemctl", "restart", "rsyslog"], check=True)
        elif distro in ['centos', 'redhat']:
            # For CentOS/RHEL
            if os.path.exists("/etc/rsyslog.d"):
                with open("/etc/rsyslog.d/10-iptables.conf", "w") as f:
                    f.write(":msg, contains, \"IPTABLES:\" -/var/log/iptables.log\n")
                    f.write("& ~\n")
                
                # Restart rsyslog
                subprocess.run(["systemctl", "restart", "rsyslog"], check=True)
        
        # Ensure OSSEC can read PSAD logs
        if os.path.exists("/var/ossec/etc/ossec.conf"):
            # Check if PSAD log monitoring is already configured
            with open("/var/ossec/etc/ossec.conf", "r") as f:
                ossec_conf = f.read()
            
            if "<location>/var/log/psad</location>" not in ossec_conf:
                log_info("Adicionando monitoramento de logs do PSAD ao OSSEC...")
                
                # Add PSAD log monitoring to OSSEC configuration
                subprocess.run([
                    "sed", "-i", 
                    "/<\/ossec_config>/i \  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/psad/psad.log</location>\n  </localfile>", 
                    "/var/ossec/etc/ossec.conf"
                ], check=True)
        
        # Update PSAD signatures
        log_info("Atualizando assinaturas do PSAD...")
        subprocess.run(["psad", "--sig-update"], check=True)
        
        # Initialize PSAD
        log_info("Inicializando PSAD...")
        subprocess.run(["psad", "-H"], check=True)
        
        # Restart PSAD to apply changes
        log_info("Reiniciando PSAD...")
        subprocess.run(["systemctl", "restart", "psad"], check=True)
        
        # Validate PSAD configuration
        log_info("Validando configuração do PSAD...")
        psad_status = subprocess.run(["psad", "--Status"], capture_output=True, text=True)
        if "psad: pid" in psad_status.stdout:
            log_info("PSAD está em execução corretamente.")
        else:
            log_warning("PSAD pode não estar em execução corretamente. Verifique manualmente.")
        
        log_info("PSAD configurado com sucesso para integração com OSSEC.")
        return True
        
    except subprocess.CalledProcessError as e:
        log_error(f"Erro ao configurar PSAD: {str(e)}")
        return False
    except Exception as e:
        log_error(f"Erro inesperado ao configurar PSAD: {str(e)}")
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