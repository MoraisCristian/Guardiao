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
        print("Verificando e configurando logging do iptables...")
        
        # Função para verificar se uma regra já existe e remover duplicatas
        def limpar_regras_log(chain):
            # Primeiro, verifica se existem regras LOG
            cmd_check = ['iptables', '-L', chain, '--line-numbers']
            if usar_sudo:
                cmd_check.insert(0, 'sudo')
            
            resultado = subprocess.run(cmd_check, capture_output=True, text=True)
            
            # Conta quantas regras LOG existem
            log_rules = [line for line in resultado.stdout.split('\n') if "LOG" in line]
            
            if len(log_rules) > 1:
                print(f"Detectadas {len(log_rules)} regras LOG duplicadas na chain {chain}. Removendo duplicatas...")
                
                # Remove todas as regras LOG, começando da última para não afetar os índices
                for i in range(len(log_rules)):
                    # Pega o número da linha da regra LOG
                    line_num = log_rules[-(i+1)].split()[0]
                    if line_num.isdigit():
                        cmd_del = ['iptables', '-D', chain, line_num]
                        if usar_sudo:
                            cmd_del.insert(0, 'sudo')
                        subprocess.run(cmd_del, check=True)
                
                # Agora adiciona uma única regra LOG
                cmd_add = ['iptables', '-A', chain, '-j', 'LOG']
                if usar_sudo:
                    cmd_add.insert(0, 'sudo')
                subprocess.run(cmd_add, check=True)
                print(f"Regras LOG na chain {chain} corrigidas.")
                return True
            elif len(log_rules) == 1:
                print(f"Uma regra LOG já existe na chain {chain}. Mantendo como está.")
                return True
            else:
                print(f"Nenhuma regra LOG encontrada na chain {chain}. Adicionando...")
                cmd_add = ['iptables', '-A', chain, '-j', 'LOG']
                if usar_sudo:
                    cmd_add.insert(0, 'sudo')
                subprocess.run(cmd_add, check=True)
                print(f"Regra LOG adicionada à chain {chain}.")
                return True
        
        # Limpa e configura regras LOG para INPUT e FORWARD
        limpar_regras_log('INPUT')
        limpar_regras_log('FORWARD')
        
        # Resto do código permanece igual
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
        
        # Atualizar assinaturas do PSAD com tratamento de erro específico
        print("Atualizando assinaturas do PSAD...")
        comando_sig = ['psad', '--sig-update']
        if usar_sudo:
            comando_sig.insert(0, 'sudo')
        
        try:
            # Executa o comando de atualização de assinaturas
            resultado = subprocess.run(comando_sig, capture_output=True, text=True)
            
            # Verifica se houve erro na execução
            if resultado.returncode != 0:
                # Verifica se o erro é relacionado ao HOSTNAME
                if "HOSTNAME not allowed" in resultado.stderr:
                    print("Aviso: Problema de configuração de HOSTNAME detectado. Tentando correção...")
                    # Corrige o problema de HOSTNAME
                    with open('/etc/psad/psad.conf', 'r') as f:
                        config = f.read()
                    
                    # Remove configurações problemáticas de HOSTNAME
                    config = config.replace('HOSTNAME $HOSTNAME;', 'HOSTNAME;')
                    
                    with open('/etc/psad/psad.conf', 'w') as f:
                        f.write(config)
                    
                    # Tenta novamente a atualização
                    subprocess.run(comando_sig, check=True)
                else:
                    raise subprocess.CalledProcessError(resultado.returncode, comando_sig, resultado.stdout, resultado.stderr)
            
            print("Assinaturas do PSAD atualizadas com sucesso.")
        except subprocess.CalledProcessError as e:
            print(f"Erro ao atualizar assinaturas do PSAD: {str(e)}")
            return False

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