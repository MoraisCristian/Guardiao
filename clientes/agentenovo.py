import subprocess, requests, platform, socket, base64, psutil, time, json, pwd, os
from time import sleep

# Variáveis globais
ram = {}
nome = socket.gethostname()
chave_ativacao = 'KOAUBDFDOEOER1EQLKZQQQ5COTTQFLO1ZI1TYHDZVPLDEDA0'
codigos = {'registro': 1, 'ping': 2, 'upload': 3, 'ossec-register': 4}

def baixar_ossec_conf():
    url = 'http://10.0.10.183:5002/download/ossec.conf'
    resposta = requests.get(url)
    if resposta.status_code == 200:
        with open('preloaded-vars.conf', 'wb') as file:
            file.write(resposta.content)
        print('Arquivo de configuração do OSSEC baixado com sucesso.')
        return True
    else:
        print('Falha ao baixar o arquivo de configuração do OSSEC.')
        return False

# Function to detect the OS distribution
def detect_os_distribution():
    if platform.system().lower() != 'linux':
        return platform.system().lower()
    
    # Check for specific Linux distributions
    if os.path.exists('/etc/debian_version'):
        with open('/etc/os-release') as f:
            if 'ID=ubuntu' in f.read():
                return 'ubuntu'
            return 'debian'
    elif os.path.exists('/etc/centos-release'):
        return 'centos'
    elif os.path.exists('/etc/redhat-release'):
        return 'redhat'
    
    # Default to generic linux if can't determine specific distro
    return 'linux'

# Function to update the operating system
def os_update():
    os_type = detect_os_distribution()
    print(f"Atualizando sistema operacional: {os_type}")
    
    try:
        if os_type == 'debian' or os_type == 'ubuntu':
            # For Debian/Ubuntu systems
            subprocess.run(['sudo', 'apt-get', 'update'], check=True)
            subprocess.run(['sudo', 'apt-get', 'upgrade', '-y'], check=True)
            print("Sistema Debian/Ubuntu atualizado com sucesso.")
            return True
        elif os_type == 'centos' or os_type == 'redhat':
            # For CentOS/RHEL systems
            subprocess.run(['sudo', 'yum', 'update', '-y'], check=True)
            print("Sistema CentOS/RHEL atualizado com sucesso.")
            return True
        elif os_type == 'darwin':
            # For macOS
            subprocess.run(['softwareupdate', '--install', '--all'], check=True)
            print("Sistema macOS atualizado com sucesso.")
            return True
        else:
            print(f"Atualização não suportada para o sistema: {os_type}")
            return False
    except subprocess.CalledProcessError as e:
        print(f"Erro ao atualizar o sistema: {str(e)}")
        return False
    except Exception as e:
        print(f"Erro inesperado ao atualizar o sistema: {str(e)}")
        return False

# Function to install packages with support for different distributions
def os_install(package):
    os_type = detect_os_distribution()
    print(f"Instalando pacote no sistema: {os_type}")
    
    # Package name mapping for different distributions
    package_names = {
        'build-essential': {
            'debian': 'build-essential',
            'ubuntu': 'build-essential',
            'centos': 'gcc gcc-c++ make',
            'redhat': 'gcc gcc-c++ make',
            'darwin': 'xcode-select'
        },
        'python3-dev': {
            'debian': 'python3-dev',
            'ubuntu': 'python3-dev',
            'centos': 'python3-devel',
            'redhat': 'python3-devel',
            'darwin': 'python3'
        },
        'libssl-dev': {
            'debian': 'libssl-dev',
            'ubuntu': 'libssl-dev',
            'centos': 'openssl-devel',
            'redhat': 'openssl-devel',
            'darwin': 'openssl'
        },
        'zlib1g-dev': {
            'debian': 'zlib1g-dev',
            'ubuntu': 'zlib1g-dev',
            'centos': 'zlib-devel',
            'redhat': 'zlib-devel',
            'darwin': 'zlib'
        },
        'libpcap-dev': {
            'debian': 'libpcap-dev',
            'ubuntu': 'libpcap-dev',
            'centos': 'libpcap-devel',
            'redhat': 'libpcap-devel',
            'darwin': 'libpcap'
        },
        'libpcre2-dev': {
            'debian': 'libpcre2-dev',
            'ubuntu': 'libpcre2-dev',
            'centos': 'pcre2-devel',
            'redhat': 'pcre2-devel',
            'darwin': 'pcre2'
        },
        'libsystemd-dev': {
            'debian': 'libsystemd-dev',
            'ubuntu': 'libsystemd-dev',
            'centos': 'systemd-devel',
           'redhat': 'systemd-devel',
            'darwin': 'systemd'
        }
    }
    
    try:
        if package in package_names:
            if os_type in package_names[package]:
                pkg_name = package_names[package][os_type]
                
                if os_type == 'debian' or os_type == 'ubuntu':
                    subprocess.run(['sudo', 'apt-get', 'install', '-y', pkg_name], check=True)
                elif os_type == 'centos' or os_type == 'redhat':
                    subprocess.run(['sudo', 'yum', 'install', '-y'] + pkg_name.split(), check=True)
                elif os_type == 'darwin':
                    if pkg_name == 'xcode-select':
                        subprocess.run(['xcode-select', '--install'], check=True)
                    else:
                        subprocess.run(['brew', 'install', pkg_name], check=True)
                
                print(f"Pacote {package} ({pkg_name}) instalado com sucesso.")
                return True
            else:
                print(f"Pacote {package} não suportado para o sistema {os_type}")
                return False
        else:
            print(f"Pacote {package} não encontrado no mapeamento de pacotes")
            return False
    except subprocess.CalledProcessError as e:
        print(f"Erro ao instalar o pacote {package}: {str(e)}")
        return False
    except Exception as e:
        print(f"Erro inesperado ao instalar o pacote {package}: {str(e)}")
        return False

# Função para verificar se o OSSEC já está instalado
def verificar_ossec_instalado():
    return os.path.exists('/var/ossec/bin/ossec-agentd')

# Função para verificar se já existe uma chave importada
def verificar_chave_ossec_importada():
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

# Função para importar a chave do OSSEC
def importar_chave_ossec(activation_key):
    import re
    
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

# Função para reiniciar o serviço do OSSEC
def reiniciar_ossec():
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

# Função para configurar o PSAD após a instalação
def configurar_psad():
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
        url = f'http://10.0.10.183:5002/download/{arquivo_config}'
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

def instalar_ossec():
    # Verifica se o OSSEC já está instalado
    if verificar_ossec_instalado():
        print("OSSEC já está instalado. Pulando a instalação.")
        return True
    
    # Baixa o arquivo de configuração
    if not baixar_ossec_conf():
        return False
        
    # Instala dependências necessárias
    os_update()
    os_install('libpcre2-dev')
    os_install('libsystemd-dev')
    os_install('libssl-dev')
    os_install('zlib1g-dev')
    os_install('fwsnort')
    os_install('psad')
    
    # Configura o PSAD após a instalação
    configurar_psad()

    # Baixa o código-fonte do OSSEC
    ossec_url = 'https://github.com/ossec/ossec-hids/archive/refs/tags/3.7.0.tar.gz'
    ossec_tar = 'ossec-hids-3.7.0.tar.gz'
    ossec_dir = 'ossec-hids-3.7.0'

    # Baixa o arquivo tar.gz
    resposta = requests.get(ossec_url)
    if resposta.status_code == 200:
        with open(ossec_tar, 'wb') as file:
            file.write(resposta.content)
        print('Código-fonte do OSSEC baixado com sucesso.')
    else:
        print('Falha ao baixar o código-fonte do OSSEC.')
        return False

    # Baixa o código-fonte do OSSEC
    ossec_tar = 'ossec-hids-3.7.0.tar.gz'
    ossec_dir = 'ossec-hids-3.7.0'

    # Baixa o arquivo tar.gz
    resposta = requests.get(ossec_url)
    if resposta.status_code == 200:
        with open(ossec_tar, 'wb') as file:
            file.write(resposta.content)
        print('Código-fonte do OSSEC baixado com sucesso.')
    else:
        print('Falha ao baixar o código-fonte do OSSEC.')
        return False

    # Extrai o arquivo tar.gz
    subprocess.run(['tar', '-xvzf', ossec_tar], check=True)

    # Move o arquivo de configuração para o diretório do OSSEC
    os.replace('preloaded-vars.conf', f'{ossec_dir}/etc/preloaded-vars.conf')

    # Navega para o diretório do OSSEC e executa a instalação
    os.chdir(ossec_dir)
    subprocess.run(['./install.sh'], check=True)

    # Volta para o diretório anterior
    os.chdir('..')

    # Limpa os arquivos temporários
    os.remove(ossec_tar)
    subprocess.run(['rm', '-rf', ossec_dir], check=True)

    print('OSSEC instalado com sucesso.')
    return True

# Função para verificar se o PSAD está instalado
def verificar_psad_instalado():
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

# Função para verificar se o PSAD está em execução
def verificar_psad_running():
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

# Função para instalar o PSAD
def instalar_psad():
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

# Função para verificar e configurar o PSAD
def verificar_e_configurar_psad():
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

# Função para verificar se o OSSEC está instalado
def verificar_ossec_instalado():
    return os.path.exists('/var/ossec/bin/ossec-agentd')

# Função para verificar se já existe uma chave importada
def verificar_chave_ossec_importada():
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

# Função para importar a chave do OSSEC
def importar_chave_ossec(activation_key):
    import re
    
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

# Função para reiniciar o serviço do OSSEC
def reiniciar_ossec():
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

# Função para configurar o PSAD após a instalação
def configurar_psad():
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
        url = f'http://10.0.10.183:5002/download/{arquivo_config}'
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

def instalar_ossec():
    # Verifica se o OSSEC já está instalado
    if verificar_ossec_instalado():
        print("OSSEC já está instalado. Pulando a instalação.")
        return True
    
    # Baixa o arquivo de configuração
    if not baixar_ossec_conf():
        return False
        
    # Instala dependências necessárias
    os_update()
    os_install('libpcre2-dev')
    os_install('libsystemd-dev')
    os_install('libssl-dev')
    os_install('zlib1g-dev')
    os_install('fwsnort')
    os_install('psad')
    
    # Configura o PSAD após a instalação
    configurar_psad()

    # Baixa o código-fonte do OSSEC
    ossec_url = 'https://github.com/ossec/ossec-hids/archive/refs/tags/3.7.0.tar.gz'
    ossec_tar = 'ossec-hids-3.7.0.tar.gz'
    ossec_dir = 'ossec-hids-3.7.0'

    # Baixa o arquivo tar.gz
    resposta = requests.get(ossec_url)
    if resposta.status_code == 200:
        with open(ossec_tar, 'wb') as file:
            file.write(resposta.content)
        print('Código-fonte do OSSEC baixado com sucesso.')
    else:
        print('Falha ao baixar o código-fonte do OSSEC.')
        return False

    # Baixa o código-fonte do OSSEC
    ossec_tar = 'ossec-hids-3.7.0.tar.gz'
    ossec_dir = 'ossec-hids-3.7.0'

    # Baixa o arquivo tar.gz
    resposta = requests.get(ossec_url)
    if resposta.status_code == 200:
        with open(ossec_tar, 'wb') as file:
            file.write(resposta.content)
        print('Código-fonte do OSSEC baixado com sucesso.')
    else:
        print('Falha ao baixar o código-fonte do OSSEC.')
        return False

    # Extrai o arquivo tar.gz
    subprocess.run(['tar', '-xvzf', ossec_tar], check=True)

    # Move o arquivo de configuração para o diretório do OSSEC
    os.replace('preloaded-vars.conf', f'{ossec_dir}/etc/preloaded-vars.conf')

    # Navega para o diretório do OSSEC e executa a instalação
    os.chdir(ossec_dir)
    subprocess.run(['./install.sh'], check=True)

    # Volta para o diretório anterior
    os.chdir('..')

    # Limpa os arquivos temporários
    os.remove(ossec_tar)
    subprocess.run(['rm', '-rf', ossec_dir], check=True)

    print('OSSEC instalado com sucesso.')
    return True


# Função para codificar dados em base64
def encrypt_base64(data):
    encoded_bytes = base64.b64encode(data.encode('utf-8'))
    encoded_string = encoded_bytes.decode('utf-8')
    return encoded_string

# Função para enviar mensagens ao servidor
def enviar_mensagem(message, endpoint):
    print(message)
    url = f'http://10.0.10.183:5002/{endpoint}'
    resposta = requests.post(url, data=json.dumps(message), headers={'Content-Type': 'application/json'})
    return resposta

# Função para salvar o ID do agente
def salvar_id(id_agente):
    with open('AGENTID', 'w') as file:
        file.write(str(id_agente))

# Função para verificar se o OSSEC está em execução
def verificar_ossec_running():
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

# Função para enviar um ping ao servidor
def ping():
    data = {"chave": chave_ativacao, "id": id_agente}
    resposta = enviar_mensagem(data, 'ping')
    return resposta

# Função para processar a resposta do ping
def acoes_ping(resposta):
    mensagem = resposta.get('mensagem')
    if mensagem == 'Há atividades pendentes na fila.':
        ram['tarefas'] = resposta.get('fila')
        if resposta.get('fila') == 'script':
            ram['script_name'] = resposta.get('script_name')

# Função para tratar a resposta do ping
def res_ping(resposta):
    acoes_ping(resposta)

# Função para verificar a resposta do servidor
def verifica_resposta(resposta):
    if resposta.status_code == 200:
        resposta_json = resposta.json()
        codigo = int(resposta_json.get('codigo'))
        if codigo == codigos['ping']:
            res_ping(resposta_json)
        elif codigo == codigos['ossec-register']:
            registrar_ossec()
    else:
        print('Falha na comunicação. Status Code:', resposta.status_code)

# Função para registrar o agente no OSSEC
def registrar_ossec():
    # Verifica se o OSSEC já está instalado e se já tem uma chave importada
    if verificar_ossec_instalado() and verificar_chave_ossec_importada():
        print("OSSEC já está instalado e com chave importada. Nenhuma ação necessária.")
        return True
    
    # Dados para o registro no OSSEC
    message_ossec = {
        'name': nome,  # Nome do agente (hostname)
        'id': id_agente,  # ID do agente no Guardião
        'chave': chave_ativacao  # Chave de ativação do Guardião
    }

    # Envia a requisição para o endpoint de registro no OSSEC
    resposta = enviar_mensagem(message_ossec, 'registro-ossec')
    
    # Verifica a resposta
    if resposta.status_code == 200:
        dados_resposta = resposta.json()
        if dados_resposta.get('status') == 'sucesso':
            activation_key = dados_resposta.get('activation_key')
            ossec_server = dados_resposta.get('ossec_server')
            print(f'Registro no OSSEC bem-sucedido!')
            print(f'Chave de ativação do OSSEC: {activation_key}')
            print(f'Servidor OSSEC: {ossec_server}')
            
            # Verifica se o OSSEC já está instalado
            if verificar_ossec_instalado():
                print("OSSEC já está instalado.")
                # Verifica se já tem uma chave importada
                if verificar_chave_ossec_importada():
                    print("Chave do OSSEC já importada. Nenhuma ação necessária.")
                    return True
                else:
                    print("Importando chave...")
                    return importar_chave_ossec(activation_key)
            else:
                # Instala o OSSEC se não estiver instalado
                if instalar_ossec():
                    print('OSSEC instalado com sucesso!')
                    # Após a instalação, importa a chave
                    return importar_chave_ossec(activation_key)
                else:
                    print('Falha na instalação do OSSEC.')
                    return False
        else:
            print('Falha no registro no OSSEC:', dados_resposta.get('mensagem'))
            return False
    else:
        print('Erro na comunicação com o servidor:', resposta.status_code)

# Função para executar tarefas
def executar(tarefa):
    if tarefa == 'softwares':
        softwares()
    elif tarefa == 'infos':
        infos()
    elif tarefa == 'vuln-scan':
        vuln_scan()
    elif tarefa == 'script':
        executar_script()

# Função para coletar informações de software no macOS
def softwares_mac():
    output = subprocess.check_output(['system_profiler', 'SPApplicationsDataType']).decode()
    sections = output.strip().split("\n\n")
    software_list = []
    for section in sections:
        lines = section.strip().split("\n")
        software = {}
        for i in range(len(lines)):
            line = lines[i].strip()
            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip()
                if value == "":
                    software['Name'] = key
                    nextsection = sections[sections.index(section) + 1]
                    lines2 = nextsection.strip().split("\n")
                    if "Version" in lines2[0]:
                        for i in range(len(lines2)):
                            line2 = lines2[i].strip()
                            if ":" in line2:
                                key2, value2 = line2.split(":", 1)
                                key2 = key2.strip()
                                value2 = value2.strip()
                            software[key2] = value2
        if software:
            software_list.append(software)

    with open('softwares.json', 'w') as file:
        json.dump(software_list, file, indent=4)

    enviar_softwares()

# Função para coletar informações de software no Debian/Ubuntu
def softwares_deb():
    try:
        output = subprocess.check_output(['dpkg', '-l']).decode()
        lines = output.strip().split("\n")
        
        # Find the header line to determine where the package list starts
        header_index = 0
        for i, line in enumerate(lines):
            if line.startswith("+++") or line.startswith("ii"):
                header_index = i
                break
        
        # Skip header lines
        package_lines = lines[header_index:]
        
        software_list = []
        for line in package_lines:
            if not line.strip():
                continue
                
            parts = line.split(None, 4)  # Split by whitespace, max 5 parts
            
            # Check if we have enough parts
            if len(parts) >= 4:
                software = {
                    'Name': parts[1],
                    'Version': parts[2],
                    'Description': parts[3] if len(parts) == 4 else parts[4]
                }
                software_list.append(software)
        
        with open('softwares.json', 'w') as file:
            json.dump(software_list, file, indent=4)
        
        print(f"Informações sobre {len(software_list)} softwares foram armazenadas no arquivo 'softwares.json'.")
        enviar_softwares()
    except Exception as e:
        print(f"Erro ao coletar informações de software: {str(e)}")
        # Create an empty software list to avoid further errors
        with open('softwares.json', 'w') as file:
            json.dump([], file)
        enviar_softwares()

# Função para coletar informações de software
def softwares():
    print(platform.platform())
    try:
        if 'macOS' in platform.platform():
            print('MacOSX detectado!')
            softwares_mac()
        elif 'ubuntu' in platform.platform().lower() or 'debian' in platform.platform().lower():
            print('Debian/Ubuntu detectado!')
            softwares_deb()
        else:
            # Fallback for other systems
            print(f'Sistema {platform.platform()} detectado, usando método genérico')
            with open('softwares.json', 'w') as file:
                json.dump([], file)
            enviar_softwares()
    except Exception as e:
        print(f"Erro na função softwares: {str(e)}")
        # Create an empty software list to avoid further errors
        with open('softwares.json', 'w') as file:
            json.dump([], file)
        enviar_softwares()

# Função para enviar informações de software
def enviar_softwares():
    with open('softwares.json', 'r') as file:
        software_data = file.read()
    mensagem = {'tipo': 'softwares', 'chave': chave_ativacao, 'id': id_agente, 'payload': encrypt_base64(software_data)}
    enviar_mensagem(mensagem, 'envios')
    print('softwares.json enviado!')

# Função para coletar informações do sistema
def infos():
    info = coletar_info()

    with open('info.json', 'w') as f:
        json.dump(info, f, indent=4)
    enviar_infos()

# Função para coletar informações do sistema
def coletar_info():
    hostname = socket.gethostname()
    ip_externo = requests.get('http://httpbin.org/ip').json()['origin']
    os_info = platform.platform()
    addrs = psutil.net_if_addrs()
    ip_info = {iface: [addr.address for addr in addrs_info if addr.family == socket.AF_INET] for iface, addrs_info in addrs.items()}
    all_users = [user.pw_name for user in pwd.getpwall() if not user.pw_name.startswith('_')]
    ram_info = psutil.virtual_memory()._asdict()
    manufacturer = platform.uname().node
    model = platform.uname().machine
    disk_info = psutil.disk_usage('/')._asdict()
    cpu_info = {
        'name': platform.processor(),
        'version': platform.uname().release,
        'cores': psutil.cpu_count(logical=False),
        'threads': psutil.cpu_count(logical=True)
    }

    return {
        'chave': chave_ativacao,
        'id_agente': id_agente,
        'hostname': hostname,
        'ip_externo': ip_externo,
        'os_info': os_info,
        'ip_info': ip_info,
        'all_users': all_users,
        'ram_info': ram_info,
        'manufacturer': manufacturer,
        'model': model,
        'disk_info': disk_info,
        'cpu_info': cpu_info,
    }

# Função para enviar informações do sistema
def enviar_infos():
    with open('info.json', 'r') as file:
        info_data = file.read()
    mensagem = {'tipo': 'infos', 'chave': chave_ativacao, 'id': id_agente, 'payload': encrypt_base64(info_data)}
    enviar_mensagem(mensagem, 'envios')
    print('info.json enviado!')

# Função para verificar se o Trivy está instalado
def verificar_trivy_instalado():
    try:
        if platform.system().lower() == 'windows':
            subprocess.run(['where', 'trivy'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            subprocess.run(['which', 'trivy'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        return False

# Função para verificar se o sudo está disponível
def verificar_sudo_disponivel():
    try:
        subprocess.run(['sudo', '--version'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

# Função para baixar e instalar o Trivy
def baixar_e_instalar_trivy():
    sistema_operacional = platform.system().lower()
    arquitetura = platform.machine().lower()

    if sistema_operacional == 'linux':
        # Determine architecture
        if 'aarch64' in arquitetura:
            arch_prefix = 'arm64'
        elif 'arm' in arquitetura:
            arch_prefix = 'arm'
        elif 'x86_64' in arquitetura or 'amd64' in arquitetura:
            arch_prefix = '64'
        else:
            arch_prefix = '32'
        
        # Determine package format
        if os.path.exists('/usr/bin/dpkg'):
            pkg_ext = 'deb'
        else:
            pkg_ext = 'rpm'
        
        binario = f'trivy-{arch_prefix}.{pkg_ext}'
    elif sistema_operacional == 'darwin':
        binario = 'trivy-macos'
    elif sistema_operacional == 'windows':
        binario = 'trivy-windows.exe'
    else:
        print(f"Sistema operacional {sistema_operacional} não suportado.")
        return

    url = f'http://10.0.10.183:5002/download/{binario}'
    resposta = requests.get(url)
    if resposta.status_code == 200:
        with open(binario, 'wb') as file:
            file.write(resposta.content)
        print(f'Binário {binario} baixado com sucesso.')

        # Verificar se o usuário é root ou se o sudo está disponível
        usar_sudo = False
        if os.geteuid() != 0 and verificar_sudo_disponivel():
            usar_sudo = True

        # Instalar o binário
        if sistema_operacional == 'linux':
            if binario.endswith('.deb'):
                comando = ['dpkg', '-i', binario]
            elif binario.endswith('.rpm'):
                comando = ['rpm', '-i', binario]
            
            if usar_sudo:
                comando.insert(0, 'sudo')
            
            try:
                subprocess.run(comando, check=True)
                print(f'Trivy instalado com sucesso via {binario}.')
            except subprocess.CalledProcessError as e:
                print(f'Erro ao instalar Trivy: {str(e)}')
                return False
        elif sistema_operacional == 'darwin':
            # Para macOS, mover para /usr/local/bin
            destino = '/usr/local/bin/trivy'
            comando = ['mv', binario, destino]
            if usar_sudo:
                comando.insert(0, 'sudo')
            
            try:
                subprocess.run(comando, check=True)
                subprocess.run(['chmod', '+x', destino], check=True)
                print('Trivy instalado com sucesso no macOS.')
            except subprocess.CalledProcessError as e:
                print(f'Erro ao instalar Trivy no macOS: {str(e)}')
                return False
        elif sistema_operacional == 'windows':
            # Mover o binário para um diretório no PATH
            try:
                destino = os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'Trivy')
                if not os.path.exists(destino):
                    os.makedirs(destino)
                os.rename(binario, os.path.join(destino, 'trivy.exe'))
                
                # Adicionar ao PATH se não estiver
                path_env = os.environ.get('PATH', '')
                if destino not in path_env:
                    # Apenas informativo, pois não podemos modificar o PATH do sistema aqui
                    print(f'Trivy instalado em {destino}. Considere adicionar este diretório ao PATH.')
                print('Trivy instalado com sucesso no Windows.')
            except Exception as e:
                print(f'Erro ao instalar Trivy no Windows: {str(e)}')
                return False

        # Limpar o arquivo baixado
        try:
            os.remove(binario)
        except:
            pass
            
        return True
    else:
        print(f'Falha ao baixar o binário {binario}. Status Code: {resposta.status_code}')
        return False

# Função para executar um scan de vulnerabilidades
def vuln_scan():
    if not verificar_trivy_instalado():
        baixar_e_instalar_trivy()
    
    # Modificado para usar --scanners vuln para scan mais rápido
    comando = ['trivy', 'fs', '--scanners', 'vuln', '--format', 'json', '-o', 'vuln-scan.json', '/']
    subprocess.run(comando, check=True)
    
    with open('vuln-scan.json', 'r') as file:
        vuln_data = file.read()
    
    mensagem = {'tipo': 'vuln-scan', 'chave': chave_ativacao, 'id': id_agente, 'payload': encrypt_base64(vuln_data)}
    enviar_mensagem(mensagem, 'envios')
    print('vuln-scan.json enviado!')

# Função para baixar um script
def baixar_script(script_name):
    url = f'http://10.0.10.183:5002/download/script/{id_agente}/{script_name}'
    resposta = requests.get(url)
    if resposta.status_code == 200:
        # Criar diretório scripts se não existir
        if not os.path.exists('scripts'):
            os.makedirs('scripts')
        
        script_path = os.path.join('scripts', script_name)
        with open(script_path, 'wb') as file:
            file.write(resposta.content)
        
        # Tornar o script executável em sistemas Unix-like
        if platform.system() != 'Windows':
            os.chmod(script_path, 0o755)
        
        return script_path
    else:
        print(f'Falha ao baixar o script {script_name}. Status Code:', resposta.status_code)
        return None

# Função para executar um script
def executar_script():
    try:
        script_name = ram.get('script_name')
        if not script_name:
            print("Nome do script não encontrado na RAM")
            return
        
        print(f"Baixando script: {script_name}")
        script_path = baixar_script(script_name)
        
        if script_path:
            print(f"Executando script: {script_path}")
            
            # Determinar o comando de execução baseado na extensão do arquivo
            if script_name.endswith('.sh'):
                comando = ['bash', script_path]
            elif script_name.endswith('.py'):
                comando = ['python3', script_path]
            else:
                print(f"Extensão de arquivo não suportada para: {script_name}")
                return
            
            # Executar o script e capturar a saída
            resultado = subprocess.run(comando, capture_output=True, text=True)
            
            # Preparar a mensagem de resposta
            mensagem = {
                'tipo': 'script-resultado',
                'chave': chave_ativacao,
                'id': id_agente,
                'script_name': script_name,
                'payload': encrypt_base64(json.dumps({
                    'stdout': resultado.stdout,
                    'stderr': resultado.stderr,
                    'returncode': resultado.returncode
                }))
            }
            
            # Enviar resultado
            enviar_mensagem(mensagem, 'envios')
            print(f'Resultado do script {script_name} enviado!')
            
            # Limpar o script da RAM
            ram['script_name'] = None
            
            # Remover o script após a execução
            os.remove(script_path)
            
        else:
            print("Falha ao baixar o script")
            
    except Exception as e:
        print(f"Erro ao executar script: {str(e)}")
        mensagem = {
            'tipo': 'script-erro',
            'chave': chave_ativacao,
            'id': id_agente,
            'script_name': script_name,
            'payload': encrypt_base64(json.dumps({
                'erro': str(e)
            }))
        }
        enviar_mensagem(mensagem, 'envios')

# Função para executar tarefas pendentes
def executor():
    try:
        tarefa = ram['tarefas']
        if tarefa == 'ossec-register':
            registrar_ossec()
        else:
            executar(tarefa)
        ram['tarefas'] = None
    except Exception as e:
        print(e)

# Função de ativação do agente
def ativacao():
    global id_agente, chave_ativacao
    message_registro = {'chave': chave_ativacao, 'host': nome}
    if os.path.exists('AGENTID'):
        with open('AGENTID', 'r') as file:
            id_agente = file.read().strip()
            print(f'Agente já ativado com ID: %s' % id_agente)
    else:
        resposta = enviar_mensagem(message_registro, 'registro')
        verifica_resposta(resposta)
        if resposta.status_code == 200:
            print('Registro bem-sucedido!')
            print('Resposta:', resposta.json())
            id_agente = resposta.json().get('id_agente')
            salvar_id(id_agente)
        else:
            print('Registro falhou. Status Code:', resposta.status_code)
            print('Resposta:', resposta.json())
            exit()
    
    # Verifica e configura o PSAD
    verificar_e_configurar_psad()
    
    # Verifica se o OSSEC está instalado
    if verificar_ossec_instalado():
        # Verifica se o arquivo client.keys existe e não está vazio
        if not verificar_chave_ossec_importada():
            print("Arquivo client.keys não existe ou está vazio. Iniciando registro no OSSEC...")
            registrar_ossec()
        # Verifica se o OSSEC está em execução
        elif not verificar_ossec_running():
            print("OSSEC não está em execução. Reiniciando...")
            reiniciar_ossec()
    else:
        print("OSSEC não está instalado. Instalando...")
        instalar_ossec()
        registrar_ossec()

# Inicia a ativação do agente
ativacao()

# Loop principal
while True:
    resposta = ping()
    print(resposta.json())
    verifica_resposta(resposta)
    executor()
    sleep(1)