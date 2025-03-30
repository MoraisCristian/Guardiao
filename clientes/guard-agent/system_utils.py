import os
import platform
import subprocess

def detect_os_distribution():
    """Detect the operating system distribution"""
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

def os_update():
    """Update the operating system"""
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

def os_install(package):
    """Install packages with support for different distributions"""
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
        },
        'libevent-dev': {
            'debian': 'libevent-dev',
            'ubuntu': 'libevent-dev',
            'centos': 'libevent-devel',
           'redhat': 'libevent-devel',
            'darwin': 'libevent'
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

def verificar_sudo_disponivel():
    """Check if sudo is available"""
    try:
        subprocess.run(['sudo', '-n', 'true'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except (subprocess.SubprocessError, FileNotFoundError):
        return False