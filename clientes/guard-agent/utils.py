import json
import subprocess
import platform
import psutil
import os
import socket
import uuid
import requests
from network import enviar_mensagem, enviar_softwares, enviar_vulns

def verificar_sudo_disponivel():
    """Check if sudo is available"""
    try:
        subprocess.run(['sudo', '-n', 'true'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except (subprocess.SubprocessError, FileNotFoundError):
        return False

def collect_softwares():
    """Collect software information based on platform"""
    print(platform.platform())
    try:
        if 'macOS' in platform.platform():
            print('MacOSX detectado!')
            softwares_mac()
            return []  # Return empty list as the file is already saved
        elif 'ubuntu' in platform.platform().lower() or 'debian' in platform.platform().lower():
            print('Debian/Ubuntu detectado!')
            softwares_deb()
            return []  # Return empty list as the file is already saved
        else:
            # Fallback for other systems
            print(f'Sistema {platform.platform()} detectado, usando método genérico')
            with open('softwares.json', 'w') as file:
                json.dump([], file)
            return []
    except Exception as e:
        print(f"Erro na função softwares: {str(e)}")
        # Create an empty software list to avoid further errors
        with open('softwares.json', 'w') as file:
            json.dump([], file)
        return []

def softwares_mac():
    """Collect software information on macOS"""
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
                    if sections.index(section) + 1 < len(sections):
                        nextsection = sections[sections.index(section) + 1]
                        lines2 = nextsection.strip().split("\n")
                        if lines2 and "Version" in lines2[0]:
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

def softwares_deb():
    """Collect software information on Debian/Ubuntu"""
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
    except Exception as e:
        print(f"Erro ao coletar informações de software: {str(e)}")
        # Create an empty software list to avoid further errors
        with open('softwares.json', 'w') as file:
            json.dump([], file)
        return []

def collect_system_info():
    """Collect system information"""
    try:
        hostname = socket.gethostname()
        
        # Get external IP (with error handling)
        try:
            ip_externo = requests.get('http://httpbin.org/ip', timeout=5).json()['origin']
        except:
            ip_externo = "Unknown"
            
        os_info = platform.platform()
        
        # Make sure we have the platform key that's expected in registration
        platform_system = platform.system()
        
        addrs = psutil.net_if_addrs()
        ip_info = {iface: [addr.address for addr in addrs_info if addr.family == socket.AF_INET] 
                  for iface, addrs_info in addrs.items()}
        
        # Get all users (with platform-specific handling)
        all_users = []
        if platform_system != 'Windows':
            try:
                import pwd
                all_users = [user.pw_name for user in pwd.getpwall() if not user.pw_name.startswith('_')]
            except:
                all_users = ["Unable to retrieve users"]
        else:
            all_users = ["Windows user list not implemented"]
            
        ram_info = psutil.virtual_memory()._asdict()
        manufacturer = platform.uname().node
        model = platform.uname().machine
        
        # Get disk info with error handling
        try:
            disk_info = psutil.disk_usage('/')._asdict()
        except:
            disk_info = {"total": 0, "used": 0, "free": 0, "percent": 0}
            
        cpu_info = {
            'name': platform.processor(),
            'version': platform.uname().release,
            'cores': psutil.cpu_count(logical=False),
            'threads': psutil.cpu_count(logical=True)
        }

        return {
            'hostname': hostname,
            'ip_externo': ip_externo,
            'os_info': os_info,
            'platform': platform_system,  # Add the platform key explicitly
            'platform_release': platform.release(),
            'platform_version': platform.version(),
            'ip_info': ip_info,
            'all_users': all_users,
            'ram_info': ram_info,
            'manufacturer': manufacturer,
            'model': model,
            'disk_info': disk_info,
            'cpu_info': cpu_info,
            'ip_address': socket.gethostbyname(socket.gethostname()),
            'mac_address': ':'.join(("%012x" % uuid.getnode())[i:i+2] for i in range(0, 12, 2))
        }
    except Exception as e:
        log_exception(f"Error collecting system info: {str(e)}")
        # Return minimal info with required fields to avoid breaking registration
        return {
            'hostname': socket.gethostname(),
            'platform': platform.system(),
            'platform_version': platform.version(),
            'platform_release': platform.release(),
            'ip_address': socket.gethostbyname(socket.gethostname()),
            'mac_address': ':'.join(("%012x" % uuid.getnode())[i:i+2] for i in range(0, 12, 2)),
            'error': str(e)
        }

def execute_script(script_name, script_content):
    """Execute a script received from the server"""
    try:
        # Save the script to a file
        with open(script_name, 'w') as file:
            file.write(script_content)
        
        # Make the script executable
        os.chmod(script_name, 0o755)
        
        # Execute the script
        result = subprocess.run([f'./{script_name}'], capture_output=True, text=True, shell=True)
        
        # Return the result
        return {
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode
        }
    except Exception as e:
        return {
            'stdout': '',
            'stderr': str(e),
            'returncode': -1
        }

def verificar_trivy_instalado():
    """Check if Trivy is installed"""
    try:
        if platform.system().lower() == 'windows':
            subprocess.run(['where', 'trivy'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            subprocess.run(['which', 'trivy'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        return False

def baixar_e_instalar_trivy():
    """Download and install Trivy based on system architecture"""
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
        return False

    from config import SERVER_URL
    url = f'{SERVER_URL}/download/{binario}'
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

def vuln_scan():
    """Run vulnerability scan using Trivy"""
    if not verificar_trivy_instalado():
        print("Trivy não está instalado. Instalando...")
        if not baixar_e_instalar_trivy():
            print("Falha ao instalar Trivy. Usando scan básico.")
            # Fallback to basic scan
            scan_result = {
                'status': 'basic_scan',
                'open_ports': []
            }
            
            # Check for open ports
            for port in [22, 80, 443, 3306, 5432]:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.5)
                    result = s.connect_ex(('127.0.0.1', port))
                    if result == 0:
                        scan_result['open_ports'].append(port)
                    s.close()
                except:
                    pass
            
            return scan_result
    
    # Use Trivy for vulnerability scanning with --scanners vuln for faster scan
    try:
        # Create a temporary file for the scan results
        output_file = 'vuln-scan.json'
        
        # Run Trivy scan with limited scope for faster results
        comando = ['trivy', 'fs', '--scanners', 'vuln', '--format', 'json', '-o', output_file, '/']
        subprocess.run(comando, check=True)
        
        # Read the scan results
        with open(output_file, 'r') as file:
            vuln_data = json.load(file)
        
        # Clean up
        try:
            os.remove(output_file)
        except:
            pass
            
        # Enviar os resultados para o servidor
        enviar_vulns(os.environ.get('AGENT_ID'), vuln_data)
            
        return vuln_data
    except Exception as e:
        print(f"Erro ao executar scan com Trivy: {str(e)}")
        return None

def baixar_script(script_name, id_agente, server_url):
    """Download script from server"""
    url = f'{server_url}/download/script/{id_agente}/{script_name}'
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
