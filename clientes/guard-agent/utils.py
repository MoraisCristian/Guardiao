import json
import subprocess
import platform
import psutil
import os
import socket
import uuid
import requests
from network import enviar_mensagem, enviar_softwares

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
            return softwares_mac()
        elif 'ubuntu' in platform.platform().lower() or 'debian' in platform.platform().lower():
            print('Debian/Ubuntu detectado!')
            return softwares_deb()
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
    
    return software_list

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
        return software_list
    except Exception as e:
        print(f"Erro ao coletar informações de software: {str(e)}")
        # Create an empty software list to avoid further errors
        with open('softwares.json', 'w') as file:
            json.dump([], file)
        return []

def collect_system_info():
    """Collect system information"""
    info = {
        'hostname': platform.node(),
        'platform': platform.system(),
        'platform_release': platform.release(),
        'platform_version': platform.version(),
        'architecture': platform.machine(),
        'processor': platform.processor(),
        'ram': str(round(psutil.virtual_memory().total / (1024.0 **3)))+" GB",
        'ip_address': socket.gethostbyname(socket.gethostname()),
        'mac_address': ':'.join(("%012x" % uuid.getnode())[i:i+2] for i in range(0, 12, 2))
    }
    
    return info

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

def vuln_scan():
    """Run vulnerability scan"""
    try:
        # Check if OpenVAS/GVM is installed
        if os.path.exists('/usr/bin/gvm-cli') or os.path.exists('/usr/local/bin/gvm-cli'):
            # Run OpenVAS scan
            result = subprocess.run(['gvm-cli', 'socket', '--xml', '<get_tasks/>'], 
                                   capture_output=True, text=True)
            return result.stdout
        else:
            # Fallback to a basic scan
            print("OpenVAS not found, running basic scan...")
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
            
            return json.dumps(scan_result)
    except Exception as e:
        print(f"Error during vulnerability scan: {str(e)}")
        return json.dumps({'status': 'error', 'message': str(e)})


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