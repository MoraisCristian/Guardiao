import subprocess, requests, platform, socket, base64, psutil, time, json, pwd, os
from time import sleep

# Variáveis globais
ram = {}
nome = socket.gethostname()
chave_ativacao = 'KOAUBDFDOEOER1EQLKZQQQ5COTTQFLO1ZI1TYHDZVPLDEDA0'
codigos = {'registro': 1, 'ping': 2, 'upload': 3, 'ossec-register': 4}

# Função para codificar dados em base64
def encrypt_base64(data):
    encoded_bytes = base64.b64encode(data.encode('utf-8'))
    encoded_string = encoded_bytes.decode('utf-8')
    return encoded_string

# Função para enviar mensagens ao servidor
def enviar_mensagem(message, endpoint):
    url = f'http://10.0.10.183:5002/{endpoint}'
    resposta = requests.post(url, data=json.dumps(message), headers={'Content-Type': 'application/json'})
    return resposta

# Função para salvar o ID do agente
def salvar_id(id_agente):
    with open('AGENTID', 'w') as file:
        file.write(str(id_agente))

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
        else:
            print('Falha no registro no OSSEC:', dados_resposta.get('mensagem'))
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
    output = subprocess.check_output(['dpkg', '-l']).decode()
    lines = output.strip().split("\n")[5:]
    software_list = []
    for line in lines:
        software = {}
        fields = line.split()
        software['Name'] = fields[1]
        software['Version'] = fields[2]
        software['Description'] = ' '.join(fields[4:])
        software_list.append(software)

    with open('softwares.json', 'w') as file:
        json.dump(software_list, file, indent=4)

    print("Informações sobre o software foram armazenadas no arquivo 'softwares.json'.")
    enviar_softwares()

# Função para coletar informações de software
def softwares():
    print(platform.platform())
    if 'macOS' in platform.platform():
        print('MacOSX detectado!')
        softwares_mac()
    elif 'ubuntu' or 'debian' in platform.platform():
        print('Debian/Ubuntu detectado!')
        softwares_deb()

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

# Função para enviar informações de software
def enviar_softwares():
    with open('softwares.json', 'r') as file:
        software_data = file.read()
    mensagem = {'tipo': 'softwares', 'chave': chave_ativacao, 'id': id_agente, 'payload': encrypt_base64(software_data)}
    enviar_mensagem(mensagem, 'envios')
    print('softwares.json enviado!')

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
        if 'arm' in arquitetura or 'aarch64' in arquitetura:
            if os.path.exists('/usr/bin/dpkg'):
                binario = 'trivy-arm.deb'
            else:
                binario = 'trivy-arm.rpm'
        elif '64' in arquitetura:
            if os.path.exists('/usr/bin/dpkg'):
                binario = 'trivy-64.deb'
            else:
                binario = 'trivy-64.rpm'
        elif '32' in arquitetura:
            if os.path.exists('/usr/bin/dpkg'):
                binario = 'trivy-32.deb'
            else:
                binario = 'trivy-32.rpm'
    elif sistema_operacional == 'windows':
        binario = 'trivy.exe'
    else:
        print("Sistema operacional não suportado.")
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
            subprocess.run(comando, check=True)
        elif sistema_operacional == 'windows':
            # Mover o binário para um diretório no PATH (por exemplo, C:\Windows\System32)
            os.rename(binario, os.path.join(os.environ['SystemRoot'], 'System32', 'trivy.exe'))

        print(f'Trivy instalado com sucesso.')
    else:
        print(f'Falha ao baixar o binário {binario}. Status Code:', resposta.status_code)

# Função para executar um scan de vulnerabilidades
def vuln_scan():
    if not verificar_trivy_instalado():
        baixar_e_instalar_trivy()
    
    comando = ['trivy', 'fs', '--format', 'json', '-o', 'vuln-scan.json', '/']
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

# Inicia a ativação do agente
ativacao()

# Loop principal
while True:
    resposta = ping()
    print(resposta.json())
    verifica_resposta(resposta)
    executor()
    time.sleep(1)