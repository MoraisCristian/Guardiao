import json
import requests
import base64
from config import chave_ativacao, codigos, SERVER_URL
from logger import log_info, log_warning, log_error, log_debug, log_exception

def encrypt_base64(data):
    """Encode data in base64"""
    try:
        encoded_bytes = base64.b64encode(data.encode('utf-8'))
        encoded_string = encoded_bytes.decode('utf-8')
        return encoded_string
    except Exception as e:
        log_exception(f"Erro ao codificar dados em base64")
        raise

def enviar_mensagem(data, tipo):
    """Send message to server with improved logging"""
    try:
        from config import SERVER_URL, codigos
        from logger import log_info, log_error, log_debug
        
        # Determinar URL com base no tipo de mensagem
        if tipo == 'registro':
            url = f"{SERVER_URL}/api/registro"
        elif tipo == 'ping':
            url = f"{SERVER_URL}/api/ping"
        elif tipo == 'softwares':
            url = f"{SERVER_URL}/api/softwares"
        elif tipo == 'infos':
            url = f"{SERVER_URL}/api/infos"
        elif tipo == 'registro-ossec':
            url = f"{SERVER_URL}/api/registro-ossec"
        else:
            url = f"{SERVER_URL}/api/{tipo}"
        
        # Registrar detalhes da requisição
        log_info(f"Enviando requisição para: {url}")
        log_info(f"Dados da requisição: {json.dumps(data)}")
        
        # Enviar requisição
        headers = {'Content-Type': 'application/json'}
        response = requests.post(url, json=data, headers=headers)
        
        # Registrar detalhes da resposta
        log_info(f"Resposta recebida: Status={response.status_code}")
        try:
            resp_data = response.json()
            log_info(f"Conteúdo da resposta: {json.dumps(resp_data)}")
        except:
            log_info(f"Conteúdo da resposta (texto): {response.text[:200]}")
        
        return response
    except Exception as e:
        log_error(f"Erro ao enviar mensagem: {str(e)}")
        raise

def enviar_mensagem(message, endpoint):
    """Send message to server"""
    url = f'{SERVER_URL}/{endpoint}'
    log_debug(f"Enviando mensagem para {url}")
    log_debug(f"Conteúdo da mensagem: {json.dumps(message)}")
    
    try:
        resposta = requests.post(url, data=json.dumps(message), headers={'Content-Type': 'application/json'})
        log_debug(f"Resposta recebida: Status {resposta.status_code}")
        
        # Log response content
        try:
            response_content = resposta.json() if resposta.text else {}
            log_debug(f"Conteúdo da resposta: {json.dumps(response_content)}")
        except json.JSONDecodeError:
            log_warning(f"Resposta não é um JSON válido: {resposta.text}")
            # Generate and log curl command for debugging
            curl_cmd = f"curl -X POST '{url}' -H 'Content-Type: application/json' -d '{json.dumps(message)}'"
            log_warning(f"Comando curl para troubleshooting: {curl_cmd}")
        
        return resposta
    except requests.RequestException as e:
        log_error(f"Erro na requisição HTTP para {url}: {str(e)}")
        raise
    except Exception as e:
        log_exception(f"Erro inesperado ao enviar mensagem para {url}")
        raise

def salvar_id(id_agente):
    """Save agent ID to file"""
    try:
        if id_agente is None:
            log_error("Tentativa de salvar ID None. Operação abortada.")
            raise ValueError("ID do agente não pode ser None")
            
        with open('AGENTID', 'w') as file:
            file.write(str(id_agente))
        log_info(f"ID do agente {id_agente} salvo com sucesso")
    except Exception as e:
        log_exception(f"Erro ao salvar ID do agente: {str(e)}")
        raise

def carregar_id():
    """Load agent ID from file"""
    try:
        with open('AGENTID', 'r') as file:
            id_agente = file.read().strip()
            log_debug(f"ID do agente carregado: {id_agente}")
            return id_agente
    except FileNotFoundError:
        log_warning("Arquivo AGENTID não encontrado")
        return None
    except Exception as e:
        log_exception(f"Erro ao carregar ID do agente")
        return None

def ping(id_agente):
    """Send ping to server"""
    data = {"chave": chave_ativacao, "id": id_agente}
    try:
        resposta = enviar_mensagem(data, 'ping')
        return resposta
    except Exception as e:
        log_error(f"Erro ao enviar ping: {str(e)}")
        # Create a mock response to avoid crashing the main loop
        class MockResponse:
            def __init__(self):
                self.status_code = 500
                self.text = str(e)
            def json(self):
                return {"codigo": -1, "mensagem": "Erro de conexão"}
        return MockResponse()

def res_ping(resposta, ram):
    """Handle ping response"""
    acoes_ping(resposta, ram)

def acoes_ping(resposta, ram):
    """Process ping response"""
    mensagem = resposta.get('mensagem')
    if mensagem == 'Há atividades pendentes na fila.':
        ram['tarefas'] = resposta.get('fila')
        if resposta.get('fila') == 'script':
            ram['script_name'] = resposta.get('script_name')
            ram['script_content'] = resposta.get('script_content')
        elif resposta.get('fila') == 'ossec-register':
            # Store any additional OSSEC registration data if needed
            if 'ossec_server' in resposta:
                ram['ossec_server'] = resposta.get('ossec_server')
            if 'activation_key' in resposta:
                ram['activation_key'] = resposta.get('activation_key')

def enviar_softwares(id_agente):
    """Send software information to server"""
    try:
        with open('softwares.json', 'r') as file:
            software_data = file.read()
        
        # Encrypt the data using base64
        encrypted_data = encrypt_base64(software_data)
        
        # Prepare data in the same format as agentenovo.py
        mensagem = {
            'tipo': 'softwares', 
            'chave': chave_ativacao, 
            'id': id_agente, 
            'payload': encrypted_data
        }
        
        # Send to 'envios' endpoint like in agentenovo.py
        resposta = enviar_mensagem(mensagem, 'envios')
        
        if resposta.status_code == 200:
            log_info("Informações de software enviadas com sucesso.")
            return True
        else:
            log_error(f"Falha ao enviar informações de software. Status Code: {resposta.status_code}")
            return False
    except Exception as e:
        log_exception(f"Erro ao enviar informações de software")
        return False

def enviar_infos(id_agente, info_data):
    """Send system information to server"""
    try:
        # Add the authentication fields to the info_data
        info_data['chave'] = chave_ativacao
        info_data['id_agente'] = id_agente
        
        # Convert info_data to JSON string
        info_json = json.dumps(info_data)
        
        # Encrypt the data using base64
        encrypted_data = encrypt_base64(info_json)
        
        # Prepare data for sending - match exactly the structure from agentenovo.py
        data = {
            'tipo': 'infos', 
            'chave': chave_ativacao,
            'id': id_agente,
            'payload': encrypted_data
        }
        
        # Log what we're sending for debugging
        log_debug(f"Enviando informações do sistema para endpoint 'envios'")
        
        # Send data to server using the 'envios' endpoint
        resposta = enviar_mensagem(data, 'envios')
        
        if resposta.status_code == 200:
            log_info("Informações do sistema enviadas com sucesso.")
            return True
        else:
            log_error(f"Falha ao enviar informações do sistema. Status Code: {resposta.status_code}, Resposta: {resposta.text}")
            return False
    except Exception as e:
        log_exception(f"Erro ao enviar informações do sistema: {str(e)}")
        return False