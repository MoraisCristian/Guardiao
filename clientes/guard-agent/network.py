import json
import requests
import base64
from config import chave_ativacao, codigos

# Server URL
SERVER_URL = 'http://10.0.10.183:5002'

def encrypt_base64(data):
    """Encode data in base64"""
    encoded_bytes = base64.b64encode(data.encode('utf-8'))
    encoded_string = encoded_bytes.decode('utf-8')
    return encoded_string

def enviar_mensagem(message, endpoint):
    """Send message to server"""
    url = f'{SERVER_URL}/{endpoint}'
    resposta = requests.post(url, data=json.dumps(message), headers={'Content-Type': 'application/json'})
    return resposta

def salvar_id(id_agente):
    """Save agent ID to file"""
    with open('AGENTID', 'w') as file:
        file.write(str(id_agente))

def carregar_id():
    """Load agent ID from file"""
    try:
        with open('AGENTID', 'r') as file:
            return file.read().strip()
    except FileNotFoundError:
        return None

def ping(id_agente):
    """Send ping to server"""
    data = {"chave": chave_ativacao, "id": id_agente}
    resposta = enviar_mensagem(data, 'ping')
    return resposta

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

def enviar_softwares(id_agente):
    """Send software information to server"""
    try:
        with open('softwares.json', 'r') as file:
            softwares_data = json.load(file)
        
        # Prepare data for sending
        data = {
            "chave": chave_ativacao,
            "id": id_agente,
            "softwares": softwares_data
        }
        
        # Send data to server
        resposta = enviar_mensagem(data, 'softwares')
        
        if resposta.status_code == 200:
            print("Informações de software enviadas com sucesso.")
            return True
        else:
            print(f"Falha ao enviar informações de software. Status Code: {resposta.status_code}")
            return False
    except Exception as e:
        print(f"Erro ao enviar informações de software: {str(e)}")
        return False