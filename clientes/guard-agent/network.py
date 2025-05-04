import requests
import json
import os
import time
from logger import log_info, log_error, log_debug, log_exception
from config import API_URL, SERVER_URL

def enviar_mensagem(data, endpoint):
    """Envia mensagem para o servidor Guardian"""
    try:
        # Garantir que o endpoint comece com /api/
        if not endpoint.startswith('/'):
            endpoint = f'/{endpoint}'
            
        # Construir URL completa com prefixo /api/
        url = f"{API_URL}{endpoint}"
        
        log_debug(f"Enviando requisição para: {url}")
        headers = {'Content-Type': 'application/json'}
        
        response = requests.post(url, json=data, headers=headers)
        return response
    except Exception as e:
        log_exception(f"Erro ao enviar mensagem para {endpoint}: {str(e)}")
        return None

def salvar_id(id_agente):
    """Salva o ID do agente em um arquivo local"""
    try:
        with open('AGENTID', 'w') as f:
            f.write(str(id_agente))
        return True
    except Exception as e:
        log_exception(f"Erro ao salvar ID do agente: {str(e)}")
        return False

def carregar_id():
    """Carrega o ID do agente do arquivo local"""
    try:
        if os.path.exists('AGENTID'):
            with open('AGENTID', 'r') as f:
                return f.read().strip()
        return None
    except Exception as e:
        log_exception(f"Erro ao carregar ID do agente: {str(e)}")
        return None

def ping(id_agente):
    """Envia ping para o servidor"""
    try:
        data = {"id": id_agente}
        return enviar_mensagem(data, '/ping')
    except Exception as e:
        log_exception(f"Erro ao enviar ping: {str(e)}")
        return None

def res_ping(id_agente, comando_id):
    """Responde a um comando recebido no ping"""
    try:
        data = {
            "id": id_agente,
            "comando_id": comando_id
        }
        return enviar_mensagem(data, '/res-ping')
    except Exception as e:
        log_exception(f"Erro ao responder ping: {str(e)}")
        return None

def enviar_softwares(id_agente, softwares):
    """Envia lista de softwares para o servidor"""
    try:
        data = {
            "id": id_agente,
            "softwares": softwares
        }
        return enviar_mensagem(data, '/softwares')
    except Exception as e:
        log_exception(f"Erro ao enviar softwares: {str(e)}")
        return None

def enviar_infos(id_agente, infos):
    """Envia informações do sistema para o servidor"""
    try:
        data = {
            "id": id_agente,
            "infos": infos
        }
        return enviar_mensagem(data, '/infos')
    except Exception as e:
        log_exception(f"Erro ao enviar informações: {str(e)}")
        return None