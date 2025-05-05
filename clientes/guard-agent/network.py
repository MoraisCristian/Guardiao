import requests
import json
import os
import time
from logger import log_info, log_error, log_debug, log_exception, log_warning
from config import API_URL, SERVER_URL, chave_ativacao

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
        log_info(f"Enviando ping para o servidor com ID: {id_agente}")
        data = {
            "id": id_agente,
            "chave": chave_ativacao
        }
        log_debug(f"Dados do ping: {json.dumps(data)}")
        
        resposta = enviar_mensagem(data, '/ping')
        
        if resposta:
            log_info(f"Resposta do ping recebida. Status: {resposta.status_code}")
            try:
                dados = resposta.json()
                log_debug(f"Dados da resposta: {json.dumps(dados)}")
                return resposta
            except json.JSONDecodeError as e:
                log_error(f"Erro ao decodificar resposta JSON: {str(e)}")
                return None
        else:
            log_warning("Nenhuma resposta recebida do servidor")
            return None
            
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
            "chave": chave_ativacao,
            "tipo": "softwares",
            "payload": softwares
        }
        return enviar_mensagem(data, '/envios')
    except Exception as e:
        log_exception(f"Erro ao enviar softwares: {str(e)}")
        return None

def enviar_infos(id_agente, infos):
    """Envia informações do sistema para o servidor"""
    try:
        data = {
            "id": id_agente,
            "chave": chave_ativacao,
            "tipo": "infos",
            "payload": infos
        }
        return enviar_mensagem(data, '/envios')
    except Exception as e:
        log_exception(f"Erro ao enviar informações: {str(e)}")
        return None

def enviar_vulns(id_agente, vulns):
    """Envia resultados do scan de vulnerabilidades para o servidor"""
    try:
        data = {
            "id": id_agente,
            "chave": chave_ativacao,
            "tipo": "vuln-scan",
            "payload": vulns
        }
        return enviar_mensagem(data, '/envios')
    except Exception as e:
        log_exception(f"Erro ao enviar vulnerabilidades: {str(e)}")
        return None