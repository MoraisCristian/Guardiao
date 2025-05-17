import requests
import json
import os
import time
import base64
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
        
        # Gerar comando curl equivalente para debug
        curl_cmd = f"curl -X POST -H 'Content-Type: application/json' -d '{json.dumps(data)}' {url}"
        log_info(f"Comando curl equivalente: {curl_cmd}")
        
        log_debug(f"Enviando requisição para: {url}")
        log_debug(f"Payload: {json.dumps(data)}")
        
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
        # Codifica o payload em base64
        payload_json = json.dumps(softwares)
        payload_base64 = base64.b64encode(payload_json.encode('utf-8')).decode('utf-8')
        
        data = {
            "id": id_agente,
            "chave": chave_ativacao,
            "tipo": "softwares",
            "payload": payload_base64
        }
        return enviar_mensagem(data, '/envios')
    except Exception as e:
        log_exception(f"Erro ao enviar softwares: {str(e)}")
        return None

def enviar_infos(id_agente, infos):
    """Envia informações do sistema para o servidor"""
    try:
        # Codifica o payload em base64
        payload_json = json.dumps(infos)
        payload_base64 = base64.b64encode(payload_json.encode('utf-8')).decode('utf-8')
        
        data = {
            "id": id_agente,
            "chave": chave_ativacao,
            "tipo": "infos",
            "payload": payload_base64
        }
        return enviar_mensagem(data, '/envios')
    except Exception as e:
        log_exception(f"Erro ao enviar informações: {str(e)}")
        return None

def enviar_vulns(id_agente, vulns):
    """Envia resultados do scan de vulnerabilidades para o servidor"""
    try:
        log_info(f"Iniciando envio de resultados de vulnerabilidades para o servidor...")
        
        # Codifica o payload em base64
        payload_json = json.dumps(vulns)
        payload_base64 = base64.b64encode(payload_json.encode('utf-8')).decode('utf-8')
        
        data = {
            "id": id_agente,
            "chave": chave_ativacao,
            "tipo": "vuln-scan",
            "payload": payload_base64
        }
        
        log_info(f"Enviando dados para o servidor...")
        log_info(f"Tamanho do payload: {len(payload_base64)} bytes")
        log_info(f"Tamanho do payload original: {len(payload_json)} bytes")
        
        # Configurar timeout maior para requisições grandes
        session = requests.Session()
        session.timeout = (30, 300)  # (connect timeout, read timeout)
        
        # Gerar comando curl equivalente para debug
        curl_cmd = f"curl -X POST -H 'Content-Type: application/json' -d '{json.dumps(data)}' {API_URL}/envios"
        log_info(f"Comando curl equivalente: {curl_cmd}")
        
        resposta = session.post(f"{API_URL}/envios", json=data, timeout=(30, 300))
        
        if resposta:
            log_info(f"Resposta do servidor recebida. Status: {resposta.status_code}")
            try:
                dados_resposta = resposta.json()
                log_info(f"Resposta do servidor: {json.dumps(dados_resposta)}")
                if resposta.status_code == 200:
                    log_info("Resultados de vulnerabilidades enviados com sucesso!")
                    return True
                else:
                    log_error(f"Erro ao enviar resultados. Status: {resposta.status_code}")
                    log_error(f"Resposta do servidor: {resposta.text}")
                    return False
            except json.JSONDecodeError as e:
                log_error(f"Erro ao decodificar resposta JSON: {str(e)}")
                log_error(f"Resposta recebida: {resposta.text}")
                return False
        else:
            log_error("Nenhuma resposta recebida do servidor")
            return False
            
    except requests.exceptions.Timeout:
        log_error("Timeout ao enviar dados para o servidor")
        return False
    except requests.exceptions.ConnectionError:
        log_error("Erro de conexão ao enviar dados para o servidor")
        return False
    except Exception as e:
        log_exception(f"Erro ao enviar vulnerabilidades: {str(e)}")
        return False