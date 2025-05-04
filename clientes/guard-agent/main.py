import time
import socket
import json
import uuid
import os
import platform
from config import ram, nome, chave_ativacao, codigos, SERVER_URL
from system_utils import detect_os_distribution, os_update, os_install, verificar_sudo_disponivel
from ossec_manager import (
    verificar_ossec_instalado, verificar_chave_ossec_importada, 
    verificar_ossec_running, reiniciar_ossec, instalar_ossec, 
    configurar_ossec, registrar_ossec_no_guardiao, importar_chave_ossec
)
from psad_manager import verificar_e_configurar_psad
from network import enviar_mensagem, salvar_id, carregar_id, ping, res_ping, enviar_softwares, enviar_infos
from utils import collect_softwares, collect_system_info, execute_script, vuln_scan
from logger import log_info, log_warning, log_error, log_debug, log_critical, log_exception

def registrar_agente():
    """Register agent with the server"""
    log_info('Iniciando registro do agente...')
    
    try:
        # Collect system information for registration
        info = collect_system_info()
        log_debug(f'Informações do sistema coletadas: {json.dumps(info)}')
        
        # Ensure hostname is not None
        hostname = nome 
        log_info(f'Usando hostname: {hostname}')
        
        # Prepare registration data with fallbacks for missing keys
        data = {
            "chave": chave_ativacao,
            "nome": hostname,
            "sistema": info.get('platform', platform.system()),
            "versao": info.get('platform_version', platform.version()),
            "ip": info.get('ip_address', socket.gethostbyname(socket.gethostname())),
            "mac": info.get('mac_address', ':'.join(("%012x" % uuid.getnode())[i:i+2] for i in range(0, 12, 2))),
            "host": hostname
        }
        
        # Send registration request
        log_debug(f'Enviando dados de registro: {json.dumps(data)}')
        resposta = enviar_mensagem(data, 'registro')
        
        if resposta.status_code == 200:
            dados_resposta = resposta.json()
            log_debug(f'Resposta do servidor: {json.dumps(dados_resposta)}')
            
            if dados_resposta.get('status') == 'sucesso':
                id_agente = dados_resposta.get('id')
                log_info(f'Registro bem-sucedido! ID do agente: {id_agente}')
                
                # Save agent ID
                salvar_id(id_agente)
                return id_agente
            else:
                log_error(f'Falha no registro: {dados_resposta.get("mensagem", "Erro desconhecido")}')
                return None
        else:
            log_error(f'Falha na comunicação com o servidor. Status: {resposta.status_code}')
            return None
    except Exception as e:
        log_exception('Erro durante o registro do agente')
        return None

def registrar_ossec(id_agente):
    """Register agent with OSSEC server"""
    log_info("Iniciando processo de registro do OSSEC")
    
    # Verifica se o OSSEC já está instalado e com chave importada
    if verificar_ossec_instalado() and verificar_chave_ossec_importada():
        log_info("OSSEC já está instalado e com chave importada. Nenhuma ação necessária.")
        return True
    
    # Obter o hostname do sistema
    hostname = socket.gethostname()
    log_info(f"Usando hostname do sistema: {hostname}")
    
    # Dados para registro no OSSEC
    message_ossec = {
        'name': hostname,  # Nome do agente (hostname do sistema)
        'id': id_agente,   # ID do agente no Guardian
        'chave': chave_ativacao  # Chave de ativação do Guardian
    }
    
    # Verificar se algum campo está vazio ou None
    for key, value in message_ossec.items():
        if value is None or (isinstance(value, str) and value.strip() == ''):
            log_error(f"Campo '{key}' está vazio ou nulo. Valor: {value}")
            if key == 'name':
                # Forçar o uso do hostname do sistema
                message_ossec[key] = hostname
                log_info(f"Forçando uso do hostname do sistema: {hostname}")
    
    # Gerar equivalente curl para troubleshooting
    endpoint = 'registro-ossec'
    endpoint_url = f"{SERVER_URL}/{endpoint}"
    curl_cmd = f"curl -X POST -H 'Content-Type: application/json' -d '{json.dumps(message_ossec)}' {endpoint_url}"
    
    # Logar o comando curl no nível INFO para garantir que apareça no log
    log_info(f"Enviando solicitação de registro OSSEC: {json.dumps(message_ossec)}")
    log_info(f"Endpoint: {endpoint_url}")
    log_info(f"Comando curl para troubleshooting: {curl_cmd}")
    
    try:
        resposta = enviar_mensagem(message_ossec, endpoint)
        
        # Log detalhado da resposta para diagnóstico
        if resposta:
            log_info(f"Resposta recebida. Status: {resposta.status_code}")
            
            try:
                dados_resposta = resposta.json()
                log_info(f"Resposta do registro OSSEC: {json.dumps(dados_resposta)}")
                
                if resposta.status_code == 200:
                    if dados_resposta.get('status') == 'sucesso':
                        ossec_manager = dados_resposta.get('ossec_server')
                        ossec_key = dados_resposta.get('chave_ossec')
                        
                        log_info(f'Registro no OSSEC bem-sucedido!')
                        
                        # Instala e configura o OSSEC se necessário
                        if not verificar_ossec_instalado():
                            log_info("Instalando OSSEC...")
                            if not instalar_ossec(ossec_manager):
                                log_error("Falha ao instalar OSSEC.")
                                return False
                        
                        # Importar a chave OSSEC diretamente
                        if ossec_key:
                            log_info("Importando chave OSSEC recebida do servidor...")
                            if importar_chave_ossec(ossec_key):
                                log_info("Chave OSSEC importada com sucesso.")
                                
                                # Reinicia o serviço OSSEC após importar a chave
                                log_info("Reiniciando serviço OSSEC...")
                                if reiniciar_ossec():
                                    log_info("OSSEC configurado e iniciado com sucesso.")
                                    return True
                                else:
                                    log_error("Falha ao reiniciar OSSEC após importar chave.")
                                    return False
                            else:
                                log_error("Falha ao importar chave OSSEC.")
                                return False
                        else:
                            log_error("Chave OSSEC não recebida do servidor.")
                            return False
                    else:
                        mensagem_erro = dados_resposta.get('mensagem', 'Erro desconhecido')
                        log_error(f"Falha no registro OSSEC: {mensagem_erro}")
                        log_error(f"Resposta completa: {json.dumps(dados_resposta)}")
                        return False
                else:
                    # Log detalhado para falha na comunicação
                    log_error(f"Falha na comunicação com o servidor para registro OSSEC. Status: {resposta.status_code}")
                    log_error(f"Endpoint: {endpoint_url}")
                    log_error(f"Payload: {json.dumps(message_ossec)}")
                    log_error(f"Resposta: {resposta.text if hasattr(resposta, 'text') else 'Sem corpo de resposta'}")
                    log_error(f"Comando para troubleshooting: {curl_cmd}")
                    return False
            except ValueError as e:
                # A resposta não é um JSON válido
                log_error(f"Erro ao processar resposta JSON: {str(e)}")
                log_error(f"Corpo da resposta (texto): {resposta.text[:500]}")
                log_error(f"Comando para troubleshooting: {curl_cmd}")
                return False
        else:
            log_error("Nenhuma resposta recebida do servidor")
            log_error(f"Comando para troubleshooting: {curl_cmd}")
            return False
    except Exception as e:
        log_exception(f"Erro durante o registro OSSEC: {str(e)}")
        log_error(f"Tipo de exceção: {type(e).__name__}")
        import traceback
        log_error(f"Traceback: {traceback.format_exc()}")
        log_error(f"Endpoint: {endpoint_url}")
        log_error(f"Payload: {json.dumps(message_ossec)}")
        log_error(f"Comando para troubleshooting: {curl_cmd}")
        return False

def initialize_ossec(id_agente):
    """Handle OSSEC initialization"""
    try:
        # Check if OSSEC is already installed and configured
        if verificar_ossec_instalado() and verificar_chave_ossec_importada() and verificar_ossec_running():
            log_info("OSSEC já está instalado, configurado e em execução.")
            return True
            
        # If not installed, install it
        if not verificar_ossec_instalado():
            log_info("OSSEC não está instalado. Iniciando instalação...")
            if not instalar_ossec():
                log_error("Falha na instalação do OSSEC.")
                return False
        
        # Verificar se a chave está importada
        if not verificar_chave_ossec_importada():
            log_info("Chave OSSEC não encontrada. Iniciando registro...")
            # Register with OSSEC server - apenas uma tentativa para evitar loop
            resultado = registrar_ossec(id_agente)
            if not resultado:
                log_error("Falha no registro do OSSEC. Tentativa única para evitar loop.")
                return False
            return resultado  # Retorna o resultado do registro diretamente
        else:
            log_info("Chave OSSEC já importada.")
            
        # Verify final status
        if not verificar_ossec_running():
            log_warning("OSSEC não está em execução. Tentando reiniciar...")
            if not reiniciar_ossec():
                log_error("Falha ao reiniciar OSSEC.")
                return False
                
        log_info("OSSEC inicializado com sucesso.")
        return True
        
    except Exception as e:
        log_exception("Erro durante a inicialização do OSSEC")
        return False

def main():
    """Main function"""
    log_info("Iniciando agente Guardian...")
    
    try:
        # Load agent ID if exists
        id_agente = carregar_id()
        log_debug(f'ID do agente carregado: {id_agente}')
        
        # Register agent if not registered
        if not id_agente:
            log_info('Nenhum ID de agente encontrado, iniciando registro')
            id_agente = registrar_agente()
            if not id_agente:
                log_critical("Falha no registro do agente. Saindo...")
                return
        
        # Initialize OSSEC - apenas uma tentativa para evitar loop
        ossec_inicializado = initialize_ossec(id_agente)
        if not ossec_inicializado:
            log_critical("Falha na inicialização do OSSEC. Continuando sem OSSEC...")
        
        # Configure PSAD if needed
        verificar_e_configurar_psad()
        
        # Main loop
        log_info("Iniciando loop principal do agente...")
        while True:
            try:
                log_info("Enviando ping para o servidor...")
                ping_response = ping(id_agente)
                
                if ping_response:
                    log_info("Ping bem-sucedido")
                    
                    try:
                        # Converter a resposta HTTP para um dicionário JSON
                        ping_data = ping_response.json()
                        log_debug(f"Dados recebidos do servidor: {json.dumps(ping_data)}")
                        
                        # Verificar se há comandos na fila
                        if 'fila' in ping_data and ping_data['fila']:
                            log_info(f"Comando recebido da fila: {ping_data['fila']}")
                            
                            # Processar comando da fila
                            if ping_data['fila'] == 'softwares':
                                log_info("Coletando lista de softwares...")
                                softwares = collect_softwares()
                                enviar_softwares(id_agente, softwares)
                                
                            elif ping_data['fila'] == 'infos':
                                log_info("Coletando informações do sistema...")
                                infos = collect_system_info()
                                enviar_infos(id_agente, infos)
                                
                            elif ping_data['fila'] == 'vuln-scan':
                                log_info("Iniciando varredura de vulnerabilidades...")
                                vuln_scan(id_agente)
                                
                            elif ping_data['fila'] == 'script' and 'script_name' in ping_data:
                                log_info(f"Executando script: {ping_data['script_name']}")
                                execute_script(id_agente, ping_data['script_name'])
                                
                            else:
                                log_warning(f"Comando desconhecido na fila: {ping_data['fila']}")
                        else:
                            log_info("Nenhum comando na fila")
                            
                    except json.JSONDecodeError as e:
                        log_error(f"Erro ao decodificar resposta JSON: {str(e)}")
                    except Exception as e:
                        log_exception(f"Erro ao processar resposta do servidor: {str(e)}")
                else:
                    log_warning("Falha no ping ao servidor")
                    
            except Exception as e:
                log_exception(f"Erro no loop principal: {str(e)}")
                
            # Sleep before next iteration
            log_info("Aguardando 60 segundos antes do próximo ping...")
            time.sleep(60)
            
    except Exception as e:
        log_exception(f"Erro fatal no agente: {str(e)}")

if __name__ == "__main__":
    main()