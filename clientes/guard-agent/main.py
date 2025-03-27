import time
import socket
import json
import uuid
import os
import platform  # Add this import
from config import ram, nome, chave_ativacao, codigos, SERVER_URL
from system_utils import detect_os_distribution, os_update, os_install, verificar_sudo_disponivel
from ossec_manager import instalar_ossec, verificar_ossec_instalado, verificar_chave_ossec_importada, verificar_ossec_running, reiniciar_ossec, importar_chave_ossec
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
        hostname = nome if nome else socket.gethostname()
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
            resposta_json = resposta.json()
            log_debug(f'Resposta completa do servidor: {json.dumps(resposta_json)}')
            
            # Check for id_agente first, then fall back to id if needed
            id_agente = resposta_json.get('id_agente')
            if id_agente is None:
                id_agente = resposta_json.get('id')  # Try alternative key
                
            if id_agente is None:
                log_error(f'Servidor retornou status 200 mas sem ID de agente. Resposta completa: {json.dumps(resposta_json)}')
                return None
                
            log_info(f'Agente registrado com sucesso! ID: {id_agente}')
            
            # Save agent ID
            salvar_id(id_agente)
            return id_agente
        else:
            log_error(f'Falha no registro do agente. Status code: {resposta.status_code}, Resposta: {resposta.text}')
            return None
    except Exception as e:
        log_exception(f'Erro inesperado durante o registro do agente')
        return None

def registrar_ossec(id_agente):
    """Register agent with OSSEC server"""
    log_info("Iniciando processo de registro do OSSEC")
    
    # Verify if OSSEC is already installed and has a key imported
    if verificar_ossec_instalado() and verificar_chave_ossec_importada():
        log_info("OSSEC já está instalado e com chave importada. Nenhuma ação necessária.")
        return True
    
    # Data for OSSEC registration
    message_ossec = {
        'name': nome,  # Agent name (hostname)
        'id': id_agente,  # Agent ID in Guardian
        'chave': chave_ativacao  # Guardian activation key
    }
    
    log_debug(f"Enviando solicitação de registro OSSEC: {json.dumps(message_ossec)}")
    
    # Send request to OSSEC registration endpoint
    try:
        resposta = enviar_mensagem(message_ossec, 'registro-ossec')
        
        # Check response
        if resposta.status_code == 200:
            dados_resposta = resposta.json()
            log_debug(f"Resposta do registro OSSEC: {json.dumps(dados_resposta)}")
            
            if dados_resposta.get('status') == 'sucesso':
                activation_key = dados_resposta.get('activation_key')
                ossec_server = dados_resposta.get('ossec_server')
                log_info(f'Registro no OSSEC bem-sucedido!')
                log_debug(f'Chave de ativação do OSSEC: {activation_key}')
                log_debug(f'Servidor OSSEC: {ossec_server}')
                
                # Check if OSSEC is already installed
                if verificar_ossec_instalado():
                    log_info("OSSEC já está instalado.")
                    # Check if a key is already imported
                    if verificar_chave_ossec_importada():
                        log_info("Chave do OSSEC já importada. Nenhuma ação necessária.")
                        return True
                    else:
                        log_info("Importando chave...")
                        return importar_chave_ossec(activation_key)
                else:
                    # Install OSSEC if not installed
                    log_info("Instalando OSSEC...")
                    if instalar_ossec():
                        log_info('OSSEC instalado com sucesso!')
                        # After installation, import the key
                        return importar_chave_ossec(activation_key)
                    else:
                        log_error('Falha na instalação do OSSEC.')
                        return False
            else:
                log_error(f"Falha no registro do OSSEC: {dados_resposta.get('mensagem', 'Erro desconhecido')}")
                return False
        else:
            log_error(f"Falha na comunicação com o servidor para registro do OSSEC. Status: {resposta.status_code}")
            return False
    except Exception as e:
        log_exception(f"Erro durante o registro do OSSEC")
        return False

def verifica_resposta(resposta, ram, id_agente):
    """Check server response"""
    try:
        if resposta.status_code == 200:
            resposta_json = resposta.json()
            codigo = int(resposta_json.get('codigo'))
            log_debug(f'Resposta recebida com código: {codigo}')
            
            if codigo == codigos['ping']:
                log_debug('Processando resposta de ping')
                res_ping(resposta_json, ram)
                
                # Check if there are tasks in the response
                if 'tarefas' in ram and ram['tarefas']:
                    log_info(f"Tarefa recebida: {ram['tarefas']}")
                    executar_tarefa(ram['tarefas'], id_agente)
                    # Clear the task after execution
                    ram['tarefas'] = None
            elif codigo == codigos['ossec-register']:
                log_info('Iniciando registro do OSSEC')
                registrar_ossec(id_agente)
        else:
            log_warning(f'Falha na comunicação. Status Code: {resposta.status_code}, Resposta: {resposta.text}')
    except Exception as e:
        log_exception(f'Erro ao processar resposta do servidor')

def executar_tarefa(tarefa, id_agente):
    """Execute a task based on server request"""
    log_info(f'Executando tarefa: {tarefa}')
    
    try:
        if tarefa == 'softwares':
            log_debug('Coletando informações de software')
            collect_softwares()  # This now saves the file directly
            log_debug('Enviando informações de software')
            enviar_softwares(id_agente)
        elif tarefa == 'infos':
            log_debug('Coletando informações do sistema')
            info = collect_system_info()
            log_debug(f'Enviando informações do sistema')
            # Only use the enviar_infos function, remove the duplicate call
            enviar_infos(id_agente, info)
        elif tarefa == 'vuln-scan':
            log_info('Iniciando scan de vulnerabilidades')
            scan_result = vuln_scan()
            
            # Convert scan result to JSON string
            scan_json = json.dumps(scan_result)
            
            # Encrypt the data using base64 (matching agentenovo.py format)
            from network import encrypt_base64
            encrypted_data = encrypt_base64(scan_json)
            
            # Prepare data in the same format as agentenovo.py
            data = {
                'tipo': 'vuln-scan', 
                'chave': chave_ativacao,
                'id': id_agente,
                'payload': encrypted_data
            }
            
            log_debug('Enviando resultados do scan de vulnerabilidades')
            # Send to 'envios' endpoint like in agentenovo.py
            resposta = enviar_mensagem(data, 'envios')
            
            if resposta.status_code == 200:
                log_info('Resultados do scan de vulnerabilidades enviados com sucesso')
            else:
                log_error(f'Falha ao enviar resultados do scan. Status Code: {resposta.status_code}')
        elif tarefa == 'ossec-register':
            log_info('Iniciando registro do OSSEC')
            success = registrar_ossec(id_agente)
            if success:
                log_info('Registro do OSSEC concluído com sucesso')
            else:
                log_error('Falha no registro do OSSEC')
        elif tarefa == 'script':
            if 'script_name' in ram and 'script_content' in ram:
                log_info(f'Executando script: {ram["script_name"]}')
                result = execute_script(ram['script_name'], ram['script_content'])
                data = {
                    "chave": chave_ativacao,
                    "id": id_agente,
                    "script_result": result
                }
                log_debug('Enviando resultado da execução do script')
                enviar_mensagem(data, 'script-result')
            else:
                log_warning('Tarefa de script recebida, mas sem nome ou conteúdo')
        else:
            log_warning(f'Tarefa desconhecida recebida: {tarefa}')
    except Exception as e:
        log_exception(f'Erro ao executar tarefa {tarefa}')

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
        
        # Install and configure OSSEC
        if not verificar_ossec_instalado():
            log_info("OSSEC não está instalado. Instalando...")
            instalar_ossec()
            registrar_ossec(id_agente)
        elif not verificar_ossec_running():
            log_warning("OSSEC não está em execução. Reiniciando...")
            reiniciar_ossec()
        elif not verificar_chave_ossec_importada():
            log_warning("OSSEC instalado mas sem chave ou chave inválida. Registrando...")
            registrar_ossec(id_agente)
        
        # Configure PSAD with enhanced settings
        log_info("Verificando e configurando PSAD para detecção de port scans...")
        if verificar_e_configurar_psad():
            log_info("PSAD configurado com sucesso.")
            
            # Restart OSSEC after PSAD configuration to ensure integration
            log_info("Reiniciando OSSEC para garantir integração com PSAD...")
            reiniciar_ossec()
        else:
            log_warning("Houve problemas na configuração do PSAD. Alguns recursos podem não funcionar corretamente.")
        
        # Main loop
        log_info(f"Agente Guardian iniciado com ID: {id_agente}")
        while True:
            try:
                # Send ping to server
                log_debug("Enviando ping para o servidor")
                resposta = ping(id_agente)
                
                # Process response
                verifica_resposta(resposta, ram, id_agente)
                
                # Execute tasks if any
                if 'tarefas' in ram and ram['tarefas']:
                    log_info(f"Tarefa recebida: {ram['tarefas']}")
                    executar_tarefa(ram['tarefas'], id_agente)
                    ram['tarefas'] = None
                
                # Wait before next ping
                log_debug("Aguardando próximo ciclo")
                time.sleep(15)
            except Exception as e:
                log_exception(f"Erro no loop principal")
                time.sleep(15)
    except Exception as e:
        log_critical("Erro fatal na inicialização do agente", exc_info=e)

if __name__ == "__main__":
    main()