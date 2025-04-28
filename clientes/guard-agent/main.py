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
    configurar_ossec, registrar_ossec_no_guardiao
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
                ossec_manager = dados_resposta.get('ossec_server')
                activation_key = dados_resposta.get('activation_key')
                ossec_hostname = dados_resposta.get('ossec_hostname')
                
                log_info(f'Registro no OSSEC bem-sucedido!')
                
                # Install and configure OSSEC
                if not verificar_ossec_instalado():
                    log_info("Instalando OSSEC...")
                    if not instalar_ossec(ossec_manager):
                        log_error("Falha ao instalar OSSEC.")
                        return False
                
                # Configure OSSEC with the server address
                log_info(f"Configurando OSSEC para conectar ao servidor: {ossec_manager}")
                if not configurar_ossec(ossec_manager):
                    log_error("Falha ao configurar OSSEC.")
                    return False
                
                # Importar a chave recebida
                log_info("Importando chave OSSEC...")
                if not importar_chave_ossec(activation_key, ossec_hostname):
                    log_error("Falha ao importar chave OSSEC.")
                    return False
                
                # Restart OSSEC service
                log_info("Reiniciando serviço OSSEC...")
                if not reiniciar_ossec():
                    log_error("Falha ao reiniciar OSSEC.")
                    return False
                
                log_info("OSSEC configurado e iniciado com sucesso.")
                return True
            else:
                log_error(f"Falha no registro OSSEC: {dados_resposta.get('mensagem', 'Erro desconhecido')}")
                return False
        else:
            log_error(f"Falha na comunicação com o servidor para registro OSSEC. Status: {resposta.status_code}")
            return False
    except Exception as e:
        log_exception(f"Erro durante o registro OSSEC: {str(e)}")
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
            # Register with OSSEC server
            if not registrar_ossec(id_agente):
                log_error("Falha no registro do OSSEC.")
                return False
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
        
        # Initialize OSSEC
        if not initialize_ossec(id_agente):
            log_critical("Falha na inicialização do OSSEC. Saindo...")
            return
            
        # Validate OSSEC client.keys file and registration
        client_keys_path = "/var/ossec/etc/client.keys"
        if not os.path.exists(client_keys_path) or os.path.getsize(client_keys_path) == 0:
            log_info("Arquivo client.keys não encontrado ou vazio. Iniciando registro OSSEC...")
            if registrar_ossec(id_agente):
                log_info("Registro OSSEC concluído com sucesso.")
                if not reiniciar_ossec():
                    log_error("Falha ao reiniciar OSSEC após registro.")
            else:
                log_error("Falha no registro OSSEC.")
        
        # Configure PSAD if needed
        verificar_e_configurar_psad()
        
        # Main loop
        log_info("Iniciando loop principal do agente...")
        while True:
            try:
                # Send ping to server
                ping_response = ping(id_agente)
                
                if ping_response:
                    log_debug("Ping bem-sucedido")
                    
                    # Converter a resposta HTTP para um dicionário JSON
                    ping_data = ping_response.json() if hasattr(ping_response, 'json') else {}
                    
                    # Process commands from server
                    for comando in ping_data.get('comandos', []):
                        log_info(f"Executando comando: {comando}")
                        
                        if comando == 'softwares':
                            # Collect and send software list
                            softwares = collect_softwares()
                            enviar_softwares(id_agente, softwares)
                            
                        elif comando == 'infos':
                            # Collect and send system info
                            infos = collect_system_info()
                            enviar_infos(id_agente, infos)
                            
                        elif comando == 'vuln':
                            # Run vulnerability scan
                            vuln_scan(id_agente)
                            
                        elif comando.startswith('script:'):
                            # Execute custom script
                            script_id = comando.split(':')[1]
                            execute_script(id_agente, script_id)
                            
                        elif comando == 'restart_ossec':
                            # Restart OSSEC service
                            log_info("Reiniciando serviço OSSEC...")
                            reiniciar_ossec()
                            
                        else:
                            log_warning(f"Comando desconhecido: {comando}")
                else:
                    log_warning("Falha no ping ao servidor")
                    
            except Exception as e:
                log_exception(f"Erro no loop principal: {str(e)}")
                
            # Sleep before next iteration
            time.sleep(60)
            
    except Exception as e:
        log_exception(f"Erro fatal no agente: {str(e)}")

if __name__ == "__main__":
    main()