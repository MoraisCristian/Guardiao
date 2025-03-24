import time
import socket
import json
import uuid
import os
from config import ram, nome, chave_ativacao, codigos, SERVER_URL
from system_utils import detect_os_distribution, os_update, os_install, verificar_sudo_disponivel
from ossec_manager import instalar_ossec, verificar_ossec_instalado, verificar_chave_ossec_importada, verificar_ossec_running, reiniciar_ossec, importar_chave_ossec
from psad_manager import verificar_e_configurar_psad
from network import enviar_mensagem, salvar_id, carregar_id, ping, res_ping, enviar_softwares
from utils import collect_softwares, collect_system_info, execute_script, vuln_scan

def registrar_agente():
    """Register agent with the server"""
    print('Registrando agente...')
    
    # Collect system information for registration
    info = collect_system_info()
    
    # Prepare registration data
    data = {
        "chave": chave_ativacao,
        "nome": nome,
        "sistema": info['platform'],
        "versao": info['platform_version'],
        "ip": info['ip_address'],
        "mac": info['mac_address']
    }
    
    # Send registration request
    resposta = enviar_mensagem(data, 'registro')
    
    if resposta.status_code == 200:
        resposta_json = resposta.json()
        id_agente = resposta_json.get('id')
        print(f'Agente registrado com sucesso! ID: {id_agente}')
        
        # Save agent ID
        salvar_id(id_agente)
        return id_agente
    else:
        print('Falha no registro do agente.')
        return None

def registrar_ossec(id_agente):
    """Register agent with OSSEC server"""
    # Verify if OSSEC is already installed and has a key imported
    if verificar_ossec_instalado() and verificar_chave_ossec_importada():
        print("OSSEC já está instalado e com chave importada. Nenhuma ação necessária.")
        return True
    
    # Data for OSSEC registration
    message_ossec = {
        'name': nome,  # Agent name (hostname)
        'id': id_agente,  # Agent ID in Guardian
        'chave': chave_ativacao  # Guardian activation key
    }

    # Send request to OSSEC registration endpoint
    resposta = enviar_mensagem(message_ossec, 'registro-ossec')
    
    # Check response
    if resposta.status_code == 200:
        dados_resposta = resposta.json()
        if dados_resposta.get('status') == 'sucesso':
            activation_key = dados_resposta.get('activation_key')
            ossec_server = dados_resposta.get('ossec_server')
            print(f'Registro no OSSEC bem-sucedido!')
            print(f'Chave de ativação do OSSEC: {activation_key}')
            print(f'Servidor OSSEC: {ossec_server}')
            
            # Check if OSSEC is already installed
            if verificar_ossec_instalado():
                print("OSSEC já está instalado.")
                # Check if a key is already imported
                if verificar_chave_ossec_importada():
                    print("Chave do OSSEC já importada. Nenhuma ação necessária.")
                    return True
                else:
                    print("Importando chave...")
                    return importar_chave_ossec(activation_key)
            else:
                # Install OSSEC if not installed
                if instalar_ossec():
                    print('OSSEC instalado com sucesso!')
                    # After installation, import the key
                    return importar_chave_ossec(activation_key)
                else:
                    print('Falha na instalação do OSSEC.')
                    return False
        else:
            print('Falha no registro no OSSEC:', dados_resposta.get('mensagem'))
            return False
    else:
        print('Erro na comunicação com o servidor:', resposta.status_code)
        return False

def verifica_resposta(resposta, ram, id_agente):
    """Check server response"""
    if resposta.status_code == 200:
        resposta_json = resposta.json()
        codigo = int(resposta_json.get('codigo'))
        if codigo == codigos['ping']:
            res_ping(resposta_json, ram)
        elif codigo == codigos['ossec-register']:
            registrar_ossec(id_agente)
    else:
        print('Falha na comunicação. Status Code:', resposta.status_code)

def executar_tarefa(tarefa, id_agente):
    """Execute a task based on server request"""
    if tarefa == 'softwares':
        software_list = collect_softwares()
        enviar_softwares(id_agente)
    elif tarefa == 'infos':
        info = collect_system_info()
        data = {
            "chave": chave_ativacao,
            "id": id_agente,
            "infos": info
        }
        enviar_mensagem(data, 'infos')
    elif tarefa == 'vuln-scan':
        scan_result = vuln_scan()
        data = {
            "chave": chave_ativacao,
            "id": id_agente,
            "scan_result": scan_result
        }
        enviar_mensagem(data, 'vuln-scan')
    elif tarefa == 'script':
        if 'script_name' in ram and 'script_content' in ram:
            result = execute_script(ram['script_name'], ram['script_content'])
            data = {
                "chave": chave_ativacao,
                "id": id_agente,
                "script_result": result
            }
            enviar_mensagem(data, 'script-result')
    elif tarefa == 'update':
        success = os_update()
        data = {
            "chave": chave_ativacao,
            "id": id_agente,
            "update_result": success
        }
        enviar_mensagem(data, 'update-result')

def main():
    """Main function"""
    print("Iniciando agente Guardian...")
    
    # Load agent ID if exists
    id_agente = carregar_id()
    
    # Register agent if not registered
    if not id_agente:
        id_agente = registrar_agente()
        if not id_agente:
            print("Falha no registro do agente. Saindo...")
            return
    
    # Install and configure OSSEC
    if not verificar_ossec_instalado():
        print("OSSEC não está instalado. Instalando...")
        instalar_ossec()
        registrar_ossec(id_agente)
    elif not verificar_ossec_running():
        print("OSSEC não está em execução. Reiniciando...")
        reiniciar_ossec()
    elif not verificar_chave_ossec_importada():
        print("OSSEC instalado mas sem chave. Registrando...")
        registrar_ossec(id_agente)
    
    # Configure PSAD
    verificar_e_configurar_psad()
    
    # Main loop
    print(f"Agente Guardian iniciado com ID: {id_agente}")
    while True:
        try:
            # Send ping to server
            resposta = ping(id_agente)
            
            # Process response
            verifica_resposta(resposta, ram, id_agente)
            
            # Execute tasks if any
            if 'tarefas' in ram and ram['tarefas']:
                executar_tarefa(ram['tarefas'], id_agente)
                ram['tarefas'] = None
            
            # Wait before next ping
            time.sleep(60)
        except Exception as e:
            print(f"Erro no loop principal: {str(e)}")
            time.sleep(60)

if __name__ == "__main__":
    main()