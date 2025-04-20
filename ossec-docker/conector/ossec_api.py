from flask import Flask, request, jsonify
import subprocess
import os
import re
from datetime import datetime

app = Flask(__name__)

# Senha pré-combinada para autorizar a comunicação
API_PASSWORD = os.getenv("API_PASSWORD", "sua_senha_secreta")

@app.route('/add', methods=['POST'])
def add_agent():
    # Verifica a senha
    if request.headers.get('Authorization') != API_PASSWORD:
        return jsonify({"error": "Unauthorized"}), 401

    # Extrai os dados da requisição
    data = request.json
    ip = data.get('ip', 'any')
    name = data.get('name')

    if not name:
        return jsonify({"error": "Name is required"}), 400

    try:
        # Verifica se o agente já existe - Wazuh usa o mesmo caminho que OSSEC
        list_result = subprocess.run(['/var/ossec/bin/manage_agents', '-l'], 
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                  universal_newlines=True)
        
        # Procura pelo agente existente
        match = re.search(rf'ID:\s+(\d+),\s+Name:\s+{re.escape(name)}(?:,|$)', list_result.stdout)
        if match:
            agent_id = match.group(1)
            # Se o agente já existe, extrai a chave
            extract_result = subprocess.run(
                ['/var/ossec/bin/manage_agents', '-e', agent_id],
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                universal_newlines=True
            )
            
            if extract_result.returncode != 0:
                return jsonify({
                    "error": "Failed to extract key for existing agent",
                    "details": extract_result.stderr,
                    "line": 45  # Line number where error occurred
                }), 500

            return jsonify({
                "status": "success",
                "id": agent_id,
                "key": extract_result.stdout.strip(),
                "message": "Agent already exists"
            }), 200

        # Se o agente não existe, adiciona novo agente
        # No Wazuh, podemos usar a API ou o manage_agents
        add_result = subprocess.run(
            ['/var/ossec/bin/manage_agents', '-a', ip, '-n', name],
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            universal_newlines=True
        )
        
        if add_result.returncode != 0:
            return jsonify({
                "error": "Failed to add new agent",
                "details": add_result.stderr,
                "line": 63  # Line number where error occurred
            }), 500

        # Extrai o ID do novo agente
        list_result = subprocess.run(['/var/ossec/bin/manage_agents', '-l'], 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE, 
                                   universal_newlines=True)
        
        if list_result.returncode != 0:
            return jsonify({
                "error": "Failed to list agents after adding",
                "details": list_result.stderr,
                "line": 72  # Line number where error occurred
            }), 500

        # Procura pelo agente existente
        match = re.search(rf'ID:\s+(\d+),\s+Name:\s+{re.escape(name)}(?:,|$)', list_result.stdout)
        if not match:
            return jsonify({
                "error": "Failed to get new agent ID",
                "line": 76  # Line number where error occurred
            }), 500

        agent_id = match.group(1)
        
        # Extrai a chave do novo agente
        extract_result = subprocess.run(
            ['/var/ossec/bin/manage_agents', '-e', agent_id],
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            universal_newlines=True
        )
        
        if extract_result.returncode != 0:
            return jsonify({
                "error": "Failed to extract key for new agent",
                "details": extract_result.stderr,
                "line": 87  # Line number where error occurred
            }), 500

        return jsonify({
            "status": "success",
            "id": agent_id,
            "key": extract_result.stdout.strip(),
            "message": "Agent added successfully"
        }), 200

    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        return jsonify({
            "error": str(e),
            "traceback": tb,
            "line": "Unknown"  # General exception catch
        }), 500

@app.route('/list', methods=['GET'])
def list_agents():
    # Verifica a senha
    if request.headers.get('Authorization') != API_PASSWORD:
        return jsonify({"error": "Unauthorized"}), 401

    # Lista os agentes
    try:
        # Primeiro, obtenha a lista de agentes usando manage_agents
        result = subprocess.run(
            ["/var/ossec/bin/manage_agents", "-l"],
            capture_output=True,
            text=True,
            input="\n",  # Adiciona uma nova linha para evitar que o comando fique esperando input
        )
        
        if result.returncode != 0:
            return jsonify({"error": result.stderr}), 500
        
        # Processar a saída para extrair todos os agentes
        agents_output = result.stdout
        
        # Verificar se há agentes na saída
        if "No agent available" in agents_output:
            return jsonify({"agents": []}), 200
            
        # Verificar se o comando está esperando por input
        if "Choose your action" in agents_output:
            # Tente novamente com um método alternativo
            result = subprocess.run(
                ["grep", "-A", "1", "is available", "/var/ossec/etc/client.keys"],
                capture_output=True,
                text=True,
            )
            
            if result.returncode == 0:
                agents_output = "Available agents:\n" + result.stdout
        
        return jsonify({"agents": agents_output}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/extract-key/<agent_id>', methods=['GET'])
def extract_key(agent_id):
    # Verifica a senha
    if request.headers.get('Authorization') != API_PASSWORD:
        return jsonify({"error": "Unauthorized"}), 401

    # Extrai a chave do agente
    try:
        result = subprocess.run(
            ["/var/ossec/bin/manage_agents", "-e", agent_id],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return jsonify({"error": result.stderr}), 500
        return jsonify({"key": result.stdout}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/remove/<agent_id>', methods=['DELETE'])
def remove_agent(agent_id):
    # Verifica a senha
    if request.headers.get('Authorization') != API_PASSWORD:
        return jsonify({"error": "Unauthorized"}), 401

    # Remove o agente
    try:
        result = subprocess.run(
            ["/var/ossec/bin/manage_agents", "-r", agent_id],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return jsonify({"error": result.stderr}), 500
        return jsonify({"message": "Agent removed successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/status', methods=['GET'])
def agents_status():
    # Verifica a senha
    if request.headers.get('Authorization') != API_PASSWORD:
        return jsonify({"error": "Unauthorized"}), 401

    try:
        # Obter lista de agentes - Wazuh usa agent_control da mesma forma que OSSEC
        agents_result = subprocess.run(
            ["/var/ossec/bin/agent_control", "-l"],
            capture_output=True,
            text=True,
        )
        
        if agents_result.returncode != 0:
            # Tente com o comando alternativo do Wazuh
            agents_result = subprocess.run(
                ["/var/ossec/bin/wazuh-control", "-l"],
                capture_output=True,
                text=True,
            )
            if agents_result.returncode != 0:
                return jsonify({"error": agents_result.stderr}), 500
        
        # Processar a saída para extrair informações dos agentes
        agents_data = []
        lines = agents_result.stdout.strip().split('\n')
        
        for line in lines:
            if "ID:" in line:
                parts = line.split(',')
                agent = {}
                
                for part in parts:
                    if "ID:" in part:
                        agent['id'] = part.split('ID:')[1].strip()
                    elif "Name:" in part:
                        agent['name'] = part.split('Name:')[1].strip()
                    elif "IP:" in part:
                        agent['ip'] = part.split('IP:')[1].strip()
                
                # Obter status detalhado do agente
                if 'id' in agent and agent['id'] != '000':  # Ignorar o servidor (ID 000)
                    # Tente primeiro com agent_control
                    status_result = subprocess.run(
                        ["/var/ossec/bin/agent_control", "-i", agent['id']],
                        capture_output=True,
                        text=True,
                    )
                    
                    # Se falhar, tente com wazuh-control
                    if status_result.returncode != 0:
                        status_result = subprocess.run(
                            ["/var/ossec/bin/wazuh-control", "-i", agent['id']],
                            capture_output=True,
                            text=True,
                        )
                    
                    if status_result.returncode == 0:
                        status_lines = status_result.stdout.strip().split('\n')
                        for status_line in status_lines:
                            if "Status:" in status_line:
                                agent['status'] = status_line.split('Status:')[1].strip()
                            elif "Last keep alive:" in status_line:
                                agent['last_keepalive'] = status_line.split('Last keep alive:')[1].strip()
                                # Convert to datetime format if needed
                                try:
                                    # Try to parse the date format
                                    keepalive_date = datetime.strptime(agent['last_keepalive'], '%a %b %d %H:%M:%S %Y')
                                    agent['last_keepalive'] = keepalive_date.strftime('%Y-%m-%d %H:%M:%S')
                                except:
                                    # If parsing fails, keep the original format
                                    pass
                            elif "Operating system:" in status_line:
                                agent['os'] = status_line.split('Operating system:')[1].strip()
                    
                agents_data.append(agent)
        
        return jsonify({"agents": agents_data}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/alerts', methods=['GET'])
def get_alerts():
    # Verifica a senha
    if request.headers.get('Authorization') != API_PASSWORD:
        return jsonify({"error": "Unauthorized"}), 401

    try:
        # Path to the alerts.log file - Wazuh mantém o mesmo caminho
        alerts_file = '/var/ossec/logs/alerts/alerts.log'
        
        # Verificar caminhos alternativos do Wazuh se o padrão não existir
        if not os.path.exists(alerts_file):
            alerts_file = '/var/ossec/logs/alerts.log'
            if not os.path.exists(alerts_file):
                return jsonify({"alerts": [], "message": "No alerts file found"}), 200
        
        # Processar o arquivo de alertas
        alerts = []
        
        with open(alerts_file, 'r') as file:
            lines = file.readlines()
            
            # Process the alerts
            current_alert = {}
            for line in lines:
                line = line.strip()
                
                # Start of a new alert
                if line.startswith('** Alert'):
                    if current_alert:
                        alerts.append(current_alert)
                    current_alert = {'full_log': line + '\n'}
                    
                    # Extract timestamp and ID
                    parts = line.split(':', 1)
                    if len(parts) > 1:
                        header = parts[0]
                        timestamp_parts = header.split(' ')
                        if len(timestamp_parts) > 2:
                            current_alert['timestamp'] = timestamp_parts[1] + ' ' + timestamp_parts[2]
                            current_alert['id'] = timestamp_parts[-1] if len(timestamp_parts) > 3 else 'Unknown'
                
                # Continue building the current alert
                elif current_alert:
                    current_alert['full_log'] += line + '\n'
                    
                    # Extract rule details
                    if 'Rule:' in line:
                        rule_parts = line.split('Rule:')[1].strip()
                        if '(level' in rule_parts and ')' in rule_parts:
                            level_parts = rule_parts.split('(level')[1].split(')')[0]
                            current_alert['rule'] = rule_parts.split('(level')[0].strip()
                            current_alert['level'] = level_parts.replace('level', '').strip()
                            
                            # Extract description from the rule line
                            if '->' in rule_parts:
                                desc_part = rule_parts.split('->')[1].strip()
                                # Remove quotes if present
                                if desc_part.startswith("'") and desc_part.endswith("'"):
                                    desc_part = desc_part[1:-1]
                                current_alert['description'] = desc_part
                        else:
                            current_alert['rule'] = rule_parts
                    elif line.startswith('Src IP:'):
                        current_alert['src_ip'] = line.replace('Src IP:', '').strip()
                    # If we don't have a description yet and this is not a header line,
                    # it's likely the actual alert message
                    elif 'description' not in current_alert and not line.startswith('Rule:') and not line.startswith('2025 Mar'):
                        current_alert['description'] = line
            
            # Add the last alert
            if current_alert:
                alerts.append(current_alert)
        
        return jsonify({"alerts": alerts}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/registro', methods=['POST'])
def register_agent():
    # Verifica a senha (opcional para registro)
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header != API_PASSWORD:
        return jsonify({"error": "Unauthorized"}), 401

    # Extrai os dados da requisição
    data = request.json
    if not data:
        return jsonify({"error": "Invalid JSON data"}), 400
    
    # Extrai informações do agente
    chave = data.get('chave')
    nome = data.get('nome')
    ip = data.get('ip', 'any')
    sistema = data.get('sistema', 'Unknown')
    versao = data.get('versao', 'Unknown')
    mac = data.get('mac', '00:00:00:00:00:00')
    host = data.get('host', nome)
    
    if not nome:
        return jsonify({"error": "Nome do agente é obrigatório"}), 400
    
    # Verificar chave de ativação (se necessário)
    # Você pode adicionar uma verificação de chave aqui se quiser
    
    try:
        # Verifica se o agente já existe
        list_result = subprocess.run(['/var/ossec/bin/manage_agents', '-l'], 
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                  universal_newlines=True)
        
        # Procura pelo agente existente
        match = re.search(rf'ID:\s+(\d+),\s+Name:\s+{re.escape(nome)}(?:,|$)', list_result.stdout)
        if match:
            agent_id = match.group(1)
            # Se o agente já existe, extrai a chave
            extract_result = subprocess.run(
                ['/var/ossec/bin/manage_agents', '-e', agent_id],
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                universal_newlines=True
            )
            
            if extract_result.returncode != 0:
                return jsonify({
                    "status": "erro",
                    "mensagem": "Falha ao extrair chave para agente existente",
                    "detalhes": extract_result.stderr
                }), 500

            # Registra informações adicionais do agente em um arquivo de log ou banco de dados
            with open('/var/ossec/logs/agent_info.log', 'a') as f:
                f.write(f"{datetime.now().isoformat()} - ID: {agent_id}, Nome: {nome}, IP: {ip}, Sistema: {sistema}, Versão: {versao}, MAC: {mac}, Host: {host}\n")

            return jsonify({
                "status": "sucesso",
                "id": agent_id,
                "chave": extract_result.stdout.strip(),
                "mensagem": "Agente já existe e foi atualizado"
            }), 200

        # Se o agente não existe, adiciona novo agente
        add_result = subprocess.run(
            ['/var/ossec/bin/manage_agents', '-a', ip, '-n', nome],
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            universal_newlines=True
        )
        
        if add_result.returncode != 0:
            return jsonify({
                "status": "erro",
                "mensagem": "Falha ao adicionar novo agente",
                "detalhes": add_result.stderr
            }), 500

        # Extrai o ID do novo agente
        list_result = subprocess.run(['/var/ossec/bin/manage_agents', '-l'], 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE, 
                                   universal_newlines=True)
        
        match = re.search(rf'ID:\s+(\d+),\s+Name:\s+{re.escape(nome)}(?:,|$)', list_result.stdout)
        if not match:
            return jsonify({
                "status": "erro",
                "mensagem": "Falha ao obter ID do novo agente"
            }), 500

        agent_id = match.group(1)
        
        # Extrai a chave do novo agente
        extract_result = subprocess.run(
            ['/var/ossec/bin/manage_agents', '-e', agent_id],
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            universal_newlines=True
        )
        
        if extract_result.returncode != 0:
            return jsonify({
                "status": "erro",
                "mensagem": "Falha ao extrair chave para novo agente",
                "detalhes": extract_result.stderr
            }), 500

        # Registra informações adicionais do agente em um arquivo de log ou banco de dados
        with open('/var/ossec/logs/agent_info.log', 'a') as f:
            f.write(f"{datetime.now().isoformat()} - ID: {agent_id}, Nome: {nome}, IP: {ip}, Sistema: {sistema}, Versão: {versao}, MAC: {mac}, Host: {host}\n")

        # Reinicia o OSSEC para aplicar as mudanças
        subprocess.run(['/var/ossec/bin/ossec-control', 'restart'], 
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        return jsonify({
            "status": "sucesso",
            "id": agent_id,
            "chave": extract_result.stdout.strip(),
            "mensagem": "Agente adicionado com sucesso"
        }), 200

    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        return jsonify({
            "status": "erro",
            "mensagem": str(e),
            "traceback": tb
        }), 500

# Add a simple ping endpoint for connectivity testing
@app.route('/ping', methods=['GET'])
def ping():
    return jsonify({"status": "success", "message": "Server is running"}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=59347)