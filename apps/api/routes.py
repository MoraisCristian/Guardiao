# Standard library imports
import base64
import json
import os
import re
from datetime import datetime
import requests

# Third-party frameworks
from flask import (
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for
)
from flask_dance.contrib.github import github
from flask_login import login_user, logout_user, current_user
from flask_restx import Api, Resource, Namespace, reqparse
from werkzeug.datastructures import MultiDict

# Application modules
from apps.api import blueprint
from apps.authentication.decorators import token_required

# Models and database operations
from apps.authentication.models import (
    Agentes,
    Atividades,
    Chaves,
    Fila,
    Infos,
    Softwares,
    Users,
    Vulnerabilidades,
    registrar_agente,
    remover_agente,
    remove_da_fila,
    salvar_no_banco
)


api = Api(blueprint)

# Função para registro no OSSEC
def register_ossec_agent(name, id_agente):
    ossec_server_address = "ossec"
    ossec_http_auth = "sua_senha_secreta"
    url = f'http://{ossec_server_address}:59347/add'
    headers = {
        'Authorization': ossec_http_auth,
        'Content-Type': 'application/json'
    }
    
    # Ensure name and id_agente are strings
    name = str(name) if name else "unknown"
    id_agente = str(id_agente) if id_agente else "0"
    
    # Create unique hostname for OSSEC registration
    ossec_hostname = f"{name}_{id_agente}"
    data = {
        'ip': 'any',
        'name': ossec_hostname
    }

    try:
        # Register new agent
        response = requests.post(url, headers=headers, json=data)
        print(response.text)
        print(response.status_code)
        print(response.headers)
        
        if response.status_code == 200:
            response_data = response.json()
            if response_data.get('status') == 'success':
                ossec_agent_id = str(response_data.get('id'))
                key_response = response_data.get('key', '')
                
                # Extract the actual key from the response
                key_match = re.search(r"Agent key information for '\d+':\s+(\S+)", key_response)
                activation_key = key_match.group(1) if key_match else key_response
                
                print(f"Successfully registered OSSEC agent. ID: {ossec_agent_id}")
                return ossec_agent_id, ossec_hostname, activation_key

        print(f"Failed to register OSSEC agent. Status: {response.status_code}")
        return None, None, None

    except Exception as e:
        print(f"Exception occurred during OSSEC registration: {str(e)}")
        return None, None, None

# Modificando a implementação da rota registro-ossec para usar Resource
@api.route('/registro-ossec')
class RegistroOssec(Resource):
    def post(self):
        """
        Endpoint para registrar um agente no OSSEC
        """
        data = request.get_json()
        name = data.get('name')
        id_agente = data.get('id')
        chave_ativacao = data.get('chave')

        # Verify if agent is already registered in Guardian
        agente = Agentes.query.filter_by(id=id_agente, chave=chave_ativacao).first()
        if not agente:
            error_msg = f"Agent not found. ID: {id_agente}, Key: {chave_ativacao}"
            print(error_msg)
            return jsonify({'status': 'erro', 'mensagem': error_msg}), 404

        try:
            # Register agent in OSSEC
            ossec_agent_id, ossec_hostname, activation_key = register_ossec_agent(name, id_agente)
            
            if not all([ossec_agent_id, ossec_hostname, activation_key]):
                error_msg = "Failed to register OSSEC agent"
                print(error_msg)
                return jsonify({'status': 'erro', 'mensagem': error_msg}), 500
                
            # Update agent record with OSSEC information
            agente.ossec_registered = True
            agente.ossec_id = ossec_agent_id
            agente.ossec_hostname = ossec_hostname
            db.session.commit()

            # Remove ossec-register from queue
            remove_da_fila(id_agente, chave_ativacao, 'ossec-register')
            
            success_msg = f"Successfully registered OSSEC agent. ID: {ossec_agent_id}, Hostname: {ossec_hostname}"
            print(success_msg)
            return {
                'status': 'sucesso',
                'activation_key': activation_key,
                'ossec_hostname': ossec_hostname,
                'ossec_server': "ossec"
            }, 200
            
        except Exception as e:
            db.session.rollback()
            error_msg = f"Exception during OSSEC registration: {str(e)}"
            print(error_msg)
            return {
                'status': 'erro',
                'mensagem': error_msg
            }, 500

codigos = {'registro': 1, 'ping': 2, 'upload': 3}

def normalizar_data_iso(data_str):
    """
    Normaliza uma string de data ISO 8601 para garantir que os milissegundos tenham três dígitos.
    """
    if data_str:
        # Remove o 'Z' no final, se presente
        if data_str.endswith('Z'):
            data_str = data_str.rstrip('Z')
        
        # Verifica se há milissegundos na string
        if '.' in data_str:
            parte_data, parte_milissegundos = data_str.split('.')
            # Completa os milissegundos com zeros à direita para ter três dígitos
            parte_milissegundos = parte_milissegundos.ljust(3, '0')
            data_str = f"{parte_data}.{parte_milissegundos}"
        
        return data_str
    return None

# Função para decodificar base64
def decrypt_base64(encoded_string):
    decoded_bytes = base64.b64decode(encoded_string.encode('utf-8'))
    decoded_string = decoded_bytes.decode('utf-8')
    return decoded_string

# Registra nova atividade de agente
def registrar_atividade(chave, id_agente, atividade):
    data_contato = datetime.now()
    nova_atividade = Atividades(chave=chave, id_agente=id_agente, data_contato=data_contato, atividade=atividade)
    salvar_no_banco(nova_atividade)

def salvar_dados_db(chave_ativacao, id_agente, payload, tipo, mensagem=None):
    data_contato = datetime.now()
    
    if tipo == 'softwares':
        try:
            software_list = json.loads(payload)
            
            # Verifica se há dados de software para processar
            if software_list:
                for software in software_list:
                    nome, versao, modificacao, assinatura, local = None, None, None, None, None
                    try:
                        nome = software.get('Name', 'Desconhecido')
                    except (KeyError, AttributeError):
                        nome = 'Desconhecido'
                    try:
                        versao = software.get('Version', 'Desconhecida')
                    except (KeyError, AttributeError):
                        versao = 'Desconhecida'
                    try:
                        modificacao = software.get('Last Modified')
                    except (KeyError, AttributeError):
                        pass
                    try:
                        assinatura = software.get('Signed by')
                    except (KeyError, AttributeError):
                        pass
                    try:
                        local = software.get('Location')
                    except (KeyError, AttributeError):
                        pass
                    try:
                        descricao = software.get('Description')
                    except (KeyError, AttributeError):
                        descricao = None

                    # Salva o software no banco de dados
                    nova_atividade = Softwares(
                        chave=chave_ativacao,
                        id_agente=id_agente,
                        data_contato=data_contato,
                        software=nome,
                        versao=versao,
                        assinatura=assinatura,
                        local=local,
                        modificacao=modificacao,
                        descricao=descricao
                    )
                    salvar_no_banco(nova_atividade)
            
            # Remove a atividade da fila independentemente de ter processado softwares ou não
            print(f"Removendo atividade 'softwares' da fila para agente {id_agente}")
            resultado = remove_da_fila(id_agente, chave_ativacao, tipo)
            print(f"Resultado da remoção: {resultado}")
            
        except Exception as e:
            print(f"Erro ao processar dados de software: {str(e)}")
            # Mesmo com erro, tenta remover da fila para evitar loop infinito
            remove_da_fila(id_agente, chave_ativacao, tipo)

    elif tipo == 'infos':
        infos = Infos(json.loads(payload))
        salvar_no_banco(infos)
        remove_da_fila(id_agente, chave_ativacao, tipo)

    elif tipo == 'vuln-scan':
        # Decodifica o payload
        dados_vuln = json.loads(payload)
        data_atualizacao = datetime.now()

        # Itera sobre os resultados do scan
        for result in dados_vuln.get('Results', []):
            target = result.get('Target')
            vulnerabilities = result.get('Vulnerabilities', [])

            for vuln in vulnerabilities:
                if vuln.get('VulnerabilityID'):
                    # Extrai os dados da vulnerabilidade
                    cve_id = vuln.get('VulnerabilityID')
                    installed_version = vuln.get('InstalledVersion')
                    fixed_version = vuln.get('FixedVersion')
                    status = vuln.get('Status')
                    severity = vuln.get('Severity')
                    title = vuln.get('Title')
                    description = vuln.get('Description')
                    cwe_ids = vuln.get('CweIDs', [])
                    cvss = vuln.get('CVSS', {})
                    references = vuln.get('References', [])
                    published_date = vuln.get('PublishedDate')
                    last_modified_date = vuln.get('LastModifiedDate')

                    # Converte as datas para o formato datetime
                    if published_date:
                        published_date = normalizar_data_iso(published_date)
                        published_date = datetime.fromisoformat(published_date)
                    else:
                        published_date = None

                    if last_modified_date:
                        last_modified_date = normalizar_data_iso(last_modified_date)
                        last_modified_date = datetime.fromisoformat(last_modified_date)
                    else:
                        last_modified_date = None

                    # Verifica se a vulnerabilidade já existe para este agente
                    vuln_existente = Vulnerabilidades.query.filter_by(
                        id_agente=id_agente,
                        cve_id=cve_id
                    ).first()
                    
                    if vuln_existente:
                        # Atualiza a vulnerabilidade existente
                        vuln_existente.target = target
                        vuln_existente.status = status
                        vuln_existente.installed_version = installed_version
                        vuln_existente.fixed_version = fixed_version
                        vuln_existente.severity = severity
                        vuln_existente.title = title
                        vuln_existente.description = description
                        vuln_existente.cwe_ids = cwe_ids
                        vuln_existente.cvss = cvss
                        vuln_existente.references = references
                        vuln_existente.published_date = published_date
                        vuln_existente.last_modified_date = last_modified_date
                        vuln_existente.data_atualizacao = data_atualizacao
                        db.session.commit()
                    else:
                        # Cria uma nova entrada no banco de dados
                        nova_vulnerabilidade = Vulnerabilidades()
                        nova_vulnerabilidade.chave = chave_ativacao
                        nova_vulnerabilidade.id_agente = id_agente
                        nova_vulnerabilidade.cve_id = cve_id
                        nova_vulnerabilidade.target = target
                        nova_vulnerabilidade.status = status
                        nova_vulnerabilidade.installed_version = installed_version
                        nova_vulnerabilidade.fixed_version = fixed_version
                        nova_vulnerabilidade.severity = severity
                        nova_vulnerabilidade.title = title
                        nova_vulnerabilidade.description = description
                        nova_vulnerabilidade.cwe_ids = cwe_ids
                        nova_vulnerabilidade.cvss = cvss
                        nova_vulnerabilidade.references = references
                        nova_vulnerabilidade.published_date = published_date
                        nova_vulnerabilidade.last_modified_date = last_modified_date
                        nova_vulnerabilidade.data_atualizacao = data_atualizacao
                        salvar_no_banco(nova_vulnerabilidade)

        remove_da_fila(id_agente, chave_ativacao, tipo)

    elif tipo == 'script-resultado':
        # Decodifica o payload
        resultado = json.loads(payload)
        script_name = mensagem.get('script_name', '')
        
        # Registra a atividade com o resultado do script
        nova_atividade = Atividades(
            chave=chave_ativacao,
            id_agente=id_agente,
            data_contato=data_contato,
            atividade='script-executado'
        )
        salvar_no_banco(nova_atividade)
        
        # Remove o script da fila
        remove_da_fila(id_agente, chave_ativacao, 'script')

@api.route('/envios', methods=['POST'])
class ReceberDados(Resource):
    def post(self):
        mensagem = request.get_json()
        chave_ativacao = mensagem['chave']
        id_agente = mensagem['id']
        tipo = mensagem['tipo']
        payload = decrypt_base64(mensagem['payload'])
        print(mensagem, chave_ativacao, id_agente, tipo, payload)

        agentes = Agentes.query.all()

        for agente in agentes:
            if agente.chave == chave_ativacao:
                if int(agente.id) == int(id_agente):
                    
                    salvar_dados_db(chave_ativacao, id_agente, payload, tipo, mensagem)
                    registrar_atividade(chave_ativacao, id_agente, tipo)
                    return jsonify({'status': 'sucesso'}), 200
        return jsonify({'status': 'falha', 'mensagem': 'Chave de ativação ou ID do agente não encontrado'}), 400

# Rota para download de arquivos
@api.route('/download/<arquivo>')
class Download(Resource):
    def get(self, arquivo):
        caminho = 'downloads/' + arquivo
        return send_file(caminho, as_attachment=True)

# Nova rota para download de scripts
@api.route('/download/script/<int:id_agente>/<script_name>')
class DownloadScript(Resource):
    def get(self, id_agente, script_name):
        try:
            # Construir o caminho para o script
            caminho = f'/app/apps/utils/{id_agente}/{script_name}'
            
            # Verificar se o arquivo existe
            if not os.path.exists(caminho):
                return jsonify({'erro': 'Script não encontrado'}), 404
                
            return send_file(caminho, as_attachment=True)
        except Exception as e:
            return jsonify({'erro': str(e)}), 500


@api.route('/ping')
class Ping(Resource):
    def post(self):
        data = request.get_json()
        chave = data.get('chave')
        id_agente = data.get('id')

        output = jsonify({"mensagem": "Não há atividades pendentes na fila.", "fila": None, 'codigo': codigos['ping']}), 200

        agentes = Agentes.query.all()

        for agente in agentes:
            if agente.chave == chave:
                if int(agente.id) == int(id_agente):
                    registrar_atividade(chave, id_agente, 'ping')
                    fila = Fila.query.all()
                    for atividade in fila:
                        if atividade.chave == chave:
                            if int(atividade.id_agente) == int(id_agente):
                                resposta = {
                                    "mensagem": "Há atividades pendentes na fila.",
                                    "fila": atividade.fila,
                                    'codigo': codigos['ping']
                                }
                                # Adiciona o nome do script se a atividade for do tipo script
                                if atividade.fila == 'script':
                                    resposta['script_name'] = atividade.script_name
                                output = jsonify(resposta), 200
        return output

# Rota para registro de novos agentes
@api.route('/registro')
class Registro(Resource):
    def post(self):
        supostachave = request.json.get('chave')
        host = request.json.get('host')

        chaves = Chaves.query.all()
        for chave in chaves:
            if supostachave == chave.chave:
                id_agente = registrar_agente(chave.chave, host)
                registrar_atividade(chave.chave, id_agente, 'registro')
                return jsonify({'id_agente': id_agente, 'codigo': codigos['registro']}), 200
        return jsonify({'erro': 'Chave não autorizada', 'codigo': codigos['registro']}), 403


@api.route('/remove_agent/<int:id_agente>')
class RemoveAgent(Resource):
    def get(self, id_agente):
        try:
            # Check if user is authenticated
            if not current_user.is_authenticated:
                return redirect(url_for('authentication_api.login'))
                
            # Get the agent from database
            agent = Agentes.query.filter_by(id=id_agente).first()
            
            if not agent:
                return render_template('home/page-404.html', error="Agente não encontrado"), 404
            
            # Get agent info for display
            agent_info = Infos.query.filter_by(id_agente=id_agente).first()
            
            if not agent_info:
                return render_template('home/page-404.html', error="Informações do agente não encontradas"), 404
            
            # Show confirmation page
            return render_template('home/remove_agent.html', agent=agent, agent_info=agent_info)
                
        except Exception as e:
            print(f"Erro ao preparar remoção do agente: {str(e)}")
            return render_template('home/page-500.html', error=f"Erro ao preparar remoção do agente: {str(e)}"), 500

@api.route('/confirm_remove_agent/<int:id_agente>')
class ConfirmRemoveAgent(Resource):
    def post(self, id_agente):
        try:
            # Check if user is authenticated
            if not current_user.is_authenticated:
                return redirect(url_for('authentication_api.login'))
            
            # Get the agent from database
            agent = Agentes.query.filter_by(id=id_agente).first()
            
            if not agent:
                return render_template('home/page-404.html', error="Agente não encontrado"), 404
            
            # Get agent info
            agent_info = Infos.query.filter_by(id_agente=id_agente).first()
            
            # Verify confirmation text
            confirmation = request.form.get('confirmation', '')
            if not agent_info or confirmation != agent_info.hostname:
                flash("Confirmação incorreta. A remoção do agente foi cancelada.", "danger")
                return redirect(url_for('authentication_api.remove_agent', id_agente=id_agente))
            
            # Call the remover_agente function
            result = remover_agente(id_agente)
            
            if isinstance(result, tuple) and len(result) == 2:
                success, message = result
            else:
                # Handle the case where remover_agente doesn't return a tuple
                success = result
                message = "Agente removido com sucesso" if success else "Falha ao remover o agente"
            
            if success:
                flash("Agente removido com sucesso", "success")
                return redirect(url_for('home_api.agentes'))
            else:
                flash(f"Falha ao remover o agente: {message}", "danger")
                return redirect(url_for('authentication_api.remove_agent', id_agente=id_agente))
                
        except Exception as e:
            print(f"Erro ao remover agente: {str(e)}")
            return render_template('home/page-500.html', error=f"Erro ao remover agente: {str(e)}"), 500
