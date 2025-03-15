# -*- encoding: utf-8 -*-

import json
from datetime import datetime
import os

# Importações do Flask e extensões relacionadas
from flask_restx import Resource, Api
import flask
from flask import render_template, redirect, request, url_for, send_file
from flask_login import (
    current_user,
    login_user,
    logout_user
)
from flask_dance.contrib.github import github

# Importações dos modelos, formulários e utilitários de autenticação
from apps import db, login_manager
from apps.authentication import blueprint
from apps.authentication.forms import LoginForm, CreateAccountForm
from apps.authentication.models import Vulnerabilidades, Atividades, Softwares, Agentes, Chaves, Users, Infos, Fila, registrar_agente, salvar_no_banco, remove_da_fila
from apps.authentication.util import verify_pass, generate_token

# Inicialização da API Flask
api = Api(blueprint)

# Rota padrão redireciona para a página de login
@blueprint.route('/')
def route_default():
    return redirect(url_for('authentication_blueprint.login'))



# Rota para login de usuários
@blueprint.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm(request.form)

    if flask.request.method == 'POST':
        # Ler os dados do formulário
        username = request.form['username']
        password = request.form['password']
        #retorna 'Login: ' + username + ' / ' + password

        # Localizar o usuário
        user = Users.query.filter_by(username=username).first()

        # Verificar a senha
        if user and verify_pass(password, user.password):
            login_user(user)
            return redirect(url_for('authentication_blueprint.route_default'))

        # Caso usuário ou senha estejam incorretos
        return render_template('accounts/login.html',
                               msg='Usuário ou senha errados',
                               form=login_form)

    # Redirecionar usuário logado para a página inicial
    if current_user.is_authenticated:
        return redirect(url_for('home_blueprint.index'))
    else:
        return render_template('accounts/login.html',
                               form=login_form) 

# Rota para registro de novos usuários
@blueprint.route('/register', methods=['GET', 'POST'])
def register():
    create_account_form = CreateAccountForm(request.form)
    if 'register' in request.form:

        username = request.form['username']
        email = request.form['email']

        # Verificar se o nome de usuário já está em uso
        user = Users.query.filter_by(username=username).first()
        if user:
            return render_template('accounts/register.html',
                                   msg='Usuário já registrado',
                                   success=False,
                                   form=create_account_form)

        # Verificar se o e-mail já está em uso
        user = Users.query.filter_by(email=email).first()
        if user:
            return render_template('accounts/register.html',
                                   msg='E-mail já registrado',
                                   success=False,
                                   form=create_account_form)

        # Senão podemos criar o usuário
        user = Users(**request.form)
        db.session.add(user)
        db.session.commit()

        # Redirecionar para a página de registro com mensagem de sucesso
        logout_user()

        return render_template('accounts/register.html',
                               msg='Usuário criado com sucesso.',
                               success=True,
                               form=create_account_form)
    # Renderizar formulário de registro
    else:
        return render_template('accounts/register.html', form=create_account_form)

# Endpoint para autenticação via JWT (JSON Web Tokens)
@api.route('/login/jwt/', methods=['POST'])
class JWTLogin(Resource):
    def post(self):
        try:
            data = request.form

            if not data:
                data = request.json

            if not data:
                return {
                           'message': 'Nome de usuário ou senha está faltando',
                           "data": None,
                           'success': False
                       }, 400
            # Validar entrada
            user = Users.query.filter_by(username=data.get('username')).first()
            if user and verify_pass(data.get('password'), user.password):
                try:

                    # Gerar token se não existir ou estiver vazio
                    if not user.api_token or user.api_token == '':
                        user.api_token = generate_token(user.id)
                        user.api_token_ts = int(datetime.utcnow().timestamp())
                        db.session.commit()

                    # Token deve expirar após 24 horas
                    return {
                        "message": "Token de autenticação obtido com sucesso",
                        "success": True,
                        "data": user.api_token
                    }
                except Exception as e:
                    return {
                               "error": "Algo deu errado",
                               "success": False,
                               "message": str(e)
                           }, 500
            return {
                       'message': 'Nome de usuário ou senha está errado',
                       'success': False
                   }, 403
        except Exception as e:
            return {
                       "error": "Algo deu errado",
                       "success": False,
                       "message": str(e)
                   }, 500

# Rota para logout de usuários
@blueprint.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('authentication_blueprint.login')) 

# Manipulador de erro para acesso não autorizado
@login_manager.unauthorized_handler
def unauthorized_handler():
    return render_template('home/page-403.html'), 403

# Manipulador de erro para acesso proibido (403)
@blueprint.errorhandler(403)
def access_forbidden(error):
    return render_template('home/page-403.html'), 403

# Manipulador de erro para página não encontrada (404)
@blueprint.errorhandler(404)
def not_found_error(error):
    return render_template('home/page-404.html'), 404

# Manipulador de erro interno do servidor (500)
@blueprint.errorhandler(500)
def internal_error(error):
    return render_template('home/page-500.html'), 500


########################### API DE AGENTES ##############################
from flask import render_template, request, jsonify
from datetime import datetime
import base64
import json
import os
import requests

# Função para registro no OSSEC
def register_ossec_agent(name, id_agente):
    ossec_server_address = "ossec"
    ossec_http_auth = "sua_senha_secreta"
    url = f'http://{ossec_server_address}:59347/add'
    headers = {'Authorization': ossec_http_auth, 'Content-Type': 'application/json'}
    data = {'ip': 'any', 'name': f'{name}_{id_agente}'}  # Nome do agente no OSSEC será nome_id

    try:
        # Verifica se o agente já existe
        list_url = f'http://{ossec_server_address}:59347/list'
        response = requests.get(list_url, headers=headers)
        if response.status_code == 200:
            agents_data = response.json().get('agents', '')
            ossec_agent_id = None

            # Processa a string de agentes
            for line in agents_data.split('\n'):
                if f'{name}_{id_agente}' in line:
                    # Extrai o ID do OSSEC (campo após "ID: ")
                    ossec_agent_id = line.split('ID: ')[1].split(',')[0].strip()
                    break

            # Se o agente já existe, remove-o
            if ossec_agent_id:
                delete_url = f'http://{ossec_server_address}:59347/remove/{ossec_agent_id}'
                delete_response = requests.delete(delete_url, headers=headers)
                if delete_response.status_code != 200:
                    print(f'Erro ao remover agente existente: {delete_response.status_code}')
                    return None, None

        # Registra o novo agente
        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 200:
            # Obtém a lista de agentes novamente para encontrar o ID do novo agente
            list_response = requests.get(list_url, headers=headers)
            if list_response.status_code == 200:
                agents_data = list_response.json().get('agents', '')
                for line in agents_data.split('\n'):
                    if f'{name}_{id_agente}' in line:
                        # Extrai o ID do OSSEC do novo agente
                        ossec_agent_id = line.split('ID: ')[1].split(',')[0].strip()
                        break

                if ossec_agent_id:
                    # Extrai a chave de ativação usando o ID do OSSEC
                    key_url = f'http://{ossec_server_address}:59347/extract-key/{ossec_agent_id}'
                    key_response = requests.get(key_url, headers=headers)
                    if key_response.status_code == 200:
                        activation_key = key_response.json().get('key', '')
                        return activation_key, ossec_agent_id  # Retorna a chave e o ID do OSSEC
        return None, None
    except Exception as e:
        print(f'Erro ao registrar agente no OSSEC: {e}')
        return None, None

# Rota para registro no OSSEC
@blueprint.route('/registro-ossec', methods=['POST'])
def registro_ossec():
    data = request.get_json()
    name = data.get('name')
    id_agente = data.get('id')
    chave_ativacao = data.get('chave')

    # Verifica se a chave de ativação do Guardião é válida
    agentes = Agentes.query.all()
    for agente in agentes:
        if agente.chave == chave_ativacao and int(agente.id) == int(id_agente):
            # Registra o agente no OSSEC
            activation_key, ossec_agent_id = register_ossec_agent(name, id_agente)
            if activation_key:
                ossec_server_address = "ossec"
                # Remove a atividade ossec-register da fila após o registro bem-sucedido
                remove_da_fila(id_agente, chave_ativacao, 'ossec-register')
                return jsonify({
                    'status': 'sucesso',
                    'activation_key': activation_key,
                    'ossec_server': ossec_server_address
                }), 200
            else:
                return jsonify({'status': 'falha', 'mensagem': 'Erro ao registrar agente no OSSEC'}), 500
    return jsonify({'status': 'falha', 'mensagem': 'Chave de ativação ou ID do agente inválido'}), 400

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

                    # Cria uma nova entrada no banco de dados
                    nova_vulnerabilidade = Vulnerabilidades(
                        chave=chave_ativacao,
                        id_agente=id_agente,
                        cve_id=cve_id,
                        target=target,
                        status=status,
                        installed_version=installed_version,
                        fixed_version=fixed_version,
                        severity=severity,
                        title=title,
                        description=description,
                        cwe_ids=cwe_ids,
                        cvss=cvss,
                        references=references,
                        published_date=published_date,
                        last_modified_date=last_modified_date
                    )
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

@blueprint.route('/envios', methods=['POST'])
def receber_dados():
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

@blueprint.route('/ping', methods=['POST'])
def ping():
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
@blueprint.route('/registro', methods=['POST'])
def registro():
    supostachave = request.json.get('chave')
    host = request.json.get('host')

    chaves = Chaves.query.all()
    for chave in chaves:
        if supostachave == chave.chave:
            id_agente = registrar_agente(chave.chave, host)
            registrar_atividade(chave.chave, id_agente, 'registro')
            return jsonify({'id_agente': id_agente, 'codigo': codigos['registro']}), 200
    return jsonify({'erro': 'Chave não autorizada', 'codigo': codigos['registro']}), 403

# Rota para download de arquivos
@blueprint.route('/download/<arquivo>', methods=['GET'])
def download(arquivo):
    caminho = 'downloads/' + arquivo
    return send_file(caminho, as_attachment=True)

# Nova rota para download de scripts
@blueprint.route('/download/script/<int:id_agente>/<script_name>', methods=['GET'])
def download_script(id_agente, script_name):
    try:
        # Construir o caminho para o script
        caminho = f'/app/apps/utils/{id_agente}/{script_name}'
        
        # Verificar se o arquivo existe
        if not os.path.exists(caminho):
            return jsonify({'erro': 'Script não encontrado'}), 404
            
        return send_file(caminho, as_attachment=True)
    except Exception as e:
        return jsonify({'erro': str(e)}), 500
