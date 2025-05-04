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


# Modificar a inicialização da API para incluir configurações adicionais
api = Api(blueprint,
          version='1.0',
          title='API Guardião',
          description='API para comunicação com agentes Guardião',
          doc='/doc/',
          default='api',
          default_label='Endpoints da API Guardião')

# Códigos de resposta para as operações
codigos = {'registro': 1, 'ping': 2, 'upload': 3}

# Função para registro no OSSEC
def register_ossec_agent(name, id_agente):
    """
    Registra um agente no servidor OSSEC.
    
    Args:
        name: Nome do agente
        id_agente: ID do agente no sistema Guardião
        
    Returns:
        Tupla contendo (ossec_agent_id, ossec_hostname, activation_key) ou (None, None, None) em caso de falha
    """
    ossec_server_address = "ossec"
    ossec_http_auth = "sua_senha_secreta"
    url = f'http://{ossec_server_address}:59347/add'
    headers = {
        'Authorization': ossec_http_auth,
        'Content-Type': 'application/json'
    }
    
    # Garante que nome e id_agente são strings
    name = str(name) if name else "unknown"
    id_agente = str(id_agente) if id_agente else "0"
    
    # Cria um hostname único para registro no OSSEC
    ossec_hostname = f"{name}_{id_agente}"
    data = {
        'ip': 'any',
        'name': ossec_hostname
    }

    try:
        # Registra novo agente
        response = requests.post(url, headers=headers, json=data)
        print(response.text)
        print(response.status_code)
        print(response.headers)
        
        if response.status_code == 200:
            response_data = response.json()
            if response_data.get('status') == 'success':
                ossec_agent_id = str(response_data.get('id'))
                key_response = response_data.get('key', '')
                
                # Extrai a chave real da resposta
                key_match = re.search(r"Agent key information for '\d+':\s+(\S+)", key_response)
                activation_key = key_match.group(1) if key_match else key_response
                
                print(f"Agente OSSEC registrado com sucesso. ID: {ossec_agent_id}")
                return ossec_agent_id, ossec_hostname, activation_key

        print(f"Falha ao registrar agente OSSEC. Status: {response.status_code}")
        return None, None, None

    except Exception as e:
        print(f"Exceção ocorrida durante o registro OSSEC: {str(e)}")
        return None, None, None

def normalizar_data_iso(data_str):
    """
    Normaliza uma string de data ISO 8601 para garantir que os milissegundos tenham três dígitos.
    
    Args:
        data_str: String de data no formato ISO
        
    Returns:
        String de data normalizada ou None
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
    """
    Decodifica uma string em base64.
    
    Args:
        encoded_string: String codificada em base64
        
    Returns:
        String decodificada
    """
    decoded_bytes = base64.b64decode(encoded_string.encode('utf-8'))
    decoded_string = decoded_bytes.decode('utf-8')
    return decoded_string

# Registra nova atividade de agente
def registrar_atividade(chave, id_agente, atividade):
    """
    Registra uma atividade do agente no banco de dados
    
    Args:
        chave (str): Chave de ativação do agente
        id_agente (str ou int): ID do agente
        atividade (str): Tipo de atividade realizada
    
    Returns:
        bool: True se o registro foi bem-sucedido, False caso contrário
    """
    try:
        # Validação dos parâmetros
        if not chave or not isinstance(chave, str) or chave.strip() == '':
            print(f"[ERRO] Falha ao registrar atividade: Chave vazia ou inválida. Valor recebido: '{chave}'")
            return False
            
        if id_agente is None or (isinstance(id_agente, str) and id_agente.strip() == ''):
            print(f"[ERRO] Falha ao registrar atividade: ID do agente vazio ou inválido. Valor recebido: '{id_agente}'")
            return False
            
        if not atividade or not isinstance(atividade, str) or atividade.strip() == '':
            print(f"[ERRO] Falha ao registrar atividade: Atividade vazia ou inválida. Valor recebido: '{atividade}'")
            return False
        
        # Converte id_agente para string se for um número
        if isinstance(id_agente, int):
            id_agente = str(id_agente)
            
        data_contato = datetime.now()
        nova_atividade = Atividades(chave=chave, id_agente=id_agente, data_contato=data_contato, atividade=atividade)
        salvar_no_banco(nova_atividade)
        return True
    except Exception as e:
        print(f"[ERRO] Exceção ao registrar atividade: {str(e)}")
        return False

def salvar_dados_db(chave_ativacao, id_agente, payload, tipo, mensagem=None):
    """
    Salva dados recebidos dos agentes no banco de dados.
    
    Args:
        chave_ativacao: Chave de ativação do agente
        id_agente: ID do agente
        payload: Dados recebidos
        tipo: Tipo de dados (softwares, infos, vuln-scan, script-resultado)
        mensagem: Mensagem completa recebida (opcional)
    """
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
    @api.doc('post_envios')
    def post(self):
        """
        Endpoint para receber dados dos agentes
        """
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
                    return {'status': 'sucesso'}, 200
        return {'status': 'falha', 'mensagem': 'Chave de ativação ou ID do agente não encontrado'}, 400

# Rota para download de arquivos
@api.route('/download/<arquivo>', methods=['GET'])
class Download(Resource):
    @api.doc('get_download')
    def get(self, arquivo):
        """
        Endpoint para download de arquivos como install.sh e uninstall.sh
        """
        try:
            # Diretório onde os arquivos estão armazenados
            download_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../downloads')
            
            # Criar o diretório se não existir
            if not os.path.exists(download_dir):
                os.makedirs(download_dir)
                print(f"Diretório de downloads criado: {download_dir}")
            
            # Verificar se o arquivo solicitado existe
            arquivo_path = os.path.join(download_dir, arquivo)
            if not os.path.exists(arquivo_path):
                print(f"Arquivo não encontrado: {arquivo_path}")
                return {"erro": f"Arquivo {arquivo} não encontrado"}, 404
                
            # Retornar o arquivo para download
            print(f"Enviando arquivo: {arquivo_path}")
            return send_file(arquivo_path, as_attachment=True)
            
        except Exception as e:
            print(f"Erro ao processar o download: {str(e)}")
            return {"erro": f"Erro ao processar o download: {str(e)}"}, 500

# Rota para download de scripts
@api.route('/download/script/<int:id_agente>/<script_name>')
class DownloadScript(Resource):
    @api.doc('get_download_script')
    def get(self, id_agente, script_name):
        """
        Endpoint para download de scripts específicos para um agente
        """
        try:
            # Construir o caminho para o script
            caminho = f'/app/apps/utils/{id_agente}/{script_name}'
            
            # Verificar se o arquivo existe
            if not os.path.exists(caminho):
                return {'erro': 'Script não encontrado'}, 404
                
            return send_file(caminho, as_attachment=True)
        except Exception as e:
            return {'erro': str(e)}, 500

@api.route('/ping', methods=['GET', 'POST'])
class Ping(Resource):
    @api.doc('get_ping')
    def get(self):
        """
        Endpoint para verificar se o servidor está online (GET)
        """
        return {"status": "online", "codigo": codigos['ping']}, 200
        
    @api.doc('post_ping')
    def post(self):
        """
        Endpoint para verificar se o servidor está online (POST) e verificar atividades pendentes
        """
        # Obter dados do JSON, se houver
        data = request.get_json(silent=True) or {}
        
        # Verificar se há uma chave de agente
        chave = data.get('chave')
        id_agente = data.get('id')
        
        # Resposta padrão quando não há atividades pendentes
        resposta = {
            "mensagem": "Não há atividades pendentes na fila.", 
            "fila": None, 
            'codigo': codigos['ping']
        }
        
        # Se tiver chave e ID, registrar atividade e verificar fila
        if chave and id_agente:
            try:
                # Registra a atividade de ping
                registrar_atividade(chave, id_agente, 'ping')
                
                # Verifica se o agente existe
                agente = Agentes.query.filter_by(chave=chave, id=id_agente).first()
                if agente:
                    # Verifica se há atividades pendentes na fila
                    atividades_pendentes = Fila.query.filter_by(chave=chave, id_agente=id_agente).all()
                    
                    for atividade in atividades_pendentes:
                        resposta = {
                            "mensagem": "Há atividades pendentes na fila.",
                            "fila": atividade.fila,
                            'codigo': codigos['ping']
                        }
                        
                        # Adiciona o nome do script se a atividade for do tipo script
                        if atividade.fila == 'script':
                            resposta['script_name'] = atividade.script_name
                        
                        # Retorna a primeira atividade encontrada
                        return resposta, 200
            except Exception as e:
                print(f"Erro ao processar ping: {str(e)}")
        
        # Retorna a resposta padrão se não houver atividades pendentes
        return resposta, 200

# Rota para registro de novos agentes
@api.route('/registro')
class Registro(Resource):
    @api.doc('post_registro')
    def post(self):
        """
        Endpoint para registrar novos agentes no sistema
        """
        supostachave = request.json.get('chave')
        host = request.json.get('host')

        chaves = Chaves.query.all()
        for chave in chaves:
            if supostachave == chave.chave:
                id_agente = registrar_agente(chave.chave, host)
                if id_agente is not None:
                    # Só registra a atividade se o id_agente for válido
                    registrar_atividade(chave.chave, id_agente, 'registro')
                    return {'status': 'sucesso', 'id': id_agente, 'codigo': codigos['registro']}, 200
                else:
                    return {'status': 'erro', 'mensagem': 'Falha ao registrar agente', 'codigo': codigos['registro']}, 500
        return {'erro': 'Chave não autorizada', 'codigo': codigos['registro']}, 403

@api.route('/remove_agent/<int:id_agente>')
class RemoveAgent(Resource):
    @api.doc('get_remove_agent')
    def get(self, id_agente):
        """
        Endpoint para exibir a página de confirmação de remoção de agente
        """
        try:
            # Verifica se o usuário está autenticado
            if not current_user.is_authenticated:
                return redirect(url_for('authentication_api.login'))
                
            # Obtém o agente do banco de dados
            agent = Agentes.query.filter_by(id=id_agente).first()
            
            if not agent:
                return render_template('home/page-404.html', error="Agente não encontrado"), 404
            
            # Obtém informações do agente para exibição
            agent_info = Infos.query.filter_by(id_agente=id_agente).first()
            
            if not agent_info:
                return render_template('home/page-404.html', error="Informações do agente não encontradas"), 404
            
            # Mostra página de confirmação
            return render_template('home/remove_agent.html', agent=agent, agent_info=agent_info)
                
        except Exception as e:
            print(f"Erro ao preparar remoção do agente: {str(e)}")
            return render_template('home/page-500.html', error=f"Erro ao preparar remoção do agente: {str(e)}"), 500

@api.route('/confirm_remove_agent/<int:id_agente>')
class ConfirmRemoveAgent(Resource):
    @api.doc('post_confirm_remove_agent')
    def post(self, id_agente):
        """
        Endpoint para confirmar a remoção de um agente
        """
        try:
            # Verifica se o usuário está autenticado
            if not current_user.is_authenticated:
                return redirect(url_for('authentication_api.login'))
                
            # Remove o agente
            resultado = remover_agente(id_agente)
            
            if resultado:
                # Redireciona para a página de agentes com mensagem de sucesso
                return redirect(url_for('home_blueprint.agentes'))
            else:
                # Exibe página de erro
                return render_template('home/page-500.html', error="Falha ao remover agente"), 500
                
        except Exception as e:
            print(f"Erro ao remover agente: {str(e)}")
            return render_template('home/page-500.html', error=f"Erro ao remover agente: {str(e)}"), 500

@api.route('/registro-ossec', methods=['POST'])
class RegistroOssec(Resource):
    @api.doc('post_registro_ossec')
    def post(self):
        """
        Endpoint para registrar novos agentes no sistema
        """
        supostachave = request.json.get('chave')
        host = request.json.get('name')  # Usa o name se fornecido, senão usa o host


        chaves = Chaves.query.all()
        for chave in chaves:
            if supostachave == chave.chave:
                id_agente = registrar_agente(chave.chave, host)
                registrar_atividade(chave.chave, id_agente, 'registro')
                
                # Registrar no OSSEC e obter informações
                ossec_id, ossec_hostname, ossec_key = register_ossec_agent(host, id_agente)
                
                # Retornar resposta no formato esperado pelo cliente
                return {
                    'status': 'sucesso',
                    'id_agente': id_agente,
                    'ossec_server': 'ossec',  # Endereço do servidor OSSEC
                    'ossec_id': ossec_id,
                    'ossec_hostname': ossec_hostname,
                    'chave_ossec': ossec_key,
                    'codigo': codigos['registro']
                }, 200
                
        return {'erro': 'Chave não autorizada', 'codigo': codigos['registro']}, 403
