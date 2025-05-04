# Importações do Flask e extensões relacionadas
from flask import render_template, request, redirect, url_for, flash, send_file
from flask_login import login_required, current_user, login_user, logout_user
from flask_restx import Resource, Api
from flask_dance.contrib.github import github
from jinja2 import TemplateNotFound

# Importações de módulos padrão
import random, string ,os, requests
from datetime import datetime, timedelta

# Importações relacionadas ao banco de dados
from sqlalchemy import or_, desc
from apps import db

# Importações específicas da aplicação
from apps.home import blueprint
from apps.config import API_GENERATOR
from apps.authentication.models import (
    Vulnerabilidades, Atividades, Softwares, Agentes, 
    Chaves, Users, Infos, Fila, WebScan,
    remover_agente, criar_chave, deletar_chave
)

@blueprint.route('/index')
@login_required
def index():
    # Busque todas as chaves e agentes do banco de dados
    chaves = Chaves.query.all()
    agentes = Agentes.query.all()
    vulns = Vulnerabilidades.query.all()
    vulns_criticas = 0
    for vuln in vulns:
        if vuln.severity == 'critical':
            vulns_criticas += 1

    # Inicialize contadores
    total_keys = len(chaves)
    total_agents = len(agentes)
    total_vulns = len(vulns)
    agents_per_key = {}

    # Percorra cada chave no banco de dados
    for chave in chaves:
        # Conte o número de agentes para esta chave
        agents_per_key[chave.nome] = len([agente for agente in agentes if agente.chave == chave.chave])

    return render_template('home/index.html', segment='index', API_GENERATOR=len(API_GENERATOR), total_keys=total_keys, agents_per_key=agents_per_key, total_agents=total_agents, vulns_criticas=vulns_criticas, total_vulns=total_vulns)


@blueprint.route('/guardioes', methods=['GET', 'POST'])
@login_required
def guardioes():
    search = request.form.get('buscar')

    infos = []
    if search:
        search = search.strip()
        infos = Infos.query.filter(or_(Infos.hostname.contains(search), Infos.ip_externo.contains(search), Infos.os_info.contains(search))).all()
    else:
        infos = Infos.query.all()

    # Convertendo os objetos Infos em dicionários
    infos = [info.__dict__ for info in infos]

    segment = get_segment(request)
    return render_template('home/guardioes.html', segment=segment, infos=infos)

@blueprint.route('/guardiao/<int:id>', methods=['GET', 'POST'])
@login_required
def guardiao(id):
    search = request.form.get('search')

    vulns = Vulnerabilidades.query.filter(Vulnerabilidades.id_agente.like(f"%{id}%"))
    #vulns = vulns.filter(Vulnerabilidades.vuln_status.like(f"confirmed"))

    if search:
        vulns = vulns.filter(or_(Vulnerabilidades.cve_id.like(f"%{search}%"), Vulnerabilidades.cpe.like(f"%{search}%"), Vulnerabilidades.severity.like(f"%{search}%"))).all()

    infos = Infos.query.filter(Infos.id_agente.like(id)).all()

    infos = [info.__dict__ for info in infos]
    
    vulns = [v.to_dict() for v in vulns]

    segment = get_segment(request)
    return render_template('home/perfil_agente.html', segment=segment, infos=infos[0], vulns=vulns)

@blueprint.route('/remove_agent/<int:agent_id>', methods=['GET'])
def remove_agent_route(agent_id):
    try:
        # Check if user is authenticated
        if not current_user.is_authenticated:
            return redirect(url_for('home_api.login'))
            
        # Get the agent from database
        agent = Agentes.query.filter_by(id=agent_id).first()
        
        if not agent:
            return render_template('home/page-404.html', 
                                  error="Agente não encontrado"), 404
        
        # Call the remover_agente function that was imported
        success = remover_agente(agent_id)
        
        if success:
            # Log the activity
            nova_atividade = Atividades(
                agente_id=agent_id,
                tipo="remocao",
                descricao=f"Agente {agent.hostname} removido manualmente",
                data=datetime.utcnow()
            )
            db.session.add(nova_atividade)
            db.session.commit()
            
            # Redirect to the agents list with success message
            return redirect(url_for('home_api.agentes', 
                                   msg="Agente removido com sucesso"))
        else:
            # If removal failed, redirect with error message
            return redirect(url_for('home_api.agentes', 
                                   error="Falha ao remover o agente"))
            
    except Exception as e:
        print(f"Erro ao remover agente: {str(e)}")
        return render_template('home/page-500.html', 
                              error=f"Erro ao remover agente: {str(e)}"), 500

# Rota para realizar um scan on demand em um guardião
@blueprint.route('/scan_on_demand/<int:id>', methods=['GET', 'POST'])
@login_required
def scan_on_demand(id):
    # Consulta o agente pelo ID
    agente = Agentes.query.get_or_404(id)
    
    # Consulta a fila para verificar se já existe um scan pendente para este agente
    scan_na_fila = Fila.query.filter_by(id_agente=id, fila='vuln-scan').first()
    
    # Consulta a tabela de Atividades para obter o último scan realizado
    ultimo_scan = Atividades.query.filter_by(id_agente=id, atividade='vuln-scan').order_by(desc(Atividades.data_contato)).first()
    
    # Verifica se o último scan foi realizado nos últimos 5 minutos
    scan_recente = False
    if ultimo_scan:
        tempo_decorrido = datetime.now() - ultimo_scan.data_contato
        if tempo_decorrido < timedelta(minutes=5):
            scan_recente = True
    
    # Se o método for POST, verifica se é para forçar um novo scan
    if request.method == 'POST':
        force = request.form.get('force') == 'true'  # Verifica se o parâmetro force foi enviado
        
        # Se não houver scan na fila OU se for para forçar um novo scan
        if not scan_na_fila or force:
            novo_scan = Fila(id_agente=id, chave=agente.chave, fila='vuln-scan', data_registro=datetime.now())
            db.session.add(novo_scan)
            db.session.commit()
            flash('Novo scan agendado com sucesso!', 'success')
        else:
            flash('Já existe um scan pendente. Use "Forçar Novo Scan" para ignorar essa restrição.', 'warning')
        
        return redirect(url_for('home_blueprint.scan_on_demand', id=id))
    
    # Renderiza o template com as informações necessárias
    return render_template('home/scan_on_demand.html', 
                           id=id, 
                           scan_na_fila=scan_na_fila, 
                           ultimo_scan=ultimo_scan, 
                           scan_recente=scan_recente)

# Rota para executar o scripts personalizados
@blueprint.route('/run_script/<int:id>', methods=['GET','POST'])
@login_required
def run_script(id):
    agente = Agentes.query.get_or_404(id)
    path = f'apps/utils/{id}'
    if not os.path.exists(path):
        os.makedirs(path)
    if request.method == 'POST':
        script_name = request.form['script_name']
        script = request.form['script']
        #salva o script na pasta /app/apps/utils
        with open(f'{path}/{script_name}', 'w') as file:
            file.write(script)
        atividade = Fila(id_agente=id, chave=agente.chave, fila='script', data_registro=datetime.now(), script_name=script_name)
        db.session.add(atividade)
        db.session.commit()
        flash('Script salvo com sucesso!', 'success')
        return redirect(url_for('home_blueprint.run_script', id=id))
    return render_template('home/run_script.html', agente=agente)

@blueprint.route('/vulns', methods=['GET', 'POST'])
@login_required
def vulns3():
    search_query = Vulnerabilidades.query
    search = request.form.get('buscar')

    if search:
        search = search.strip()
        search_query = search_query.filter(or_(Vulnerabilidades.cve_id.contains(search), Vulnerabilidades.description.contains(search), Vulnerabilidades.severity.contains(search), Vulnerabilidades.id_agente.contains(search), Vulnerabilidades.cvss.contains(search)))
    
    #search_query = search_query.filter(Vulnerabilidades.status.like(f"confirmed"))
    search_query = search_query.group_by(Vulnerabilidades.cve_id, Vulnerabilidades.id_agente, Vulnerabilidades.title)
    
    search_results = search_query.all()[:100]
    
    return render_template('home/vulns.html', segment='vulns', chaves=chaves, vulns=search_results)

####################### Criação e visualização de chaves de ambiente ##############################

@blueprint.route('/ambientes')
@login_required
def chaves():
    chaves = Chaves.query.all()
    return render_template('home/ambientes.html', segment='ambientes', chaves=chaves)

@blueprint.route('/criar-chave', methods=['POST'])
@login_required
def criar():
    nome = request.form['nome']
    chave = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(48)).upper()
    tags = request.form['tags']
    limite_agentes = int(request.form['limite_agentes'])
    data_expiracao = datetime.strptime(request.form['data_expiracao'], '%Y-%m-%d') if request.form['data_expiracao'] else None
    status = request.form['status']

    criar_chave(nome, chave, tags, limite_agentes, data_expiracao, status)

    return redirect('/ambientes')

@blueprint.route('/deletar-chave', methods=['POST'])
@login_required
def deletar():
    chave = request.form.get('chave')
    print(chave)

    deletar_chave(chave)

    return redirect('/ambientes')


####################################################################################################

@blueprint.route('/<template>')
@login_required
def route_template(template):

    try:

        if not template.endswith('.html'):
            template += '.html'

        # Detect the current page
        segment = get_segment(request)

        # Serve the file (if exists) from app/templates/home/FILE.html
        return render_template("home/" + template, segment=segment, API_GENERATOR=len(API_GENERATOR))

    except TemplateNotFound:
        return render_template('home/page-404.html'), 404

    except:
        return render_template('home/page-500.html'), 500


# Helper - Extract current page name from request
def get_segment(request):

    try:

        segment = request.path.split('/')[-1]

        if segment == '':
            segment = 'index'

        return segment

    except:
        return None


# Helper function to call OSSEC API
def call_ossec_api(endpoint, method='GET', data=None):
    api_url = "http://ossec:59347"  # Assuming 'ossec' is the service name in docker-compose
    api_password = os.getenv("API_PASSWORD", "sua_senha_secreta")
    
    headers = {
        "Authorization": api_password,
        "Content-Type": "application/json"
    }
    
    try:
        if method == 'GET':
            response = requests.get(f"{api_url}/{endpoint}", headers=headers, timeout=10)
        elif method == 'POST':
            response = requests.post(f"{api_url}/{endpoint}", headers=headers, json=data, timeout=10)
        elif method == 'DELETE':
            response = requests.delete(f"{api_url}/{endpoint}", headers=headers, timeout=10)
        else:
            return {"error": "Method not supported"}
        
        if response.status_code != 200:
            return {"error": f"API returned status code {response.status_code}: {response.text}"}
        
        return response.json()
    except requests.exceptions.ConnectionError:
        return {"error": "Could not connect to OSSEC API. Make sure the service is running."}
    except requests.exceptions.Timeout:
        return {"error": "Connection to OSSEC API timed out."}
    except Exception as e:
        return {"error": str(e)}

@blueprint.route('/agents-status', methods=['GET', 'POST'])
@login_required
def agents_status():
    search = request.form.get('buscar')
    
    # Get agents from OSSEC API
    ossec_agents_data = call_ossec_api('status')
    
    if 'error' in ossec_agents_data:
        flash(f"Erro ao conectar com a API do OSSEC: {ossec_agents_data['error']}", "error")
        agents_data = []
    else:
        agents_data = ossec_agents_data.get('agents', [])
    
    # Apply search filter if provided
    if search:
        search = search.lower().strip()
        agents_data = [agent for agent in agents_data 
                      if search in agent.get('id', '').lower() or 
                         search in agent.get('name', '').lower() or 
                         search in agent.get('ip', '').lower()]
    
    # Format the data for the template
    agents = []
    agent_activities = {}
    agent_infos = {}
    
    for agent in agents_data:
        agent_id = agent.get('id')
        if agent_id:
            agents.append({"id": agent_id})
            
            # Last activity info
            last_keepalive = agent.get('last_keepalive', 'Nunca conectado')
            status = agent.get('status', 'Desconhecido')
            
            # Check if last_keepalive is a valid datetime string
            if last_keepalive and last_keepalive != 'Unknown' and last_keepalive != 'Nunca conectado':
                try:
                    last_contact = datetime.strptime(last_keepalive, '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    last_contact = "Unknown"
            else:
                last_contact = "Unknown"
            
            agent_activities[agent_id] = {
                'last_contact': last_contact,
                'activity_type': status
            }
            
            # Agent info
            agent_infos[agent_id] = {
                'hostname': agent.get('name', 'Desconhecido'),
                'ip': agent.get('ip', 'Desconhecido'),
                'os': agent.get('os', 'Desconhecido')
            }
    
    segment = get_segment(request)
    return render_template('home/agents_status.html', 
                          segment=segment, 
                          agents=agents, 
                          activities=agent_activities,
                          infos=agent_infos,
                          now=datetime.now())  # Pass current datetime as 'now'

@blueprint.route('/ossec-alerts', methods=['GET', 'POST'])
@login_required
def ossec_alerts():
    search = request.form.get('buscar')
    
    # Get alerts from OSSEC API
    ossec_alerts_data = call_ossec_api('alerts')
    
    if 'error' in ossec_alerts_data:
        flash(f"Erro ao conectar com a API do OSSEC: {ossec_alerts_data['error']}", "error")
        alerts = []
    else:
        alerts = ossec_alerts_data.get('alerts', [])
    
    # Apply search filter if provided
    if search:
        search = search.lower().strip()
        alerts = [alert for alert in alerts if 
                 search in alert.get('full_log', '').lower() or
                 search in alert.get('description', '').lower() or
                 search in alert.get('rule', '').lower() or
                 search in alert.get('src_ip', '').lower()]
    
    # Limit to the most recent 100 alerts
    alerts = alerts[-100:] if len(alerts) > 100 else alerts
    alerts.reverse()  # Most recent first
    
    segment = get_segment(request)
    return render_template('home/ossec_alerts.html', segment=segment, alerts=alerts)



########## Páginas web do WAS #############
from apps.authentication.models import WebScan

# Página de gerenciamento de scans web
@blueprint.route('/webscans')
def webscans():
    scans = WebScan.query.filter_by(usuario_id=current_user.id).all()
    segment = 'webscans'
    return render_template('home/webscans.html', scans=scans, segment=segment)

# Página para criar novo scan
@blueprint.route('/webscans/novo', methods=['GET', 'POST'])
def novo_webscan():
    if request.method == 'POST':
        nome = request.form['nome']
        url = request.form['url']
        recorrencia = request.form['recorrencia']
        hora_execucao_str = request.form.get('hora_execucao')
        
        # Processar dias da semana (checkboxes)
        dias_semana = request.form.getlist('dias_semana')
        dias_semana_str = ','.join(dias_semana) if dias_semana else None
        
        # Converter hora de execução para objeto Time
        hora_execucao = None
        if hora_execucao_str:
            from datetime import datetime, time
            hora, minuto = hora_execucao_str.split(':')
            hora_execucao = time(int(hora), int(minuto))
        
        # Calcular próxima execução com base na recorrência e dias selecionados
        proxima_execucao = None
        if recorrencia != 'Nunca' and hora_execucao:
            from datetime import datetime, timedelta
            agora = datetime.now()
            
            # Definir a próxima execução com base na hora especificada
            proxima_execucao = datetime.combine(agora.date(), hora_execucao)
            
            # Se a hora já passou hoje, avançar para o próximo dia
            if proxima_execucao < agora:
                proxima_execucao += timedelta(days=1)
            
            # Para recorrência semanal, quinzenal ou mensal, encontrar o próximo dia da semana válido
            if recorrencia in ['Semanal', 'Quinzenal', 'Mensal'] and dias_semana:
                # Converter dias da semana para inteiros
                dias_int = [int(dia) for dia in dias_semana]
                
                # Encontrar o próximo dia da semana válido
                dias_para_adicionar = 0
                while proxima_execucao.weekday() not in dias_int:
                    proxima_execucao += timedelta(days=1)
                    dias_para_adicionar += 1
                    if dias_para_adicionar > 7:  # Evitar loop infinito
                        break
        
        scan = WebScan(
            nome=nome,
            url=url,
            recorrencia=recorrencia,
            dias_semana=dias_semana_str,
            hora_execucao=hora_execucao,
            proxima_execucao=proxima_execucao,
            usuario_id=current_user.id
        )
        db.session.add(scan)
        db.session.commit()
        return redirect(url_for('home_blueprint.webscans'))
    return render_template('home/novo_webscan.html')

# Editar scan
@blueprint.route('/webscans/editar/<int:id>', methods=['GET', 'POST'])
def editar_webscan(id):
    scan = WebScan.query.get_or_404(id)
    if request.method == 'POST':
        scan.nome = request.form['nome']
        scan.url = request.form['url']
        scan.recorrencia = request.form['recorrencia']
        
        # Processar dias da semana (checkboxes)
        dias_semana = request.form.getlist('dias_semana')
        scan.dias_semana = ','.join(dias_semana) if dias_semana else None
        
        # Processar hora de execução
        hora_execucao_str = request.form.get('hora_execucao')
        if hora_execucao_str:
            from datetime import time
            hora, minuto = hora_execucao_str.split(':')
            scan.hora_execucao = time(int(hora), int(minuto))
        else:
            scan.hora_execucao = None
        
        # Recalcular próxima execução
        if scan.recorrencia != 'Nunca' and scan.hora_execucao:
            from datetime import datetime, timedelta
            agora = datetime.now()
            
            # Definir a próxima execução com base na hora especificada
            proxima_execucao = datetime.combine(agora.date(), scan.hora_execucao)
            
            # Se a hora já passou hoje, avançar para o próximo dia
            if proxima_execucao < agora:
                proxima_execucao += timedelta(days=1)
            
            # Para recorrência semanal, quinzenal ou mensal, encontrar o próximo dia da semana válido
            if scan.recorrencia in ['Semanal', 'Quinzenal', 'Mensal'] and scan.dias_semana:
                # Converter dias da semana para inteiros
                dias_int = [int(dia) for dia in scan.dias_semana.split(',')]
                
                # Encontrar o próximo dia da semana válido
                dias_para_adicionar = 0
                while proxima_execucao.weekday() not in dias_int:
                    proxima_execucao += timedelta(days=1)
                    dias_para_adicionar += 1
                    if dias_para_adicionar > 7:  # Evitar loop infinito
                        break
            
            scan.proxima_execucao = proxima_execucao
        else:
            scan.proxima_execucao = None
        
        db.session.commit()
        return redirect(url_for('home_blueprint.webscans'))
    
    # Preparar dias da semana para o template
    dias_semana = scan.dias_semana.split(',') if scan.dias_semana else []
    
    return render_template('home/editar_webscan.html', scan=scan, dias_semana=dias_semana)

# Desativar scan
@blueprint.route('/webscans/desativar/<int:id>', methods=['POST'])
def desativar_webscan(id):
    scan = WebScan.query.get_or_404(id)
    scan.ativo = False
    scan.status = 'desativado'
    db.session.commit()
    return redirect(url_for('home_blueprint.webscans'))

@blueprint.route('/webscans/ativar/<int:id>', methods=['POST'])
def ativar_webscan(id):
    scan = WebScan.query.get_or_404(id)
    scan.ativo = True
    scan.status = 'agendado'
    
    # Recalcular próxima execução
    if scan.recorrencia != 'Nunca' and scan.hora_execucao:
        from datetime import datetime, timedelta
        agora = datetime.now()
        
        # Definir a próxima execução com base na hora especificada
        proxima_execucao = datetime.combine(agora.date(), scan.hora_execucao)
        
        # Se a hora já passou hoje, avançar para o próximo dia
        if proxima_execucao < agora:
            proxima_execucao += timedelta(days=1)
        
        # Para recorrência semanal, quinzenal ou mensal, encontrar o próximo dia da semana válido
        if scan.recorrencia in ['Semanal', 'Quinzenal', 'Mensal'] and scan.dias_semana:
            # Converter dias da semana para inteiros
            dias_int = [int(dia) for dia in scan.dias_semana.split(',')]
            
            # Encontrar o próximo dia da semana válido
            dias_para_adicionar = 0
            while proxima_execucao.weekday() not in dias_int:
                proxima_execucao += timedelta(days=1)
                dias_para_adicionar += 1
                if dias_para_adicionar > 7:  # Evitar loop infinito
                    break
        
        scan.proxima_execucao = proxima_execucao
    
    db.session.commit()
    return redirect(url_for('home_blueprint.webscans'))

# Clonar scan
@blueprint.route('/webscans/clonar/<int:id>', methods=['POST'])
def clonar_webscan(id):
    scan = WebScan.query.get_or_404(id)
    novo_scan = WebScan(
        nome=scan.nome + ' (Clone)',
        url=scan.url,
        status='agendado',
        recorrencia=scan.recorrencia,
        dias_semana=scan.dias_semana,
        hora_execucao=scan.hora_execucao,
        proxima_execucao=scan.proxima_execucao,
        usuario_id=scan.usuario_id
    )
    db.session.add(novo_scan)
    db.session.commit()
    return redirect(url_for('home_blueprint.webscans'))

# Excluir scan
@blueprint.route('/webscans/excluir/<int:id>', methods=['POST'])
def excluir_webscan(id):
    scan = WebScan.query.get_or_404(id)
    db.session.delete(scan)
    db.session.commit()
    return redirect(url_for('home_blueprint.webscans'))




