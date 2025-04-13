# -*- encoding: utf-8 -*-

from flask_login import UserMixin
from datetime import datetime

from sqlalchemy.orm import relationship
from flask_dance.consumer.storage.sqla import OAuthConsumerMixin

from apps import db, login_manager

from apps.authentication.util import hash_pass

from sqlalchemy import Column, Integer, String, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
import json

Base = declarative_base()

#Usuários
class Users(db.Model, UserMixin):

    __tablename__ = 'Users'

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(64), unique=True)
    email         = db.Column(db.String(64), unique=True)
    password      = db.Column(db.LargeBinary)

    oauth_github  = db.Column(db.String(100), nullable=True)

    api_token     = db.Column(db.String(100))
    api_token_ts  = db.Column(db.Integer)    

    def __init__(self, **kwargs):
        for property, value in kwargs.items():
            # depending on whether value is an iterable or not, we must
            # unpack it's value (when **kwargs is request.form, some values
            # will be a 1-element list)
            if hasattr(value, '__iter__') and not isinstance(value, str):
                # the ,= unpack of a singleton fails PEP8 (travis flake8 test)
                value = value[0]

            if property == 'password':
                value = hash_pass(value)  # we need bytes here (not plain str)

            setattr(self, property, value)

    def __repr__(self):
        return str(self.username)

# Chaves de ativação
class Chaves(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(80), nullable=False)
    chave = db.Column(db.String(120), unique=True, nullable=False)
    tags = db.Column(db.String(120), nullable=True)
    limite_agentes = db.Column(db.Integer, nullable=False)
    data_expiracao = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(10), nullable=False)

    def __repr__(self):
        return '<Chave %r>' % self.nome

# Registro de agentes
class Agentes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chave = db.Column(db.String(120), nullable=False)
    host = db.Column(db.String(120), nullable=False)
    data_ativacao = db.Column(db.DateTime, nullable=False)
    ossec_registered = db.Column(db.Boolean, default=False, nullable=False)
    ossec_id = db.Column(db.String(120), nullable=True)
    ossec_hostname = db.Column(db.String(120), nullable=True)

    def __repr__(self):
        return '<Agente %r>' % self.id
    
# Registro de agentes
class Fila(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_agente = db.Column(db.Integer, nullable=False)
    chave = db.Column(db.String(120), nullable=False)
    fila = db.Column(db.String(20), nullable=False)
    script_name = db.Column(db.String(120), nullable=True)
    data_registro = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return '<Atividade %r>' % self.id

# Registro de atividades
class Atividades(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chave = db.Column(db.String(120), nullable=False)
    id_agente = db.Column(db.String(120), nullable=False)
    data_contato = db.Column(db.DateTime, nullable=False)
    atividade = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return '<Atividade %r>' % self.id

# Registro de softwares
class Softwares(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chave = db.Column(db.String(120), nullable=False)
    id_agente = db.Column(db.String(120), nullable=False)
    data_contato = db.Column(db.DateTime, nullable=False)
    software = db.Column(db.String(120), nullable=False)
    versao = db.Column(db.String(120), nullable=False)
    desenvolvedor = db.Column(db.String(120), nullable=True)
    local = db.Column(db.String(250), nullable=True)
    modificacao = db.Column(db.String(120), nullable=True)
    assinatura = db.Column(db.String(120), nullable=True)
    descricao = db.Column(db.String(120), nullable=True)

    def __repr__(self):
        return '<Atividade %r>' % self.id
    
class Infos(db.Model):
    __tablename__ = 'infos'

    id = Column(Integer, primary_key=True)
    chave = db.Column(db.String(120), nullable=False)
    id_agente = db.Column(db.String(120), nullable=False)
    hostname = Column(String(120))
    ip_externo = Column(String(120))
    os_info = Column(String(120))
    ip_info = Column(JSON)
    all_users = Column(JSON)
    ram_info = Column(JSON)
    manufacturer = Column(String(120))
    model = Column(String(120))
    disk_info = Column(JSON)
    cpu_info = Column(JSON)

    def __init__(self, data):
        self.chave = data['chave']
        self.id_agente = data['id_agente']
        self.hostname = data['hostname']
        self.ip_externo = data['ip_externo']
        self.os_info = data['os_info']
        self.ip_info = data['ip_info']
        self.all_users = data['all_users']
        self.ram_info = data['ram_info']
        self.manufacturer = data['manufacturer']
        self.model = data['model']
        self.disk_info = data['disk_info']
        self.cpu_info = data['cpu_info']

class CpeHml(db.Model):
    __tablename__ = 'cpehml'

    id = Column(Integer, primary_key=True)
    software = db.Column(db.String(120), nullable=False)
    cpe = db.Column(db.String(120), nullable=False)
    hml = db.Column(Integer, nullable=False)

    def __init__(self, data):
        self.software = data['software']
        self.cpe = data['cpe']
        self.hml = data['hml']

# Add this to the Vulnerabilidades class if it doesn't already exist
class Vulnerabilidades(db.Model):
    __tablename__ = 'vulnerabilidades'

    id = db.Column(db.Integer, primary_key=True)
    chave = db.Column(db.String(120), nullable=False)
    id_agente = db.Column(db.String(120), nullable=False)
    cve_id = db.Column(db.String(120), nullable=False)
    target = db.Column(db.String(250), nullable=True)
    status = db.Column(db.String(120), nullable=True)
    installed_version = db.Column(db.String(120), nullable=True)
    fixed_version = db.Column(db.String(120), nullable=True)
    severity = db.Column(db.String(120), nullable=True)
    title = db.Column(db.String(250), nullable=True)
    description = db.Column(db.Text, nullable=True)
    cwe_ids = db.Column(JSON, nullable=True)
    cvss = db.Column(JSON, nullable=True)
    references = db.Column(JSON, nullable=True)
    published_date = db.Column(db.DateTime, nullable=True)
    last_modified_date = db.Column(db.DateTime, nullable=True)
    data_atualizacao = db.Column(db.DateTime, nullable=True, default=datetime.utcnow)
    
    # Rest of the class...
    chave = db.Column(db.String(120), nullable=False)  # Chave de ativação do agente
    id_agente = db.Column(db.String(120), nullable=False)  # ID do agente
    cve_id = db.Column(db.String(50), nullable=False)  # ID da CVE (ex: CVE-2022-29526)
    target = db.Column(db.String(500), nullable=False)  # Target onde a vulnerabilidade foi encontrada
    status = db.Column(db.String(50))  # Status da vulnerabilidade (ex: fixed, affected)
    installed_version = db.Column(db.String(100))  # Versão instalada do pacote vulnerável
    fixed_version = db.Column(db.String(100))  # Versão que corrige a vulnerabilidade
    severity = db.Column(db.String(50))  # Severidade da vulnerabilidade (ex: MEDIUM, HIGH)
    title = db.Column(db.String(500))  # Título da vulnerabilidade
    description = db.Column(db.Text)  # Descrição da vulnerabilidade
    cwe_ids = db.Column(db.JSON)  # Lista de CWE IDs (ex: ["CWE-269"])
    cvss = db.Column(db.JSON)  # Dados do CVSS (ex: {"nvd": {"V3Score": 5.3}})
    references = db.Column(db.JSON)  # Lista de referências (ex: URLs)
    published_date = db.Column(db.DateTime)  # Data de publicação da CVE
    last_modified_date = db.Column(db.DateTime)  # Data da última modificação da CVE

    def __init__(self, chave, id_agente, cve_id, target, status, installed_version, fixed_version, severity, title, description, cwe_ids, cvss, references, published_date, last_modified_date):
        self.chave = chave
        self.id_agente = id_agente
        self.cve_id = cve_id
        self.target = target
        self.status = status
        self.installed_version = installed_version
        self.fixed_version = fixed_version
        self.severity = severity
        self.title = title
        self.description = description
        self.cwe_ids = cwe_ids
        self.cvss = cvss
        self.references = references
        self.published_date = published_date
        self.last_modified_date = last_modified_date

    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

def criar_chave(nome, chave, tags, limite_agentes, data_expiracao, status):
    nova_chave = Chaves(nome=nome, chave=chave, tags=tags, limite_agentes=limite_agentes, data_expiracao=data_expiracao, status=status)
    db.session.add(nova_chave)
    db.session.commit()

def remove_da_fila(id_agente, chave, fila):
    agente = Fila.query.filter_by(id_agente=id_agente, chave=chave, fila=fila).first()
    if agente is None:
        return 'Agente não encontrado'
    
    db.session.delete(agente)
    db.session.commit()
    return 'Agente removido com sucesso'

def registrar_agente(chave, host):
    agentes = Agentes.query.all()
    if agentes:
        id_agente = max(agente.id for agente in agentes) + 1
    else:
        id_agente = 1
    data_ativacao = datetime.now()
    acoes=['softwares', 'vuln-scan', 'infos', 'ossec-register']
    for acao in acoes:
        print(id_agente, chave, acao, data_ativacao)
        fila = Fila(id_agente=id_agente, chave=chave, fila=acao, data_registro=data_ativacao)
        salvar_no_banco(fila)
    novo_agente = Agentes(id=id_agente, chave=chave, host=host, data_ativacao=data_ativacao)
    salvar_no_banco(novo_agente)

    return id_agente

def salvar_no_banco(nova_atividade):
    db.session.merge(nova_atividade)
    db.session.commit()

def remover_agente(id_agente):
    """
    Remove um agente e todos os seus dados relacionados do banco de dados
    """
    try:
        # Primeiro, obter as informações do agente antes de excluí-lo
        agente = Agentes.query.filter_by(id=id_agente).first()
        if not agente:
            return False, "Agente não encontrado"
        
        # Remover registros de vulnerabilidades
        Vulnerabilidades.query.filter_by(id_agente=id_agente).delete()
        
        # Remover registros de softwares
        Softwares.query.filter_by(id_agente=id_agente).delete()
        
        # Remover registros de atividades
        Atividades.query.filter_by(id_agente=id_agente).delete()
        
        # Remover registros da fila
        Fila.query.filter_by(id_agente=id_agente).delete()
        
        # Remover informações do agente
        Infos.query.filter_by(id_agente=id_agente).delete()
        
        # Finalmente, remover o agente
        db.session.delete(agente)
        db.session.commit()
        
        return True, "Agente removido com sucesso"
    except Exception as e:
        db.session.rollback()
        return False, f"Erro ao remover agente: {str(e)}"

@login_manager.user_loader
def user_loader(id):
    return Users.query.filter_by(id=id).first()


@login_manager.request_loader
def request_loader(request):
    username = request.form.get('username')
    user = Users.query.filter_by(username=username).first()
    return user if user else None

class OAuth(OAuthConsumerMixin, db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey("Users.id", ondelete="cascade"), nullable=False)
    user = db.relationship(Users)

def deletar_chave(chave_id):
    chave_d = Chaves.query.filter_by(chave=chave_id).first()
    if chave_d:
        db.session.delete(chave_d)
        db.session.commit()
