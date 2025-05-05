import os
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class WebScan(Base):
    __tablename__ = 'webscans'

    id = Column(Integer, primary_key=True)
    nome = Column(String(120), nullable=False)
    urls = Column(Text, nullable=False)  # Armazena múltiplas URLs separadas por vírgula
    status = Column(String(50), nullable=False, default='agendado')  # agendado, executando, finalizado, desativado
    recorrencia = Column(String(50), nullable=True)  # ex: 'Nunca', 'Diário', 'Semanal', 'Quinzenal', 'Mensal'
    dias_semana = Column(String(100), nullable=True)  # Armazena os dias da semana como string (ex: "1,3,5" para segunda, quarta e sexta)
    hora_execucao = Column(DateTime, nullable=True)  # Hora específica para execução
    ultima_execucao = Column(DateTime, nullable=True)
    proxima_execucao = Column(DateTime, nullable=True)
    ativo = Column(Boolean, default=True)
    
    # Configurações de autenticação
    autenticado = Column(Boolean, default=False)
    username = Column(String(100), nullable=True)
    password = Column(String(100), nullable=True)
    
    # Configurações do Nuclei
    severidade = Column(String(50), default='medium')  # low, medium, high, critical
    templates = Column(Text, nullable=True)  # Templates específicos do Nuclei
    rate_limit = Column(Integer, default=150)  # Limite de requisições por segundo
    threads = Column(Integer, default=25)  # Número de threads
    timeout = Column(Integer, default=5)  # Timeout em segundos
    retries = Column(Integer, default=1)  # Número de tentativas
    
    usuario_id = Column(Integer, ForeignKey('Users.id'), nullable=False)

    def __repr__(self):
        return f'<WebScan {self.nome}>' 