import os
import json
import time
import redis
import logging
import threading
import traceback
from datetime import datetime, timedelta
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from models import WebScan, ScanResult
import subprocess
import uuid

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/webscan_worker.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('webscan_worker')

# Configurações do banco de dados
DB_ENGINE = os.getenv('DB_ENGINE', 'mysql+pymysql')
DB_USERNAME = os.getenv('DB_USERNAME', 'guardiao')
DB_PASS = os.getenv('DB_PASS', 'guardiao_password')
DB_HOST = os.getenv('DB_HOST', 'mariadb')
DB_PORT = os.getenv('DB_PORT', '3306')
DB_NAME = os.getenv('DB_NAME', 'guardiao_db')

# Configuração do Redis
REDIS_HOST = os.getenv('REDIS_HOST', 'redis')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))

# Configuração do diretório de resultados
RESULTS_DIR = '/var/webscan_results'

class WebScanWorker:
    def __init__(self, worker_id):
        self.worker_id = worker_id
        self.redis_client = None
        self.db_engine = None
        self.Session = None
        self.lock = threading.Lock()
        self.last_status_check = datetime.now()
        self.status_check_interval = 300  # 5 minutos
        
        # Garantir que o diretório de resultados existe
        os.makedirs(RESULTS_DIR, exist_ok=True)
        
        # Inicializar conexões
        self.initialize_connections()

    def initialize_connections(self):
        """Inicializa ou reinicializa as conexões com o banco de dados e Redis"""
        try:
            # Inicializar conexão com Redis
            self.redis_client = redis.Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                decode_responses=True,
                socket_timeout=5,
                socket_connect_timeout=5
            )
            self.redis_client.ping()  # Testa a conexão
            logger.info(f"Worker {self.worker_id}: Conexão com Redis estabelecida com sucesso")

            # Inicializar conexão com o banco de dados
            connection_string = f'{DB_ENGINE}://{DB_USERNAME}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}'
            logger.info(f"Worker {self.worker_id}: Tentando conectar ao banco de dados: {DB_HOST}:{DB_PORT}/{DB_NAME}")
            
            self.db_engine = create_engine(
                connection_string,
                pool_recycle=3600,  # Reconecta a cada hora
                pool_pre_ping=True,  # Verifica a conexão antes de usar
                pool_size=5,
                max_overflow=10
            )
            self.Session = sessionmaker(bind=self.db_engine)
            
            # Testa a conexão
            with self.Session() as session:
                session.execute(text("SELECT 1"))
            logger.info(f"Worker {self.worker_id}: Conexão com banco de dados estabelecida com sucesso")
            
        except redis.RedisError as e:
            logger.error(f"Worker {self.worker_id}: Erro ao conectar com Redis:\n{traceback.format_exc()}")
            self.redis_client = None
        except SQLAlchemyError as e:
            logger.error(f"Worker {self.worker_id}: Erro ao conectar com banco de dados:\n{traceback.format_exc()}")
            self.db_engine = None
            self.Session = None
        except Exception as e:
            logger.error(f"Worker {self.worker_id}: Erro inesperado durante inicialização:\n{traceback.format_exc()}")
            self.redis_client = None
            self.db_engine = None
            self.Session = None

    def check_connections(self):
        """Verifica o status das conexões e tenta reconectar se necessário"""
        current_time = datetime.now()
        
        # Verifica conexões a cada 5 minutos
        if (current_time - self.last_status_check).total_seconds() >= self.status_check_interval:
            self.last_status_check = current_time
            
            # Verifica Redis
            try:
                if self.redis_client:
                    self.redis_client.ping()
                    logger.info(f"Worker {self.worker_id}: Conexão com Redis está ativa")
                else:
                    logger.warning(f"Worker {self.worker_id}: Tentando reconectar ao Redis")
                    self.initialize_connections()
            except redis.RedisError as e:
                logger.error(f"Worker {self.worker_id}: Erro na conexão com Redis:\n{traceback.format_exc()}")
                self.redis_client = None
                self.initialize_connections()

            # Verifica banco de dados
            try:
                if self.Session:
                    with self.Session() as session:
                        session.execute(text("SELECT 1"))
                    logger.info(f"Worker {self.worker_id}: Conexão com banco de dados está ativa")
                else:
                    logger.warning(f"Worker {self.worker_id}: Tentando reconectar ao banco de dados")
                    self.initialize_connections()
            except SQLAlchemyError as e:
                logger.error(f"Worker {self.worker_id}: Erro na conexão com banco de dados:\n{traceback.format_exc()}")
                self.db_engine = None
                self.Session = None
                self.initialize_connections()

    def check_scheduled_scans(self):
        """Verifica scans agendados e os adiciona à fila do Redis"""
        session = self.Session()
        try:
            current_time = datetime.now()
            logger.info(f"Verificando scans agendados para execução até: {current_time}")
            
            # Log dos parâmetros da consulta
            logger.info(f"Parâmetros da consulta: (status='agendado' OR status='finalizado'), ativo=True, proxima_execucao<={current_time}")
            
            scheduled_scans = session.query(WebScan).filter(
                (WebScan.status == 'agendado') | (WebScan.status == 'finalizado'),
                WebScan.ativo == True,
                WebScan.proxima_execucao <= current_time
            ).all()
            
            logger.info(f"Encontrados {len(scheduled_scans)} scans agendados")
            
            for scan in scheduled_scans:
                logger.info(f"Processando scan {scan.id} - {scan.nome}")
                logger.info(f"Detalhes do scan: status={scan.status}, ativo={scan.ativo}, proxima_execucao={scan.proxima_execucao}")
                
                scan_key = f"webscan:{scan.id}"
                if not self.redis_client.exists(scan_key):
                    scan_data = {
                        'id': str(scan.id),
                        'nome': scan.nome,
                        'urls': scan.urls,
                        'severidade': scan.severidade,
                        'templates': scan.templates if scan.templates else '',
                        'rate_limit': str(scan.rate_limit),
                        'threads': str(scan.threads),
                        'timeout': str(scan.timeout),
                        'retries': str(scan.retries),
                        'autenticado': '1' if scan.autenticado else '0',
                        'username': scan.username if scan.username else '',
                        'password': scan.password if scan.password else ''
                    }
                    
                    logger.info(f"Adicionando scan {scan.id} à fila do Redis")
                    # Usando hset ao invés de hmset
                    for key, value in scan_data.items():
                        self.redis_client.hset(scan_key, key, value)
                    
                    self.redis_client.lpush('webscan_queue', str(scan.id))
                    scan.status = 'fila'
                    session.commit()
                    logger.info(f"Scan {scan.id} adicionado à fila com sucesso")
                else:
                    logger.info(f"Scan {scan.id} já existe na fila do Redis")
        except Exception as e:
            logger.error(f"Erro ao verificar scans agendados:\n{traceback.format_exc()}")
        finally:
            session.close()

    def update_nuclei(self):
        """Atualiza o Nuclei e seus templates"""
        try:
            logger.info("Atualizando Nuclei e templates...")
            
            # Atualiza o Nuclei
            update_cmd = ['nuclei', '-update']
            process = subprocess.Popen(
                update_cmd,
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE,
                universal_newlines=True
            )
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Erro ao atualizar Nuclei: {stderr}")
            else:
                logger.info("Nuclei atualizado com sucesso")
            
            # Atualiza os templates
            template_cmd = ['nuclei', '-ut']
            process = subprocess.Popen(
                template_cmd,
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE,
                universal_newlines=True
            )
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Erro ao atualizar templates: {stderr}")
            else:
                logger.info("Templates atualizados com sucesso")
                
        except Exception as e:
            logger.error(f"Erro ao atualizar Nuclei e templates:\n{traceback.format_exc()}")

    def execute_nuclei_scan(self, scan_data, url):
        """Executa o scan do Nuclei para uma URL específica"""
        scan_id = scan_data['id']
        scan_dir = os.path.join(RESULTS_DIR, 'scans')
        os.makedirs(scan_dir, exist_ok=True)
        
        # Atualiza o Nuclei e os templates antes do scan
        self.update_nuclei()
        
        # Processa a URL removendo espaços extras e quebras de linha
        processed_url = url.strip()
        
        # Remove o protocolo se existir para normalização
        if processed_url.startswith(('http://', 'https://')):
            processed_url = processed_url.split('://', 1)[1]
            
        logger.info(f"Iniciando processamento da URL: {processed_url}")
        
        # Gera um nome único para o arquivo de resultado
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"scan_{scan_id}_{timestamp}_{uuid.uuid4().hex[:8]}.json"
        output_file = os.path.join(scan_dir, filename)
        
        cmd = [
            'nuclei',
            '-u', processed_url,
            '-rate-limit', str(scan_data['rate_limit']),
            '-c', str(scan_data['threads']),
            '-timeout', str(scan_data['timeout']),
            '-retries', str(scan_data['retries']),
            '-o', output_file
        ]

        if scan_data['autenticado'] == '1':
            logger.info(f"Configurando autenticação para usuário: {scan_data['username']}")
            cmd.extend(['-auth', f"{scan_data['username']}:{scan_data['password']}"])

        try:
            logger.info(f"Iniciando scan do Nuclei para URL: {processed_url}")
            logger.info(f"Comando Nuclei: {' '.join(cmd)}")
            
            # Inicia o processo do Nuclei
            process = subprocess.Popen(
                cmd,
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1  # Line buffered
            )
            
            # Função para ler e logar a saída em tempo real
            def log_output(pipe, prefix):
                for line in pipe:
                    if line.strip():
                        logger.info(f"{prefix}: {line.strip()}")
            
            # Inicia threads para ler stdout e stderr em tempo real
            stdout_thread = threading.Thread(target=log_output, args=(process.stdout, "Nuclei Output"))
            stderr_thread = threading.Thread(target=log_output, args=(process.stderr, "Nuclei Error"))
            
            stdout_thread.daemon = True
            stderr_thread.daemon = True
            
            stdout_thread.start()
            stderr_thread.start()
            
            # Aguarda o processo terminar
            process.wait()
            
            # Aguarda as threads de log terminarem
            stdout_thread.join()
            stderr_thread.join()
            
            if process.returncode != 0:
                logger.error(f"Erro no scan da URL {processed_url}")
                return False
            
            # Verifica se o arquivo de saída foi criado e tem conteúdo
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                logger.info(f"Scan concluído com sucesso para URL: {processed_url}")
                
                # Registra o resultado no banco de dados usando o modelo ScanResult
                session = self.Session()
                try:
                    scan_result = ScanResult(
                        scan_id=scan_id,
                        url=processed_url,
                        filename=filename,
                        created_at=datetime.now(),
                        status='success'
                    )
                    
                    session.add(scan_result)
                    session.commit()
                    logger.info(f"Resultado do scan registrado no banco de dados: {filename}")
                    
                except Exception as e:
                    logger.error(f"Erro ao registrar resultado no banco de dados: {str(e)}")
                    session.rollback()
                finally:
                    session.close()
                
                # Log dos resultados encontrados
                try:
                    with open(output_file, 'r') as f:
                        results = json.load(f)
                        if isinstance(results, list):
                            logger.info(f"Encontrados {len(results)} resultados para URL: {processed_url}")
                            # Log detalhado dos resultados
                            for idx, result in enumerate(results, 1):
                                logger.info(f"Resultado {idx}:")
                                logger.info(f"  - Template: {result.get('template', 'N/A')}")
                                logger.info(f"  - Severidade: {result.get('info', {}).get('severity', 'N/A')}")
                                logger.info(f"  - Nome: {result.get('info', {}).get('name', 'N/A')}")
                        else:
                            logger.info(f"Resultados encontrados para URL: {processed_url}")
                except json.JSONDecodeError as e:
                    logger.warning(f"Erro ao decodificar JSON dos resultados para URL: {processed_url}")
                    logger.warning(f"Detalhes do erro: {str(e)}")
                return True
            else:
                logger.warning(f"Scan concluído sem resultados para URL: {processed_url}")
                return True
            
        except subprocess.SubprocessError as e:
            logger.error(f"Erro na execução do comando Nuclei para URL {processed_url}")
            logger.error(f"Detalhes do erro: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Erro inesperado ao executar Nuclei para URL {processed_url}")
            logger.error(f"Detalhes do erro: {traceback.format_exc()}")
            return False

    def calculate_next_execution(self, scan):
        """Calcula a próxima data de execução baseado nas configurações de agendamento"""
        current_time = datetime.now()
        
        if scan.recorrencia == 'diario':
            next_execution = current_time.replace(
                hour=scan.hora_execucao.hour,
                minute=scan.hora_execucao.minute,
                second=0,
                microsecond=0
            ) + timedelta(days=1)
            
        elif scan.recorrencia == 'semanal':
            # Encontra o próximo dia da semana configurado
            dias_semana = [int(d) for d in scan.dias_semana.split(',')]
            current_weekday = current_time.weekday()
            
            # Procura o próximo dia da semana configurado
            next_weekday = None
            for dia in sorted(dias_semana):
                if dia > current_weekday:
                    next_weekday = dia
                    break
            
            # Se não encontrou um dia na mesma semana, pega o primeiro dia da próxima semana
            if next_weekday is None:
                next_weekday = min(dias_semana)
                days_ahead = 7 - current_weekday + next_weekday
            else:
                days_ahead = next_weekday - current_weekday
                
            next_execution = current_time.replace(
                hour=scan.hora_execucao.hour,
                minute=scan.hora_execucao.minute,
                second=0,
                microsecond=0
            ) + timedelta(days=days_ahead)
            
        else:  # único
            next_execution = None
            
        return next_execution

    def process_scan(self, scan_id):
        """Processa um scan da fila"""
        session = self.Session()
        scan = None
        try:
            scan_key = f"webscan:{scan_id}"
            scan_data = self.redis_client.hgetall(scan_key)
            
            if not scan_data:
                logger.error(f"Scan {scan_id} não encontrado no Redis")
                return

            scan = session.get(WebScan, scan_id)
            if not scan:
                logger.error(f"Scan {scan_id} não encontrado no banco de dados")
                return

            logger.info(f"Iniciando processamento do scan {scan_id} - {scan.nome}")
            scan.status = 'executando'
            scan.ultima_execucao = datetime.now()
            session.commit()

            # Processa cada URL individualmente, tratando tanto vírgulas quanto quebras de linha
            urls = []
            # Conta a ocorrência de vírgulas e quebras de linha
            comma_count = scan_data['urls'].count(',')
            newline_count = scan_data['urls'].count('\n')
            
            # Determina o separador mais recorrente
            if comma_count > newline_count:
                urls = [url.strip() for url in scan_data['urls'].split(',') if url.strip()]
            else:
                urls = [url.strip() for url in scan_data['urls'].split('\n') if url.strip()]
            for url in scan_data['urls'].split(','):
                # Se a URL contém quebras de linha, divide por elas também
                if '\n' in url:
                    urls.extend([u.strip() for u in url.split('\n') if u.strip()])
                else:
                    urls.append(url.strip())
            
            # Remove URLs vazias e duplicadas
            urls = list(set([url for url in urls if url]))
            
            results = {
                'scan_id': scan_id,
                'start_time': datetime.now().isoformat(),
                'urls': []
            }

            success = True
            for url in urls:
                logger.info(f"Processando URL: {url}")
                url_result = {
                    'url': url,
                    'success': self.execute_nuclei_scan(scan_data, url)
                }
                results['urls'].append(url_result)
                if not url_result['success']:
                    success = False

            results['end_time'] = datetime.now().isoformat()
            
            # Salvar resultados
            results_file = os.path.join(RESULTS_DIR, str(scan_id), 'results.json')
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=2)

            # Atualizar status e datas
            scan.status = 'finalizado' if success else 'falha'
            scan.ultima_execucao = datetime.now()
            scan.proxima_execucao = self.calculate_next_execution(scan)
            session.commit()
            
            logger.info(f"Scan {scan_id} {scan.status} com sucesso")
            if scan.proxima_execucao:
                logger.info(f"Próxima execução agendada para: {scan.proxima_execucao}")

        except Exception as e:
            logger.error(f"Erro ao processar scan {scan_id}:\n{traceback.format_exc()}")
            if scan:
                scan.status = 'falha'
                scan.ultima_execucao = datetime.now()
                scan.proxima_execucao = self.calculate_next_execution(scan)
                session.commit()
        finally:
            session.close()
            if scan_key in self.redis_client:
                self.redis_client.delete(scan_key)

    def run(self):
        """Loop principal do worker"""
        logger.info(f"Worker {self.worker_id} iniciado")
        while True:
            try:
                # Verifica conexões periodicamente
                self.check_connections()
                
                # Só prossegue se tiver conexões ativas
                if not self.redis_client or not self.Session:
                    logger.warning(f"Worker {self.worker_id}: Aguardando conexões serem estabelecidas...")
                    time.sleep(10)
                    continue
                
                self.check_scheduled_scans()
                
                # Tentar obter um scan da fila
                scan_id = self.redis_client.rpop('webscan_queue')
                if scan_id:
                    logger.info(f"Worker {self.worker_id} processando scan {scan_id}")
                    self.process_scan(scan_id)
                else:
                    time.sleep(5)  # Espera 5 segundos antes de verificar novamente
                    
            except Exception as e:
                logger.error(f"Erro no loop principal do worker: {str(e)}")
                time.sleep(5)

if __name__ == '__main__':
    worker_id = os.getenv('WORKER_ID', '1')
    worker = WebScanWorker(worker_id)
    worker.run() 