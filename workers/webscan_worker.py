import os
import json
import time
import redis
import logging
import threading
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import WebScan
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
        self.redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
        self.db_engine = create_engine(f'{DB_ENGINE}://{DB_USERNAME}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}')
        self.Session = sessionmaker(bind=self.db_engine)
        self.lock = threading.Lock()
        
        # Garantir que o diretório de resultados existe
        os.makedirs(RESULTS_DIR, exist_ok=True)

    def check_scheduled_scans(self):
        """Verifica scans agendados e os adiciona à fila do Redis"""
        session = self.Session()
        try:
            current_time = datetime.now()
            scheduled_scans = session.query(WebScan).filter(
                WebScan.status == 'agendado',
                WebScan.ativo == True,
                WebScan.proxima_execucao <= current_time
            ).all()

            for scan in scheduled_scans:
                scan_key = f"webscan:{scan.id}"
                if not self.redis_client.exists(scan_key):
                    scan_data = {
                        'id': scan.id,
                        'nome': scan.nome,
                        'urls': scan.urls,
                        'severidade': scan.severidade,
                        'templates': scan.templates,
                        'rate_limit': scan.rate_limit,
                        'threads': scan.threads,
                        'timeout': scan.timeout,
                        'retries': scan.retries,
                        'autenticado': scan.autenticado,
                        'username': scan.username,
                        'password': scan.password
                    }
                    
                    self.redis_client.hmset(scan_key, scan_data)
                    self.redis_client.lpush('webscan_queue', scan.id)
                    scan.status = 'fila'
                    session.commit()
                    logger.info(f"Scan {scan.id} adicionado à fila")
        except Exception as e:
            logger.error(f"Erro ao verificar scans agendados: {str(e)}")
        finally:
            session.close()

    def execute_nuclei_scan(self, scan_data, url):
        """Executa o scan do Nuclei para uma URL específica"""
        scan_id = scan_data['id']
        scan_dir = os.path.join(RESULTS_DIR, str(scan_id))
        os.makedirs(scan_dir, exist_ok=True)
        
        output_file = os.path.join(scan_dir, f"{uuid.uuid4()}.json")
        
        cmd = [
            'nuclei',
            '-u', url,
            '-severity', scan_data['severidade'],
            '-rate-limit', str(scan_data['rate_limit']),
            '-c', str(scan_data['threads']),
            '-timeout', str(scan_data['timeout']),
            '-retries', str(scan_data['retries']),
            '-json'
        ]

        if scan_data['templates']:
            cmd.extend(['-t', scan_data['templates']])

        if scan_data['autenticado']:
            cmd.extend(['-auth', f"{scan_data['username']}:{scan_data['password']}"])

        try:
            with open(output_file, 'w') as f:
                process = subprocess.Popen(
                    cmd,
                    stdout=f,
                    stderr=subprocess.PIPE,
                    universal_newlines=True
                )
                _, stderr = process.communicate()
                
                if process.returncode != 0:
                    logger.error(f"Erro no scan da URL {url}: {stderr}")
                    return False
                
                return True
        except Exception as e:
            logger.error(f"Erro ao executar Nuclei para URL {url}: {str(e)}")
            return False

    def process_scan(self, scan_id):
        """Processa um scan da fila"""
        session = self.Session()
        try:
            scan_key = f"webscan:{scan_id}"
            scan_data = self.redis_client.hgetall(scan_key)
            
            if not scan_data:
                logger.error(f"Scan {scan_id} não encontrado no Redis")
                return

            scan = session.query(WebScan).get(scan_id)
            if not scan:
                logger.error(f"Scan {scan_id} não encontrado no banco de dados")
                return

            scan.status = 'executando'
            scan.ultima_execucao = datetime.now()
            session.commit()

            urls = scan_data['urls'].split(',')
            results = {
                'scan_id': scan_id,
                'start_time': datetime.now().isoformat(),
                'urls': []
            }

            for url in urls:
                url = url.strip()
                url_result = {
                    'url': url,
                    'success': self.execute_nuclei_scan(scan_data, url)
                }
                results['urls'].append(url_result)

            results['end_time'] = datetime.now().isoformat()
            
            # Salvar resultados
            results_file = os.path.join(RESULTS_DIR, str(scan_id), 'results.json')
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=2)

            scan.status = 'finalizado'
            session.commit()

        except Exception as e:
            logger.error(f"Erro ao processar scan {scan_id}: {str(e)}")
            scan.status = 'erro'
            session.commit()
        finally:
            session.close()
            self.redis_client.delete(scan_key)

    def run(self):
        """Loop principal do worker"""
        logger.info(f"Worker {self.worker_id} iniciado")
        while True:
            try:
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