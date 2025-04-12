import os
import time
import subprocess
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='/var/guardiao/guard-agent/logs/mechanic.log',
    encoding='utf-8'
)
logger = logging.getLogger('Mecanico')

VENV_PYTHON = "/var/guardiao/venv/bin/python3"

while True:
    try:
        logger.info("Iniciando processo de verificação de atualizações...")
        
        # Run installation in a detached process using venv
        subprocess.Popen([
            "nohup", VENV_PYTHON, "-c", 
            "import subprocess; subprocess.run(['curl', '-s', 'http://${SERVER_IP}:${SERVER_PORT}/download/install.sh', '|', 'sudo', 'bash'])"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        logger.info("Aguardando conclusão da instalação...")
        time.sleep(900)
        
        # Restart OSSEC
        logger.info("Reiniciando OSSEC...")
        subprocess.run(["sudo", "/var/ossec/bin/ossec-control", "restart"], check=True)
        
        # Reload systemd and restart services
        logger.info("Recarregando systemd e reiniciando serviços...")
        subprocess.run(["sudo", "systemctl", "daemon-reload"], check=True)
        subprocess.run(["sudo", "systemctl", "restart", "guardiao"], check=True)
        subprocess.run(["sudo", "systemctl", "restart", "guardiao-mecanico"], check=True)
        
        logger.info("Verificação concluída. Próxima verificação em 15 minutos.")
        time.sleep(900)
    except Exception as e:
        logger.error(f"Erro durante a execução: {str(e)}")
        logger.info("Tentando novamente em 1 minuto...")
        time.sleep(60)