import socket

# Global configuration variables
ram = {}
nome = socket.gethostname()
chave_ativacao = 'KOAUBDFDOEOER1EQLKZQQQ5COTTQFLO1ZI1TYHDZVPLDEDA0'
codigos = {'registro': 1, 'ping': 2, 'upload': 3, 'ossec-register': 4}

# Server configuration
SERVER_URL = 'http://10.0.10.183:5002'
OSSEC_LOG_PATH = "/ossec/alerts.json"