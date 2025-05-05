FROM python:3.12-slim

# Instalar dependências do sistema
RUN apt-get update && apt-get install -y \
    nuclei \
    && rm -rf /var/lib/apt/lists/*

# Criar diretório da aplicação
WORKDIR /app

# Copiar arquivos necessários
COPY webscan_worker.py /app/
COPY requirements.txt /app/

# Instalar dependências Python
RUN pip install --no-cache-dir -r requirements.txt

# Criar diretórios necessários
RUN mkdir -p /var/log /var/webscan_results

# Comando para executar o worker
CMD ["python", "webscan_worker.py"] 