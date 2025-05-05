FROM python:3.12-slim

# Instalar dependências do sistema
RUN apt-get update && apt-get install -y \
    wget \
    git \
    && rm -rf /var/lib/apt/lists/*

# Instalar Go 1.21.6
RUN wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz && \
    rm go1.21.6.linux-amd64.tar.gz

# Configurar Go
ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/root/go"
ENV PATH="${GOPATH}/bin:${PATH}"

# Instalar Nuclei via Go
RUN go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Criar diretório da aplicação
WORKDIR /app

# Copiar arquivos necessários
COPY webscan_worker.py /app/
COPY requirements.txt /app/
COPY models.py /app/

# Instalar dependências Python
RUN pip install --no-cache-dir -r requirements.txt

# Criar diretórios necessários
RUN mkdir -p /var/log /var/webscan_results

# Comando para executar o worker
CMD ["python", "webscan_worker.py"] 