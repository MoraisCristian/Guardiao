#!/bin/bash

# Função para detectar o gerenciador de pacotes
detect_package_manager() {
    if command -v dnf &> /dev/null; then
        echo "dnf"
    elif command -v yum &> /dev/null; then
        echo "yum"
    elif command -v apt-get &> /dev/null; then
        echo "apt-get"
    elif command -v apk &> /dev/null; then
        echo "apk"
    else
        echo "unknown"
    fi
}

# Função para instalar pacotes baseado no gerenciador detectado
install_packages() {
    local pkg_manager=$(detect_package_manager)
    echo "Gerenciador de pacotes detectado: $pkg_manager"

    case $pkg_manager in
        "dnf")
            dnf -y install python3 python3-pip net-tools lsof
            ;;
        "yum")
            yum -y install python3 python3-pip net-tools lsof
            ;;
        "apt-get")
            apt-get update
            apt-get install -y python3 python3-pip net-tools lsof
            ;;
        "apk")
            apk add --no-cache python3 py3-pip net-tools lsof
            ;;
        *)
            echo "Gerenciador de pacotes não suportado"
            exit 1
            ;;
    esac
}

# Função para verificar se um processo está rodando em uma porta usando lsof
is_api_running() {
    if command -v lsof &> /dev/null; then
        lsof -i :59347 > /dev/null 2>&1
        return $?
    elif command -v netstat &> /dev/null; then
        netstat -tuln | grep ":59347 " > /dev/null
        return $?
    else
        echo "Nem lsof nem netstat estão disponíveis"
        return 1
    fi
}

# Criar diretórios necessários
mkdir -p /var/ossec/logs
touch /var/ossec/logs/ossec.log

# Instalar dependências se necessário
if ! command -v python3 &> /dev/null || ! command -v pip3 &> /dev/null; then
    echo "Instalando Python e dependências..."
    install_packages
fi

# Instalar Flask se necessário
if ! python3 -c "import flask" &> /dev/null; then
    echo "Instalando Flask..."
    pip3 install flask
fi

# Iniciar Wazuh manager se não estiver rodando
if ! pgrep -f "wazuh-manager" > /dev/null; then
    echo "Iniciando Wazuh manager..."
    /var/ossec/bin/wazuh-control start
    WAZUH_PID=$!
    
    echo "Aguardando Wazuh iniciar..."
    sleep 15
else
    echo "Wazuh manager já está rodando"
    WAZUH_PID=$(pgrep -f "wazuh-manager")
fi

# Iniciar API connector se não estiver rodando
if ! is_api_running; then
    cd /opt/conector
    echo "Iniciando API connector..."
    python3 /opt/conector/ossec_api.py &
    echo "API connector iniciado"
else
    echo "API connector já está rodando na porta 59347"
fi

echo "Serviços iniciados com sucesso"

# Manter o container rodando
echo "Container está rodando em modo serviço"
tail -f /var/ossec/logs/ossec.log