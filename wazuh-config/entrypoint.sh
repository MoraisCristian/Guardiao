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

# Verificar se o Wazuh já está em execução (imagem oficial pode iniciar automaticamente)
if ! pgrep -f "wazuh-manager" > /dev/null && ! pgrep -f "ossec-server" > /dev/null; then
    echo "Iniciando Wazuh manager..."
    # Verificar qual comando está disponível na imagem
    if [ -f "/var/ossec/bin/wazuh-control" ]; then
        /var/ossec/bin/wazuh-control start
    elif [ -f "/var/ossec/bin/ossec-control" ]; then
        /var/ossec/bin/ossec-control start
    else
        echo "ERRO: Não foi possível encontrar o script de controle do Wazuh"
        exit 1
    fi
    
    echo "Aguardando Wazuh iniciar..."
    sleep 15
else
    echo "Wazuh manager já está rodando"
fi

# Iniciar API connector se não estiver rodando
if ! is_api_running; then
    # Verificar se o diretório do conector existe
    if [ -d "/opt/conector" ]; then
        cd /opt/conector
        echo "Iniciando API connector..."
        python3 /opt/conector/ossec_api.py &
        echo "API connector iniciado"
    else
        echo "AVISO: Diretório do conector não encontrado em /opt/conector"
    fi
else
    echo "API connector já está rodando na porta 59347"
fi

echo "Serviços iniciados com sucesso"

# Manter o container rodando
echo "Container está rodando em modo serviço"
tail -f /var/ossec/logs/ossec.log