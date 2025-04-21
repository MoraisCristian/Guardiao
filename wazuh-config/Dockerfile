# Wazuh Docker Copyright (C) 2017, Wazuh Inc. (License GPLv2)
FROM amazonlinux:2023

RUN rm /bin/sh && ln -s /bin/bash /bin/sh

ARG WAZUH_VERSION=4.11.2
ARG WAZUH_TAG_REVISION=1
ARG S6_VERSION="v2.2.0.3"

# Instalar dependências básicas
RUN yum install curl-minimal xz gnupg tar gzip openssl findutils procps python3 python3-pip net-tools lsof -y && \
    yum clean all

# Criar diretório para scripts de configuração
RUN mkdir -p /config

# Script para adicionar o repositório Wazuh
RUN echo '#!/bin/bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --import -
echo -e "[wazuh]\nname=Wazuh Repository\nbaseurl=https://packages.wazuh.com/4.x/yum/\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1" > /etc/yum.repos.d/wazuh.repo
' > /config/add_repository.sh && \
    chmod 775 /config/add_repository.sh && \
    /config/add_repository.sh

# Script para preparar diretórios de dados permanentes
RUN echo '#!/bin/bash
mkdir -p /var/ossec/etc/shared/default
mkdir -p /var/ossec/queue/agent-info
mkdir -p /var/ossec/queue/agent-groups
mkdir -p /var/ossec/queue/diff
mkdir -p /var/ossec/queue/fim/db
mkdir -p /var/ossec/queue/fts
mkdir -p /var/ossec/queue/logcollector
mkdir -p /var/ossec/queue/rids
mkdir -p /var/ossec/queue/rootcheck
mkdir -p /var/ossec/queue/syscheck
mkdir -p /var/ossec/queue/vulnerabilities
mkdir -p /var/ossec/var/db
mkdir -p /var/ossec/var/download
mkdir -p /var/ossec/var/run
mkdir -p /var/ossec/var/selinux
mkdir -p /var/ossec/var/upgrade
mkdir -p /var/ossec/var/wodles
mkdir -p /var/ossec/logs/alerts
mkdir -p /var/ossec/logs/archives
mkdir -p /var/ossec/logs/firewall
mkdir -p /var/ossec/logs/ossec
touch /var/ossec/logs/active-responses.log
' > /config/prepare_data.sh && \
    chmod 775 /config/prepare_data.sh

# Instalar Wazuh Manager
RUN yum install wazuh-manager-${WAZUH_VERSION}-${WAZUH_TAG_REVISION} -y && \
    yum clean all && \
    curl --fail --silent -L https://github.com/just-containers/s6-overlay/releases/download/${S6_VERSION}/s6-overlay-amd64.tar.gz \
    -o /tmp/s6-overlay-amd64.tar.gz && \
    tar xzf /tmp/s6-overlay-amd64.tar.gz -C / --exclude="./bin" && \
    tar xzf /tmp/s6-overlay-amd64.tar.gz -C /usr ./bin && \
    rm /tmp/s6-overlay-amd64.tar.gz

# Preparar diretórios para montagem de volumes
RUN mkdir -p /var/ossec/var/multigroups && \
    chown root:wazuh /var/ossec/var/multigroups && \
    chmod 770 /var/ossec/var/multigroups && \
    mkdir -p /var/ossec/agentless && \
    chown root:wazuh /var/ossec/agentless && \
    chmod 770 /var/ossec/agentless && \
    mkdir -p /var/ossec/active-response/bin && \
    chown root:wazuh /var/ossec/active-response/bin && \
    chmod 770 /var/ossec/active-response/bin && \
    /config/prepare_data.sh

# Script de inicialização personalizado
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

# Remover o repositório Wazuh para evitar atualizações automáticas
RUN rm /etc/yum.repos.d/wazuh.repo

# Expor portas necessárias
EXPOSE 55000/tcp 1514/tcp 1515/tcp 514/udp 1516/tcp

# Definir o ponto de entrada
ENTRYPOINT ["/entrypoint.sh"]