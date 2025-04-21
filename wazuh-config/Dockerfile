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
RUN echo '#!/bin/bash \n\
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --import - \n\
echo -e "[wazuh]\nname=Wazuh Repository\nbaseurl=https://packages.wazuh.com/4.x/yum/\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1" > /etc/yum.repos.d/wazuh.repo \n\
' > /config/add_repository.sh && \
    chmod 775 /config/add_repository.sh && \
    /config/add_repository.sh

# Script para preparar diretórios de dados permanentes
RUN echo '#!/bin/bash \n\
mkdir -p /var/ossec/etc/shared/default \n\
mkdir -p /var/ossec/queue/agent-info \n\
mkdir -p /var/ossec/queue/agent-groups \n\
mkdir -p /var/ossec/queue/diff \n\
mkdir -p /var/ossec/queue/fim/db \n\
mkdir -p /var/ossec/queue/fts \n\
mkdir -p /var/ossec/queue/logcollector \n\
mkdir -p /var/ossec/queue/rids \n\
mkdir -p /var/ossec/queue/rootcheck \n\
mkdir -p /var/ossec/queue/syscheck \n\
mkdir -p /var/ossec/queue/vulnerabilities \n\
mkdir -p /var/ossec/var/db \n\
mkdir -p /var/ossec/var/download \n\
mkdir -p /var/ossec/var/run \n\
mkdir -p /var/ossec/var/selinux \n\
mkdir -p /var/ossec/var/upgrade \n\
mkdir -p /var/ossec/var/wodles \n\
mkdir -p /var/ossec/logs/alerts \n\
mkdir -p /var/ossec/logs/archives \n\
mkdir -p /var/ossec/logs/firewall \n\
mkdir -p /var/ossec/logs/ossec \n\
touch /var/ossec/logs/active-responses.log \n\
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