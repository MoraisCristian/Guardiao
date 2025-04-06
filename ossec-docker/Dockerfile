FROM almalinux:8

# Adiciona arquivos necessários
ADD ossec-docker/default_agent /var/ossec/default_agent
ADD ossec-docker/ossec.conf /var/ossec/etc/ossec.conf
ADD ossec-docker/data_dirs.env /data_dirs.env
ADD ossec-docker/init.sh /init.sh
ADD ossec-docker/ossec-server.sh /ossec-server.sh
ADD ossec-docker/conector/ossec_api.py /opt/conector/ossec_api.py

# Instala dependências
RUN dnf -y update && \
    dnf -y install epel-release && \
    dnf -y install wget sudo python3 python3-pip && \
    wget -q -O - https://updates.atomicorp.com/installers/atomic | bash && \
    dnf -y update && \
    dnf -y install ossec-hids-server && \
    pip3 install flask && \
    chmod +x /ossec-server.sh && \
    dnf clean all

# Expõe as portas necessárias
EXPOSE 1514/udp 1515/tcp 59347/tcp

VOLUME [ "/var/ossec" ]

# Define o comando padrão
ENTRYPOINT ["/ossec-server.sh"]
