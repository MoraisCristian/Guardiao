FROM ubuntu:22.04

# Adiciona arquivos necessários
ADD ossec-docker/default_agent /var/ossec/default_agent
ADD ossec-docker/ossec.conf /var/ossec/etc/
ADD ossec-docker/data_dirs.env /data_dirs.env
ADD ossec-docker/init.sh /init.sh
ADD ossec-docker/ossec-server.sh /ossec-server.sh
ADD ossec-docker/conector/ossec_api.py /opt/conector/ossec_api.py

ENV DEBIAN_FRONTEND=noninteractive

# Instala dependências
RUN apt-get update 
RUN apt-get install -y wget sudo postfix python3 python3-pip 
RUN wget -q -O - https://updates.atomicorp.com/installers/atomic | bash  
RUN apt-get update 
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::="--force-confnew" ossec-hids-server 
RUN pip3 install flask 
RUN chmod +x /ossec-server.sh

# Define o volume de dados
VOLUME ["/root/"]

# Expõe as portas necessárias
EXPOSE 1514/udp 1515/tcp 59347/tcp

# Define o comando padrão
ENTRYPOINT ["/ossec-server.sh"]