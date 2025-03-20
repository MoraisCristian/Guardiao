#!/bin/bash

# Stop OSSEC if it's running
if [ -f /var/ossec/bin/ossec-control ]; then
    /var/ossec/bin/ossec-control stop
fi

# restore client.keys
cp /root/client.keys /var/ossec/etc/client.keys
# Restore the ossec.log
cp /root/ossec.log /var/ossec/logs/ossec.log
# Restore the alerts.log
cp /root/alerts.log /var/ossec/logs/alerts/alerts.log

# Start OSSEC server
/var/ossec/bin/ossec-control start

# Start the API connector
python3 /opt/conector/ossec_api.py &

# continuamente copia o ossec.log, alerts.log e client.keys para o diretório /root
while true; do
    cp /var/ossec/logs/ossec.log /root/ossec.log
    cp /var/ossec/logs/alerts/alerts.json /root/alerts.json
    cp /var/ossec/etc/client.keys /root/client.keys
    sleep 10
done &

# Keep container running
tail -f /var/ossec/logs/ossec.log