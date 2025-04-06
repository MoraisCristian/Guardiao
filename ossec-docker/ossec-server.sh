#!/bin/bash

# Stop OSSEC if it's running
if [ -f /var/ossec/bin/ossec-control ]; then
    /var/ossec/bin/ossec-control stop
fi

# Start OSSEC server
/var/ossec/bin/ossec-control start

# Start the API connector
python3 /opt/conector/ossec_api.py &

# Keep container running
tail -f /var/ossec/logs/ossec.log