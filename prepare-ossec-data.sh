#!/bin/bash

# Clean up the ossec-data directory
rm -rf /Users/lucas.araujo/code/Guardiao/ossec-data/*

# Create the necessary files
mkdir -p /Users/lucas.araujo/code/Guardiao/ossec-data
touch /Users/lucas.araujo/code/Guardiao/ossec-data/client.keys
touch /Users/lucas.araujo/code/Guardiao/ossec-data/alerts.log
touch /Users/lucas.araujo/code/Guardiao/ossec-data/ossec.log

# Set permissions to allow the container to write to these files
chmod 666 /Users/lucas.araujo/code/Guardiao/ossec-data/client.keys
chmod 666 /Users/lucas.araujo/code/Guardiao/ossec-data/alerts.log
chmod 666 /Users/lucas.araujo/code/Guardiao/ossec-data/ossec.log