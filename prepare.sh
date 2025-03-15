#!/usr/bin/env bash
python3 -m pip install --upgrade pip

flask db init
flask db migrate
flask db upgrade

apt update -y
apt install curl golang -y
#go build apps/utils/cpe_search.go
#chmod +x cpe_search