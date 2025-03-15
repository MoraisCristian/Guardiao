#!/bin/bash

# Atualizar pip
python3 -m pip install --upgrade pip

# Instalar dependências do sistema primeiro
apt-get update
apt-get install -y curl golang python3-flask-sqlalchemy python3-flask-migrate

# Configurar variável de ambiente para Flask
export FLASK_APP=app.py
export FLASK_ENV=development

# Instalar Flask-Migrate
pip install Flask-Migrate

# Executar migrações do banco de dados
flask db init || echo "Database already initialized"
flask db migrate || echo "Migration failed"
flask db upgrade || echo "Upgrade failed"

# Compilar utilitário CPE (comentado por enquanto)
#go build apps/utils/cpe_search.go
#chmod +x cpe_search