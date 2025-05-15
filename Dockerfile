FROM python:3.9-slim

COPY . /app

WORKDIR /app

# Instalar dependências do sistema
RUN apt-get update && \
    apt-get install -y \
    curl \
    default-libmysqlclient-dev \
    git \
    golang \
    build-essential && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install -r requirements.txt
RUN pip install pymysql

ENV FLASK_APP=app.py
ENV FLASK_ENV=development

CMD ["flask", "run", "--host=0.0.0.0"]