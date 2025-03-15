FROM python:3.9-slim

# Instalar dependências do sistema primeiro
RUN apt-get update && \
    apt-get install -y \
    curl \
    golang \
    git \
    python3-flask-sqlalchemy \
    python3-flask-migrate \
    dos2unix

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Converter scripts para formato Unix
RUN dos2unix prepare.sh && \
    dos2unix app.py

RUN bash prepare.sh

ENV FLASK_APP=app.py
ENV FLASK_ENV=development

CMD ["flask", "run", "--host=0.0.0.0"]
