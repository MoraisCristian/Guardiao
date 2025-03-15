FROM python:3.9-slim

COPY . /app

# Instalar dependências do sistema primeiro
RUN apt-get update && \
    apt-get install -y \
    curl \
    golang \
    git \
    python3-flask-sqlalchemy \
    python3-flask-migrate \

COPY requirements.txt .
RUN python3 -m pip install --upgrade pip

RUN pip install -r requirements.txt

COPY . .

RUN bash prepare.sh

RUN pip install -r requirements.txt

RUN apt install git -y

ENV FLASK_APP=app.py
ENV FLASK_ENV=development

CMD ["flask", "run", "--host=0.0.0.0"]
