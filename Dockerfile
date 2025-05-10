FROM python:3.9-slim

COPY . /app

WORKDIR /app

# Instalar dependências do sistema primeiro
RUN apt-get update 
RUN apt-get install -y curl golang git default-libmysqlclient-dev build-essential
###python3-flask-sqlalchemy python3-flask-migrate 

COPY requirements.txt .
#RUN python3 -m pip install --upgrade pip

RUN pip install -r requirements.txt
RUN pip install pymysql

RUN bash prepare.sh

ENV FLASK_APP=app.py
ENV FLASK_ENV=development

CMD ["flask", "run", "--host=0.0.0.0"]