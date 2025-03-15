FROM python:3.9-slim

COPY . .

# Instalar dependências do sistema primeiro
RUN apt-get update && 
RUN apt-get install -y 
RUN curl 
RUN golang 
RUN git 
RUN python3-flask-sqlalchemy 
RUN python3-flask-migrate 

COPY requirements.txt .
RUN python3 -m pip install --upgrade pip

RUN pip install -r requirements.txt

RUN bash prepare.sh

RUN pip install -r requirements.txt

RUN apt install git -y

ENV FLASK_APP=app.py
ENV FLASK_ENV=development

CMD ["flask", "run", "--host=0.0.0.0"]
