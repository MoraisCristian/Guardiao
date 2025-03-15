FROM python:3.9-slim

COPY . /app

WORKDIR /app

RUN pip install -r requirements.txt

RUN bash prepare.sh

RUN apt install git -y

ENV FLASK_APP=app.py

CMD ["flask", "run", "--host=0.0.0.0"]
