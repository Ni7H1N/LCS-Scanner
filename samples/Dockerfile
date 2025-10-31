FROM python:latest

ENV AWS_SECRET_KEY="abcd1234"
ENV DB_PASSWORD="root123"

RUN apt-get update && apt-get install -y sudo
RUN useradd -m admin && echo "admin:admin" | chpasswd
RUN echo "PermitRootLogin yes" >> /etc/ssh/sshd_config

WORKDIR /app
COPY . .
CMD ["python3", "app.py"]
