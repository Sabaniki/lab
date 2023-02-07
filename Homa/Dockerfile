FROM ubuntu:latest
RUN apt-get update -y && apt-get upgrade -y
RUN apt-get install -y iproute2 mtr

ENV APP_HOME /homa
COPY ./HomaModule ${APP_HOME}

ENTRYPOINT ["tail", "-f"]