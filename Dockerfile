FROM python:3.9-slim

LABEL org.opencontainers.image.authors="vero.valeros@gmail.com,eldraco@gmail.com"

ENV DEBIAN_FRONTEND=noninteractive

ENV DESTINATION_DIR /domain_analyzer

RUN apt update && apt install -y --no-install-recommends nmap 

COPY . ${DESTINATION_DIR}/

WORKDIR ${DESTINATION_DIR}

RUN pip install --upgrade pip

RUN pip install -r requirements.txt

