FROM python:2.7.18-slim

LABEL org.opencontainers.image.authors="vero.valeros@gmail.com,eldraco@gmail.com"

ENV PIP_NO_CACHE_DIR=1
ENV DEBIAN_FRONTEND=noninteractive
ENV DESTINATION_DIR /domain_analyzer

# Install packages needed for domain analyzer to run
RUN apt-get update && apt-get install -y \
        gcc \
        nmap \
        libgeoip1 \
        libgeoip-dev \
        geoip-bin \
        python-geoip && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy domain analyzer to the container
COPY . ${DESTINATION_DIR}/
RUN cd ${DESTINATION_DIR} 

# Install requirements through pip
RUN pip install -r ${DESTINATION_DIR}/requirements.txt

RUN apt-get remove -y gcc && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
    
WORKDIR ${DESTINATION_DIR}
