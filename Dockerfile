FROM ubuntu:16.04

RUN apt-get update && \
    apt-get install -y software-properties-common && \
    add-apt-repository ppa:deadsnakes/ppa && \
    apt-get update -y && \
    apt-get install -y build-essential python3.6 python3.6-dev python3-pip python3.6-venv && \
    python3.6 -m pip install pip --upgrade && \
    python3.6 -m pip install wheel && \
    apt-get -y install wget && \
    wget https://bootstrap.pypa.io/get-pip.py && \
    python3 get-pip.py

COPY common /common/
COPY memcached /memcached/
COPY statistics_collection /statistics_collection/
COPY /statistics_collection/statisticcollection /etc/init.d/statisticcollection

RUN chmod +x /etc/init.d/statisticcollection && \
    pip3.6 install -r /statistics_collection/requirements.txt && \
    echo "service statisticcollection start" >> /etc/bash.bashrc

CMD ["/bin/bash"]
