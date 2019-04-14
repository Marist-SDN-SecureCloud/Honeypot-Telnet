FROM ubuntu:18.04
MAINTAINER Daniel Nicolas Gisolfi

ENV DEBIAN_FRONTEND=noninteractive
ENV VERSION=02
ENV HOST_IP=10.11.17.23

RUN apt-get update -y \
    && apt-get install -y \
        build-essential \
        python3-pip \
        # zlib1g-dev \ 
        tzdata \
        wget \
        gcc \
        && pip3 install --upgrade pip

WORKDIR /usr/local/source/ptelnetd

RUN wget https://github.com/wedaa/LongTail-Telnet-honeypot-v2/raw/master/paranoid-telnetd-0.4.tgz \
    && tar -xf paranoid-telnetd-0.4.tgz


WORKDIR /usr/local/source/ptelnetd/paranoid-telnetd-0.4

RUN cp ptelnetd-initd /etc/init.d \
    && chmod a+rx /etc/init.d/ptelnetd-initd \
    && mv main.c main.c.orig \

COPY ./src/main.c main.c

RUN ./configure \
    && make \
    && cp ptelnetd /usr/local/sbin/ptelnetd \
	&& chmod a+rx /usr/local/sbin/ptelnetd

# Setup TCP Server
WORKDIR /TcpServer
COPY ./TcpServer .

RUN pip install -r requirements.txt \
    && chmod +x init.sh

ENTRYPOINT [ "/bin/bash" ]
CMD [ "./init.sh" ]