FROM ubuntu:18.04
MAINTAINER Daniel Nicolas Gisolfi

ENV DEBIAN_FRONTEND=noninteractive
ENV VERSION=02
ENV HOST_IP=0.0.0.0

RUN apt-get update -y \
    && apt-get install -y \
        build-essential \
        python3-pip \
        tzdata \
        wget \
        gcc \
        && pip3 install --upgrade pip

EXPOSE 23

# Set the TimeZone 
RUN cp /usr/share/zoneinfo/America/New_York /etc/localtime \
    && dpkg-reconfigure tzdata

WORKDIR /usr/local/source/ptelnetd

RUN wget https://github.com/wedaa/LongTail-Telnet-honeypot-v2/raw/master/paranoid-telnetd-0.4.tgz \
    && tar -xf paranoid-telnetd-0.4.tgz


WORKDIR /usr/local/source/ptelnetd/paranoid-telnetd-0.4

COPY ./src/main.c main.c
COPY ./src/client.c client.c

RUN ./configure \
    && make \
    && cp ptelnetd /usr/sbin \
	&& chmod a+rwx /usr/sbin/ptelnetd

# Setup TCP Server
WORKDIR /TcpServer
COPY ./TcpServer .

RUN pip install -r requirements.txt \
    && chmod +x init.sh

ENTRYPOINT [ "/bin/bash" ]
CMD [ "./init.sh" ]