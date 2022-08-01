FROM ubuntu:focal

LABEL org.opencontainers.image.authors="benjamin.c.burns@gmail.com"

RUN apt-get update && apt-get install -y python2 python2-dev iptables dnsmasq uml-utilities net-tools build-essential curl && apt-get clean

RUN curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py && python2 get-pip.py && rm get-pip.py

COPY docker-image-config/docker-startup.sh switchedrelay.py limiter.py requirements.txt /opt/websockproxy/
COPY docker-image-config/dnsmasq/interface docker-image-config/dnsmasq/dhcp /etc/dnsmasq.d/

WORKDIR /opt/websockproxy/

RUN pip2 install -r /opt/websockproxy/requirements.txt

EXPOSE 80

CMD /opt/websockproxy/docker-startup.sh


