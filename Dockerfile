FROM ubuntu:xenial

MAINTAINER Ben Burns

RUN apt-get update && apt-get install -y iptables dnsmasq python-pip uml-utilities net-tools && apt-get clean

COPY docker-image-config/docker-startup.sh switchedrelay.py limiter.py requirements.txt /opt/websockproxy/
COPY docker-image-config/dnsmasq/interface docker-image-config/dnsmasq/dhcp /etc/dnsmasq.d/

EXPOSE 80

RUN pip install -r /opt/websockproxy/requirements.txt

WORKDIR /opt/websockproxy/
CMD /opt/websockproxy/docker-startup.sh

