#!/usr/bin/env bash

## Create and initialize TAP device ##
ip tuntap add dev tap0 mode tap

ip link set dev tap0 down
ip addr add 10.5.0.1/16 dev tap0
ip link set dev tap0 mtu 1500
ip link set dev tap0 up
######################

## IP Forwarding config for TAP device ##
echo 1 > /proc/sys/net/ipv4/ip_forward

iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -A FORWARD -i eth0 -o tap0 -m state --state RELATED,ESTABLISHED -j ACCEPT

#Drop any packages destined for the host machine or any other docker containers
#NOTE: double check that this matches your docker bridge subnet
iptables -A FORWARD -i tap0 -o eth0 -d 172.17.0.0/16 -j DROP

iptables -A FORWARD -i tap0 -o eth0 -j ACCEPT
iptables-save
#########################################

dnsmasq --conf-dir=/etc/dnsmasq.d
uv run python -m websockproxy.switchedrelay
