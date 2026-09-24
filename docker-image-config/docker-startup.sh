#!/usr/bin/env bash
set -euo pipefail

# TAP device, IP forwarding, NAT and firewall for the relay's guests
/opt/websockproxy/setup-network.sh
iptables-save

dnsmasq --conf-dir=/etc/dnsmasq.d
# exec so the relay replaces this shell as PID 1 and receives SIGTERM
exec /opt/websockproxy/.venv/bin/websockproxy
