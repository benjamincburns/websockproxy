#!/usr/bin/env bash
set -euo pipefail

TAP=tap0
GUEST_SUBNET=10.5.0.0/16

# Interfaces guest traffic may leave through (comma or space separated).
# Defaults to the interface(s) carrying the IPv4 default route.
EGRESS_INTERFACES="${WEBSOCKPROXY_EGRESS_INTERFACES:-$(ip -4 route show default | awk '{for (i = 1; i < NF; i++) if ($i == "dev") print $(i + 1)}' | sort -u)}"
EGRESS_INTERFACES="${EGRESS_INTERFACES//,/ }"
# Non-public CIDRs guests may reach anyway (comma or space separated).
ALLOWED_PRIVATE_NETS="${WEBSOCKPROXY_ALLOWED_PRIVATE_NETS:-}"
ALLOWED_PRIVATE_NETS="${ALLOWED_PRIVATE_NETS//,/ }"

if [ -z "${EGRESS_INTERFACES// /}" ]; then
    echo "No default route found; set WEBSOCKPROXY_EGRESS_INTERFACES." >&2
    exit 1
fi
for iface in $EGRESS_INTERFACES; do
    if [ "$iface" = "$TAP" ] || ! ip link show dev "$iface" >/dev/null 2>&1; then
        echo "Invalid egress interface: $iface" >&2
        exit 1
    fi
done
for net in $ALLOWED_PRIVATE_NETS; do
    if ! python3 -c 'import ipaddress, sys; ipaddress.IPv4Network(sys.argv[1], strict=False)' "$net" 2>/dev/null; then
        echo "Invalid IPv4 CIDR in WEBSOCKPROXY_ALLOWED_PRIVATE_NETS: $net" >&2
        exit 1
    fi
done

## Create and initialize TAP device ##
ip tuntap add dev "$TAP" mode tap

ip link set dev "$TAP" down
ip addr add 10.5.0.1/16 dev "$TAP"
ip link set dev "$TAP" mtu 1500
ip link set dev "$TAP" up
######################

## IP forwarding and firewall for the TAP device ##
# Guest traffic may only leave through EGRESS_INTERFACES, and only to public
# addresses or ALLOWED_PRIVATE_NETS. Guest rules live in their own chains,
# entered only for traffic to or from the TAP device, and no chain policies
# are changed, so traffic on other interfaces is left alone.
echo 1 > /proc/sys/net/ipv4/ip_forward

# Guests may only use this container for DHCP, DNS and ping.
iptables -N GUEST_INPUT
iptables -A GUEST_INPUT -p udp --dport 67 -j ACCEPT
iptables -A GUEST_INPUT -p udp --dport 53 -j ACCEPT
iptables -A GUEST_INPUT -p tcp --dport 53 -j ACCEPT
iptables -A GUEST_INPUT -p icmp -j ACCEPT
iptables -A GUEST_INPUT -j DROP
iptables -I INPUT -i "$TAP" -j GUEST_INPUT

iptables -N GUEST_EGRESS
for net in $ALLOWED_PRIVATE_NETS; do
    iptables -A GUEST_EGRESS -d "$net" -j ACCEPT
done
# Drop IANA special-purpose (non-public) destinations: the host machine,
# docker networks, the local network, cloud metadata services
# (169.254.169.254), CGNAT/VPN ranges, loopback and multicast.
for net in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 \
           172.16.0.0/12 192.0.0.0/24 192.168.0.0/16 198.18.0.0/15 224.0.0.0/3; do
    iptables -A GUEST_EGRESS -d "$net" -j DROP
done
iptables -A GUEST_EGRESS -j ACCEPT

# Guests may receive replies, but nothing may open connections to them.
iptables -N GUEST_FORWARD
iptables -A GUEST_FORWARD -o "$TAP" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A GUEST_FORWARD -o "$TAP" -j DROP
for iface in $EGRESS_INTERFACES; do
    iptables -A GUEST_FORWARD -o "$iface" -j GUEST_EGRESS
    iptables -t nat -A POSTROUTING -s "$GUEST_SUBNET" -o "$iface" -j MASQUERADE
done
iptables -A GUEST_FORWARD -j DROP
iptables -I FORWARD -i "$TAP" -j GUEST_FORWARD
iptables -I FORWARD -o "$TAP" -j GUEST_FORWARD

# Guests get no IPv6 routing; don't let them reach the container over it
# (e.g. via link-local addresses) either.
if ip6tables -L -n >/dev/null 2>&1; then
    ip6tables -I INPUT -i "$TAP" -j DROP
    ip6tables -I FORWARD -i "$TAP" -j DROP
    ip6tables -I FORWARD -o "$TAP" -j DROP
fi

iptables-save
#########################################

dnsmasq --conf-dir=/etc/dnsmasq.d
# exec so the relay replaces this shell as PID 1 and receives SIGTERM
exec /opt/websockproxy/.venv/bin/python -m websockproxy.switchedrelay
