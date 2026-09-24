#!/usr/bin/env bash
# Set up the TAP device, IP forwarding, NAT and firewall the relay's guests
# need. Used by the Docker image, and can be run directly on a Linux host
# (as root). Safe to run more than once. Run with --remove to undo.
#
# Settings (see README.md):
#   WEBSOCKPROXY_EGRESS_INTERFACES   interfaces guest traffic may leave through
#   WEBSOCKPROXY_ALLOWED_PRIVATE_NETS non-public IPv4 CIDRs guests may reach
set -euo pipefail

TAP=tap0
GATEWAY=10.5.0.1/16
GUEST_SUBNET=10.5.0.0/16

# Remove every jump into a chain matching the given arguments.
unjump() {
    local cmd=$1 table=$2 chain=$3 from=$4; shift 4
    while "$cmd" -t "$table" -C "$from" "$@" -j "$chain" 2>/dev/null; do
        "$cmd" -t "$table" -D "$from" "$@" -j "$chain"
    done
}
# Flush and delete a chain if it exists (once nothing jumps to it).
delete_chain() {
    local cmd=$1 table=$2 chain=$3
    if "$cmd" -t "$table" -n -L "$chain" >/dev/null 2>&1; then
        "$cmd" -t "$table" -F "$chain"
        "$cmd" -t "$table" -X "$chain"
    fi
}

remove_all() {
    unjump iptables filter GUEST_INPUT INPUT -i "$TAP"
    unjump iptables filter GUEST_FORWARD FORWARD -i "$TAP"
    unjump iptables filter GUEST_FORWARD FORWARD -o "$TAP"
    unjump iptables nat GUEST_NAT POSTROUTING -s "$GUEST_SUBNET"
    delete_chain iptables filter GUEST_INPUT
    delete_chain iptables filter GUEST_FORWARD
    delete_chain iptables filter GUEST_EGRESS  # after GUEST_FORWARD, which jumps to it
    delete_chain iptables nat GUEST_NAT
    if ip6tables -n -L >/dev/null 2>&1; then
        unjump ip6tables filter GUEST_INPUT6 INPUT -i "$TAP"
        unjump ip6tables filter GUEST_FORWARD6 FORWARD -i "$TAP"
        unjump ip6tables filter GUEST_FORWARD6 FORWARD -o "$TAP"
        delete_chain ip6tables filter GUEST_INPUT6
        delete_chain ip6tables filter GUEST_FORWARD6
    fi
    if ip link show dev "$TAP" >/dev/null 2>&1; then
        ip link delete dev "$TAP"
    fi
}

# Create (or empty) a chain, and make sure it's jumped to (once) from the top
# of a built-in chain for traffic matching the given arguments.
fresh_chain() {
    local cmd=$1 table=$2 chain=$3
    "$cmd" -t "$table" -N "$chain" 2>/dev/null || "$cmd" -t "$table" -F "$chain"
}
jump_to() {
    local cmd=$1 table=$2 chain=$3 from=$4; shift 4
    "$cmd" -t "$table" -C "$from" "$@" -j "$chain" 2>/dev/null \
        || "$cmd" -t "$table" -I "$from" "$@" -j "$chain"
}

if [ "${1:-}" = "--remove" ]; then
    remove_all
    exit 0
fi

# Interfaces guest traffic may leave through (comma or space separated).
# Defaults to the interface(s) carrying the IPv4 default route.
EGRESS_INTERFACES="${WEBSOCKPROXY_EGRESS_INTERFACES:-$(ip -4 route show default | awk '{for (i = 1; i < NF; i++) if ($i == "dev") print $(i + 1)}' | sort -u)}"
EGRESS_INTERFACES="${EGRESS_INTERFACES//,/ }"
# Non-public CIDRs guests may reach anyway (comma or space separated).
ALLOWED_PRIVATE_NETS="${WEBSOCKPROXY_ALLOWED_PRIVATE_NETS:-}"
ALLOWED_PRIVATE_NETS="${ALLOWED_PRIVATE_NETS//,/ }"

if [ -z "${EGRESS_INTERFACES//[[:space:]]/}" ]; then
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
if ! ip link show dev "$TAP" >/dev/null 2>&1; then
    ip tuntap add dev "$TAP" mode tap
fi
ip addr replace "$GATEWAY" dev "$TAP"
ip link set dev "$TAP" mtu 1500
ip link set dev "$TAP" up

## IP forwarding and firewall for the TAP device ##
# Guest traffic may only leave through EGRESS_INTERFACES, and only to public
# addresses or ALLOWED_PRIVATE_NETS. Guest rules live in their own chains,
# entered only for traffic to or from the TAP device, and no chain policies
# are changed, so traffic on other interfaces is left alone.
echo 1 > /proc/sys/net/ipv4/ip_forward

# Guests may only use this machine for DHCP, DNS and ping.
fresh_chain iptables filter GUEST_INPUT
iptables -A GUEST_INPUT -p udp --dport 67 -j ACCEPT
iptables -A GUEST_INPUT -p udp --dport 53 -j ACCEPT
iptables -A GUEST_INPUT -p tcp --dport 53 -j ACCEPT
iptables -A GUEST_INPUT -p icmp -j ACCEPT
iptables -A GUEST_INPUT -j DROP
jump_to iptables filter GUEST_INPUT INPUT -i "$TAP"

fresh_chain iptables filter GUEST_EGRESS
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
fresh_chain iptables filter GUEST_FORWARD
fresh_chain iptables nat GUEST_NAT
iptables -A GUEST_FORWARD -o "$TAP" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A GUEST_FORWARD -o "$TAP" -j DROP
for iface in $EGRESS_INTERFACES; do
    iptables -A GUEST_FORWARD -o "$iface" -j GUEST_EGRESS
    iptables -t nat -A GUEST_NAT -o "$iface" -j MASQUERADE
done
iptables -A GUEST_FORWARD -j DROP
jump_to iptables filter GUEST_FORWARD FORWARD -i "$TAP"
jump_to iptables filter GUEST_FORWARD FORWARD -o "$TAP"
jump_to iptables nat GUEST_NAT POSTROUTING -s "$GUEST_SUBNET"

# Guests get no IPv6 routing; don't let them reach this machine over it
# (e.g. via link-local addresses) either.
if ip6tables -n -L >/dev/null 2>&1; then
    fresh_chain ip6tables filter GUEST_INPUT6
    ip6tables -A GUEST_INPUT6 -j DROP
    jump_to ip6tables filter GUEST_INPUT6 INPUT -i "$TAP"
    fresh_chain ip6tables filter GUEST_FORWARD6
    ip6tables -A GUEST_FORWARD6 -j DROP
    jump_to ip6tables filter GUEST_FORWARD6 FORWARD -i "$TAP"
    jump_to ip6tables filter GUEST_FORWARD6 FORWARD -o "$TAP"
fi
