#!/usr/bin/env bash
# Sourced by setup-network.sh. Validate everything before changing networking.
# No optional firewall extensions are needed when all features are disabled.

CONNECT_RATE=${WEBSOCKPROXY_DESTINATION_CONNECT_RATE:-0}
CONNECT_BURST=${WEBSOCKPROXY_DESTINATION_CONNECT_BURST:-10}
PACKET_RATE=${WEBSOCKPROXY_DESTINATION_PACKET_RATE:-0}
PACKET_BURST=${WEBSOCKPROXY_DESTINATION_PACKET_BURST:-100}
BYTE_RATE=${WEBSOCKPROXY_DESTINATION_BYTE_RATE:-0}
BYTE_BURST=${WEBSOCKPROXY_DESTINATION_BYTE_BURST:-65536}
BLOCKED_DOMAINS=${WEBSOCKPROXY_BLOCKED_DOMAINS:-}
BLOCKED_DOMAINS=${BLOCKED_DOMAINS//,/ }
ABUSE_ENABLED=0

abuse_error() {
    echo "Invalid WEBSOCKPROXY_$1: $2" >&2
    exit 1
}

abuse_integer() {
    local name=$1 value=$2 minimum=$3 maximum=$4
    [[ "$value" =~ ^(0|[1-9][0-9]{0,9})$ ]] \
        && (( value >= minimum && value <= maximum )) \
        || abuse_error "$name" "$value (expected $minimum..$maximum)"
}

# Compute idle expiry longer than the time needed to refill the whole bucket.
# Otherwise expiring an idle hash entry can reset its burst prematurely.
abuse_expiry() {
    local name=$1 rate=$2 burst=$3 period=1 amount
    if [[ "$rate" == 0 ]]; then
        echo 60000
        return
    fi
    [[ "$rate" =~ ^([1-9][0-9]{0,6})/(second|minute)$ ]] \
        || abuse_error "$name" "$rate (expected 0 or N/second or N/minute)"
    amount=${BASH_REMATCH[1]}
    [[ ${BASH_REMATCH[2]} != minute ]] || period=60
    local expiry=$(( (burst * period * 1000 + amount - 1) / amount + 1000 ))
    (( expiry >= 60000 )) || expiry=60000
    (( expiry <= 2147483647 )) || abuse_error "$name" "burst refill time is too large"
    echo "$expiry"
}

abuse_integer DESTINATION_CONNECT_BURST "$CONNECT_BURST" 1 1000000
abuse_integer DESTINATION_PACKET_BURST "$PACKET_BURST" 1 1000000
abuse_integer DESTINATION_BYTE_RATE "$BYTE_RATE" 0 1000000000
abuse_integer DESTINATION_BYTE_BURST "$BYTE_BURST" 1500 1000000000
if (( BYTE_RATE != 0 && BYTE_RATE < 1024 )); then
    abuse_error DESTINATION_BYTE_RATE 'use 0 (disabled) or at least 1024 bytes/second'
fi
CONNECT_EXPIRY=$(abuse_expiry DESTINATION_CONNECT_RATE "$CONNECT_RATE" "$CONNECT_BURST")
PACKET_EXPIRY=$(abuse_expiry DESTINATION_PACKET_RATE "$PACKET_RATE" "$PACKET_BURST")
BYTE_EXPIRY=60000
if (( BYTE_RATE != 0 )); then
    BYTE_EXPIRY=$(( (BYTE_BURST * 1000 + BYTE_RATE - 1) / BYTE_RATE + 1000 ))
    (( BYTE_EXPIRY >= 60000 )) || BYTE_EXPIRY=60000
fi
if [[ -n ${BLOCKED_DOMAINS//[[:space:]]/} || $CONNECT_RATE != 0 || $PACKET_RATE != 0 || $BYTE_RATE != 0 ]]; then
    ABUSE_ENABLED=1
    # The guest network is IPv4-only. An enabled policy must not silently leave
    # IPv6 available when the IPv6 firewall cannot be installed.
    ip6tables -n -L >/dev/null
fi

abuse_limit() {
    local name=$1 rate=$2 burst=$3 expiry=$4; shift 4
    # Only destination IP is in the key: ports and guest source addresses share
    # one budget, including across multiple egress interfaces.
    iptables -A GUEST_ABUSE "$@" -m hashlimit \
        --hashlimit-above "$rate" --hashlimit-burst "$burst" \
        --hashlimit-mode dstip --hashlimit-dstmask 32 --hashlimit-name "$name" \
        --hashlimit-htable-max 65536 --hashlimit-htable-expire "$expiry" -j DROP
}

install_abuse_rules() {
    fresh_chain iptables filter GUEST_ABUSE
    if [[ -n ${BLOCKED_DOMAINS//[[:space:]]/} ]]; then
        ipset create wsp_block4 hash:ip family inet maxelem 65536 -exist
        # Match all packets, including packets on established connections.
        iptables -A GUEST_ABUSE -m set --match-set wsp_block4 dst -j DROP
    fi
    if [[ $CONNECT_RATE != 0 ]]; then
        abuse_limit wsp_connect "$CONNECT_RATE" "$CONNECT_BURST" "$CONNECT_EXPIRY" \
            -p tcp --syn -m conntrack --ctstate NEW
    fi
    if [[ $PACKET_RATE != 0 ]]; then
        abuse_limit wsp_packet "$PACKET_RATE" "$PACKET_BURST" "$PACKET_EXPIRY"
    fi
    if [[ $BYTE_RATE != 0 ]]; then
        abuse_limit wsp_byte "${BYTE_RATE}b/second" "${BYTE_BURST}b" "$BYTE_EXPIRY"
    fi
}
