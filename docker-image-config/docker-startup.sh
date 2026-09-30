#!/usr/bin/env bash
set -euo pipefail

BLOCKLIST=/opt/websockproxy/.venv/bin/websockproxy-blocklist
"$BLOCKLIST" --check
# Seed (or restore and refresh) the denylist before opening the relay.
"$BLOCKLIST" --once

# TAP device, IP forwarding, NAT and firewall for the relay's guests
/opt/websockproxy/setup-network.sh
iptables-save

# Supervise the resolver, optional poller, and relay together. Losing the
# poller must not leave a public relay running indefinitely with stale policy.
pids=()
stop_children() {
    trap '' TERM INT
    if (( ${#pids[@]} )); then
        kill "${pids[@]}" 2>/dev/null || true
        wait "${pids[@]}" 2>/dev/null || true
        pids=()
    fi
}
trap 'stop_children; exit 0' TERM INT
trap stop_children EXIT

dnsmasq --keep-in-foreground --conf-dir=/etc/dnsmasq.d &
pids+=("$!")
domains=${WEBSOCKPROXY_BLOCKED_DOMAINS:-}
domains=${domains//,/ }
if [[ -n ${domains//[[:space:]]/} ]]; then
    "$BLOCKLIST" &
    pids+=("$!")
fi
/opt/websockproxy/.venv/bin/websockproxy &
pids+=("$!")

status=0
wait -n "${pids[@]}" || status=$?
echo "A relay service exited; stopping the container." >&2
(( status != 0 )) || status=1
exit "$status"
