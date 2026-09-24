# WebSockets Proxy

A websocket ethernet switch built using Python's asyncio and the
[websockets](https://websockets.readthedocs.io/) library.

Implements crude rate limiting on WebSocket connections to prevent abuse. Each
client is limited to 40980 bytes per second in each direction by default; see
[Configuration](#configuration) to change or disable it.

Could use some cleanup!

## How it works

It's quite simple. The program starts off by creating a TAP device and listening
for websocket connections on port 80. When clients connect, ethernet frames
received via the websocket are switched between connected clients and the TAP
device. All communication is done via raw ethernet frames.

To use this in support of a virtual network you must set up the host system as
a DHCP server and router. The Docker image does this for you; to do it on a
host yourself, see [Running on a Linux host](#running-on-a-linux-host).

TLS is not built in. To serve `wss://`, put the relay behind a reverse proxy;
see [Serving over TLS](#serving-over-tls-wss).

## Getting Started

### Local development

This project uses [uv](https://docs.astral.sh/uv/) for dependency management.

```shell
uv sync
```

The relay requires root privileges (for TAP device creation) and a Linux host.
See [Running on a Linux host](#running-on-a-linux-host) to run it outside
Docker.

### Docker

The easiest way to get up and running is via its public docker image. This
image will set up a fully contained router environment using IPTables for
basic NAT functionality and dnsmasq for DHCP support.

To set up the relay via docker simply run

```shell
docker run --privileged -p 8080:80 --name relay benjamincburns/websockproxy:latest
```

If you'd like to build the image yourself instead:

```shell
docker build -t websockproxy .
docker run --privileged -p 8080:80 --name relay websockproxy
```

Then point jor1k, your VPN client, or your emulator of choice at
ws://YOUR_HOSTNAME:8080/

Note that the container must be run in privileged mode so that it can create
its TAP device and set up IPv4 masquerading.

For a public relay, serve it over TLS from behind a reverse proxy; see
[Serving over TLS](#serving-over-tls-wss).

#### Guest network access

This applies both to the Docker image and to host installs using
`scripts/setup-network.sh`.

By default, guests can reach the public internet, and can use the relay's
machine (or container) only for DHCP, DNS and ping. Traffic to non-public addresses is
dropped, including the docker host, other containers, your local network,
cloud metadata services (169.254.169.254) and CGNAT/VPN ranges. Nothing
outside can open connections to guests. Guests on the relay can always reach
each other, since the relay switches their frames directly.

`WEBSOCKPROXY_EGRESS_INTERFACES` and `WEBSOCKPROXY_ALLOWED_PRIVATE_NETS`
adjust this (see [Configuration](#configuration)). For example, to let guests
reach one machine on your LAN:

```shell
docker run --privileged -p 8080:80 -e WEBSOCKPROXY_ALLOWED_PRIVATE_NETS=192.168.1.20/32 --name relay websockproxy
```

In Docker, the container can't see the host's own public addresses, so
guests can still reach services the host exposes on them. Use host-side
firewall rules to block those. (On a host install, traffic to the host's own
addresses is covered by the rules above.)

### Running on a Linux host

To run the relay without Docker you need a Linux host with root access,
[uv](https://docs.astral.sh/uv/), a C compiler and kernel headers (to build
`python-pytun`), and `iproute2`, `iptables` and `dnsmasq`. From a checkout of
this repository:

```shell
uv sync --no-dev

# tap0 (10.5.0.1/16), IPv4 forwarding, NAT and the guest firewall
sudo scripts/setup-network.sh

# DHCP and DNS for guests, on tap0 only
sudo dnsmasq -C /dev/null --conf-dir="$PWD/docker-image-config/dnsmasq" \
    --pid-file=/run/websockproxy-dnsmasq.pid

# The relay itself (root is needed to open and configure tap0)
sudo env WEBSOCKPROXY_PORT=8080 .venv/bin/websockproxy
```

Then point clients at `ws://YOUR_HOSTNAME:8080/`, or better, put the relay
behind a TLS reverse proxy (see below) and set `WEBSOCKPROXY_HOST=127.0.0.1`
so it isn't reachable directly.

What `scripts/setup-network.sh` changes on the host:

- It enables IPv4 forwarding system-wide.
- It adds iptables rules in their own `GUEST_*` chains, which only apply to
  traffic to or from `tap0`, plus NAT for the guest subnet. It doesn't change
  any chain policies or other rules.
- It's safe to re-run. The rules don't persist across reboots, and firewall
  managers such as firewalld or ufw may remove them when they reload; re-run
  the script if that happens.

To undo it, stop the relay and dnsmasq, then remove the rules and `tap0`
(IPv4 forwarding is left enabled):

```shell
sudo kill "$(cat /run/websockproxy-dnsmasq.pid)"
sudo scripts/setup-network.sh --remove
```

### Serving over TLS (wss://)

The relay only speaks plain `ws://`. For a public relay, put it behind a
reverse proxy that terminates TLS, and don't expose the relay's own port.
[Caddy](https://caddyserver.com/) and [Traefik](https://traefik.io/traefik/)
are both designed to be public-facing, proxy websockets without extra
configuration, and get and renew [Let's Encrypt](https://letsencrypt.org/)
certificates automatically using ACME.

Whichever you use, set `WEBSOCKPROXY_TRUSTED_PROXIES` to the proxy's address
as the relay sees it, so the relay logs each client's real IP from the
`X-Forwarded-For` header. The header is ignored from any other peer, since
clients could otherwise forge it.

Both need a DNS record pointing your domain (`relay.example.com` below) at the
server, and port 443 (plus port 80 for Caddy) open to the internet.

#### Caddy

1. [Install Caddy](https://caddyserver.com/docs/install).
2. Run the relay, listening on localhost only:

   ```shell
   docker run -d --privileged -p 127.0.0.1:8080:80 \
       -e WEBSOCKPROXY_TRUSTED_PROXIES=172.17.0.1 \
       --name relay benjamincburns/websockproxy:latest
   ```

   Connections through a published port reach the container from the Docker
   bridge's gateway, `172.17.0.1` on the default bridge. For a host install,
   use `WEBSOCKPROXY_HOST=127.0.0.1`, `WEBSOCKPROXY_PORT=8080` and
   `WEBSOCKPROXY_TRUSTED_PROXIES=127.0.0.1` instead.
3. Put this in your Caddyfile (`/etc/caddy/Caddyfile` for the packaged
   service) and reload Caddy:

   ```
   relay.example.com {
   	reverse_proxy 127.0.0.1:8080
   }
   ```

Caddy gets a certificate for `relay.example.com` on first use and renews it
automatically. Clients connect to `wss://relay.example.com/`. See Caddy's
[reverse proxy quick-start](https://caddyserver.com/docs/quick-starts/reverse-proxy)
and [Automatic HTTPS](https://caddyserver.com/docs/automatic-https) docs for
details.

#### Traefik

Traefik suits Docker setups, since it's configured with container labels.
This runs Traefik with a Let's Encrypt certificate resolver using the
TLS-ALPN challenge (port 443 only), and routes `relay.example.com` to the
relay:

```shell
docker network create proxy

docker run -d --name traefik --network proxy -p 443:443 \
    -v /var/run/docker.sock:/var/run/docker.sock:ro -v traefik-acme:/acme \
    traefik:v3.4 \
    --providers.docker=true --providers.docker.exposedbydefault=false \
    --entrypoints.websecure.address=:443 \
    --certificatesresolvers.myresolver.acme.email=you@example.com \
    --certificatesresolvers.myresolver.acme.storage=/acme/acme.json \
    --certificatesresolvers.myresolver.acme.tlschallenge=true

docker run -d --privileged --name relay --network proxy \
    -e WEBSOCKPROXY_TRUSTED_PROXIES="$(docker network inspect proxy -f '{{(index .IPAM.Config 0).Subnet}}')" \
    -l traefik.enable=true \
    -l 'traefik.http.routers.relay.rule=Host(`relay.example.com`)' \
    -l traefik.http.routers.relay.entrypoints=websecure \
    -l traefik.http.routers.relay.tls.certresolver=myresolver \
    -l traefik.http.services.relay.loadbalancer.server.port=80 \
    benjamincburns/websockproxy:latest
```

Giving Traefik the Docker socket gives it control of Docker; see Traefik's
[Docker provider](https://doc.traefik.io/traefik/reference/install-configuration/providers/docker/) docs for
safer alternatives, and its
[ACME reference](https://doc.traefik.io/traefik/reference/install-configuration/tls/certificate-resolvers/acme/)
for other challenge types and options.

### Testing

Unit tests for the relay and the test client run without root or a TAP
device:

```shell
uv run pytest
```

An end-to-end test script is included that connects to the relay via WebSocket, obtains a
DHCP lease, resolves a hostname with DNS, and sends ICMP pings through the
proxy. It uses [PEP 723](https://peps.python.org/pep-0723/) inline metadata,
so uv handles its dependencies automatically:

```shell
uv run test_ping.py [ws://host:port] [hostname_or_ip]
```

For example:

```shell
uv run test_ping.py ws://localhost:8080 www.google.com
uv run test_ping.py ws://localhost:8080 1.2.3.4
```

If no arguments are provided, it defaults to `ws://localhost:8080` and
`www.google.com`.

## Configuration

Everything is configured with environment variables. With Docker, pass them
with `-e NAME=value`. On a host, set them for the command that reads them,
e.g. `sudo env WEBSOCKPROXY_PORT=8080 .venv/bin/websockproxy`. An empty
variable means the default. Invalid values stop the relay (or the network
setup) at startup with an error.

### Relay

Read by the relay (`websockproxy`) when it starts.

| Variable | Default | Allowed values | Description |
|---|---|---|---|
| `WEBSOCKPROXY_HOST` | `0.0.0.0` | An IP address or hostname | Address to listen for websocket connections on. `0.0.0.0` listens on all IPv4 addresses, `::` on all IPv6 addresses (IPv6 only), `127.0.0.1` only on localhost (e.g. behind a reverse proxy on the same machine). |
| `WEBSOCKPROXY_PORT` | `80` | An integer from 1 to 65535 | Port to listen on. The Docker image listens on 80 inside the container; choose the public port with `-p`. |
| `WEBSOCKPROXY_RATE_LIMIT` | `40980` | A number ≥ 0 (decimals allowed) | Per-client limit in bytes per second, applied separately to traffic from and to each client. Clients may burst up to one second's worth. `0` disables rate limiting. |
| `WEBSOCKPROXY_TRUSTED_PROXIES` | *(none)* | Comma-separated IPv4/IPv6 addresses or CIDR ranges | Reverse proxies whose `X-Forwarded-For` header is trusted for logging client IPs. The header is ignored from any other peer. See [Serving over TLS](#serving-over-tls-wss) for values to use. |

### Guest network

Read by `scripts/setup-network.sh`, which the Docker image runs at startup;
see [Guest network access](#guest-network-access).

| Variable | Default | Allowed values | Description |
|---|---|---|---|
| `WEBSOCKPROXY_EGRESS_INTERFACES` | The interface(s) carrying the IPv4 default route | Comma- or space-separated names of existing network interfaces, other than `tap0` | Interfaces guest traffic may leave through; NAT is applied on these. Traffic to any other interface is dropped. Setup fails if there's no default route and this isn't set. |
| `WEBSOCKPROXY_ALLOWED_PRIVATE_NETS` | *(none)* | Comma- or space-separated IPv4 CIDRs (e.g. `192.168.1.20/32`) | Non-public destinations guests may reach anyway. All other non-public addresses (private ranges, loopback, link-local, CGNAT and so on) are blocked. |

### Fixed settings

These aren't configurable with environment variables:

- **Guest network:** TAP device `tap0`, gateway `10.5.0.1/16`, MTU 1500.
  These are set in `scripts/setup-network.sh`,
  `src/websockproxy/switchedrelay.py` and
  `docker-image-config/dnsmasq/interface`.
- **DHCP and DNS for guests:** addresses `10.5.0.2`–`10.5.254.254` with
  15-minute leases; guests are told to use `10.5.0.1`, `8.8.8.8` and
  `8.8.4.4` for DNS. Edit `docker-image-config/dnsmasq/dhcp` to change these,
  keeping the range inside `10.5.0.0/16` (and rebuild the image if you use
  Docker).
- **Relay internals** (constants in `src/websockproxy/switchedrelay.py`):
  keepalive pings every 30 seconds, with clients that don't answer within 30
  seconds disconnected; at most 128 queued frames per client, beyond which
  frames are dropped.
