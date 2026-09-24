# WebSockets Proxy

A websocket ethernet switch built using Python's asyncio and the
[websockets](https://websockets.readthedocs.io/) library.

Implements crude rate limiting on WebSocket connections to prevent abuse. Each
client is limited to 40980 bytes per second in each direction by default; set
`WEBSOCKPROXY_RATE_LIMIT` to change the limit, or to `0` to disable it (e.g.
on a trusted local network).

Could use some cleanup!

## How it works

It's quite simple. The program starts off by creating a TAP device and listening
for websocket connections on port 80. When clients connect, ethernet frames
received via the websocket are switched between connected clients and the TAP
device. All communication is done via raw ethernet frames.

To use this in support of a virtual network you must set up the host system as
a DHCP server and router.

SSL support is not included. To enable SSL, please use a reverse proxy with SSL
and websockets support, such as nginx.

## Getting Started

### Local development

This project uses [uv](https://docs.astral.sh/uv/) for dependency management.

```shell
uv sync
```

The relay requires root privileges (for TAP device creation) and a Linux host.

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

For better security be sure to set up an Nginx reverse proxy with SSL support
along with a more isolated docker bridge and some host-side firewall rules
which prevent clients of your relay from attempting to connect to your host
machine.

When running behind a reverse proxy, set `WEBSOCKPROXY_TRUSTED_PROXIES` to a
comma-separated list of the proxy's IPs or CIDR ranges (as seen by the relay)
so client IPs are logged from `X-Forwarded-For`. The header is ignored from
any other peer, since clients could otherwise forge it:

```shell
docker run --privileged -p 8080:80 -e WEBSOCKPROXY_TRUSTED_PROXIES=172.17.0.1 --name relay websockproxy
```

#### Guest network access

By default, guests can reach the public internet, and can use the container
itself only for DHCP, DNS and ping. Traffic to non-public addresses is
dropped, including the docker host, other containers, your local network,
cloud metadata services (169.254.169.254) and CGNAT/VPN ranges. Nothing
outside can open connections to guests. Guests on the relay can always reach
each other, since the relay switches their frames directly.

Two environment variables adjust this (both take comma- or space-separated
lists):

- `WEBSOCKPROXY_EGRESS_INTERFACES`: the container interfaces guest traffic
  may leave through. Defaults to the interface(s) carrying the IPv4 default
  route. The container refuses to start if a listed interface doesn't exist.
- `WEBSOCKPROXY_ALLOWED_PRIVATE_NETS`: IPv4 CIDRs guests may reach even
  though they're non-public, such as a service on your LAN. Empty by default.

```shell
docker run --privileged -p 8080:80 -e WEBSOCKPROXY_ALLOWED_PRIVATE_NETS=192.168.1.20/32 --name relay websockproxy
```

The container can't see the host's own public addresses, so guests can
still reach services the host exposes on them. Use host-side firewall rules
to block those.

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
