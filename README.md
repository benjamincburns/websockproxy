# WebSockets Proxy

A websocket ethernet switch built using Python's asyncio and the
[websockets](https://websockets.readthedocs.io/) library.

Implements crude rate limiting on WebSocket connections to prevent abuse.

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

### Testing

A test script is included that connects to the relay via WebSocket, obtains a
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
