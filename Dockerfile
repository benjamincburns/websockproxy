# Build stage - compile C extensions
FROM python:3.12-alpine AS builder

RUN apk add --no-cache build-base linux-headers

COPY --from=ghcr.io/astral-sh/uv:0.12.18 /uv /usr/local/bin/uv

COPY pyproject.toml uv.lock README.md LICENSE /opt/websockproxy/
COPY src/ /opt/websockproxy/src/

WORKDIR /opt/websockproxy/

# Install exactly what uv.lock pins; fail rather than re-resolve if it's stale
RUN uv sync --frozen --no-dev --no-editable

# Runtime stage
FROM python:3.12-alpine

LABEL org.opencontainers.image.authors="benjamin.c.burns@gmail.com"

RUN apk add --no-cache iptables dnsmasq iproute2 bash

COPY --from=builder /opt/websockproxy/ /opt/websockproxy/
COPY docker-image-config/dnsmasq/interface docker-image-config/dnsmasq/dhcp /etc/dnsmasq.d/
COPY docker-image-config/docker-startup.sh /opt/websockproxy/docker-startup.sh

WORKDIR /opt/websockproxy/

EXPOSE 80

CMD ["/opt/websockproxy/docker-startup.sh"]
