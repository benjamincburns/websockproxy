#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "scapy>=2.6",
#     "websockets>=14.0,<17",
# ]
# ///
"""
Test client for websockproxy — obtains a DHCP lease via the relay,
resolves a hostname with DNS, then sends ICMP echo requests.

Usage:
    uv run test_ping.py [ws://host:port] [hostname]

Defaults: ws://localhost:8080  www.google.com
"""

import asyncio
import ipaddress
import logging
import random
import sys
import time

import websockets
from scapy.all import (
    ARP,
    BOOTP,
    DHCP,
    DNS,
    DNSQR,
    Ether,
    ICMP,
    IP,
    Raw,
    UDP,
    raw,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(message)s")
logger = logging.getLogger(__name__)

DHCP_OFFER, DHCP_ACK, DHCP_NAK = 2, 5, 6
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def random_mac():
    """A random unicast, locally administered MAC address.

    The relay won't let two clients use the same MAC, so each run needs
    its own.
    """
    octets = [random.randint(0, 255) for _ in range(6)]
    octets[0] = (octets[0] & 0xFC) | 0x02
    return ":".join(f"{o:02x}" for o in octets)


class WebSocketNIC:
    """Minimal network stack over WebSocket-tunneled Ethernet frames."""

    def __init__(self, ws):
        self.ws = ws
        self.mac = random_mac()
        self.ip = None
        self.gateway_ip = None
        self.gateway_mac = None
        self.dns_server = None
        self.subnet_mask = None
        self._server_id = None
        self._xid = None
        self._pending = {}
        self._recv_task = None

    async def start(self):
        self._recv_task = asyncio.create_task(self._recv_loop())

    async def stop(self):
        if self._recv_task:
            self._recv_task.cancel()
            try:
                await self._recv_task
            except asyncio.CancelledError:
                pass

    async def send_frame(self, frame_bytes):
        await self.ws.send(frame_bytes)

    # ── receive / dispatch ───────────────────────────────────────────

    async def _recv_loop(self):
        try:
            async for message in self.ws:
                if isinstance(message, bytes):
                    try:
                        self._dispatch(Ether(message))
                    except Exception:
                        pass
        except websockets.exceptions.ConnectionClosed:
            pass

    def _dispatch(self, pkt):
        if pkt.haslayer(BOOTP) and pkt[BOOTP].op == 2:
            self._resolve("dhcp", pkt)
        elif pkt.haslayer(ARP) and pkt[ARP].op == 2:
            self._resolve("arp", pkt)
        elif pkt.haslayer(DNS) and pkt[DNS].qr == 1:
            self._resolve("dns", pkt)
        elif pkt.haslayer(ICMP) and pkt[ICMP].type == 0:
            self._resolve("icmp", pkt)

    def _resolve(self, key, pkt):
        fut, matches = self._pending.get(key, (None, None))
        if fut and not fut.done() and matches(pkt):
            fut.set_result(pkt)

    async def _exchange(self, frame, key, matches, timeout=10):
        """Send a frame and wait for a reply dispatched under ``key``.

        Only replies for which ``matches(reply)`` is true are accepted, so
        replies to other clients' (or earlier) requests are ignored. The
        waiter is registered before sending, so a reply that arrives while
        send() is still in progress isn't lost.
        """
        fut = asyncio.get_running_loop().create_future()
        self._pending[key] = (fut, matches)
        try:
            await self.send_frame(raw(frame))
            return await asyncio.wait_for(fut, timeout=timeout)
        finally:
            self._pending.pop(key, None)

    # ── DHCP ─────────────────────────────────────────────────────────

    async def dhcp_acquire(self):
        self._xid = random.randint(0, 0xFFFFFFFF)
        xid = self._xid
        chaddr = bytes.fromhex(self.mac.replace(":", ""))

        # Discover
        logger.info("DHCP  Sending Discover...")
        discover = (
            Ether(src=self.mac, dst=BROADCAST_MAC)
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(chaddr=chaddr, xid=xid, flags=0x8000)
            / DHCP(options=[("message-type", "discover"), "end"])
        )
        def ours(pkt, *message_types):
            return (
                pkt[BOOTP].xid == xid
                and pkt[BOOTP].chaddr[:6] == chaddr
                and _dhcp_opts(pkt).get("message-type") in message_types
            )

        offer = await self._exchange(discover, "dhcp", lambda p: ours(p, DHCP_OFFER))
        offered_ip = offer[BOOTP].yiaddr
        opts = _dhcp_opts(offer)
        server_id = opts.get("server_id", offer[BOOTP].siaddr)
        logger.info(f"DHCP  Offer: {offered_ip} from {server_id}")

        # Request
        logger.info("DHCP  Sending Request...")
        request = (
            Ether(src=self.mac, dst=BROADCAST_MAC)
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(chaddr=chaddr, xid=xid, flags=0x8000)
            / DHCP(
                options=[
                    ("message-type", "request"),
                    ("requested_addr", offered_ip),
                    ("server_id", server_id),
                    "end",
                ]
            )
        )
        ack = await self._exchange(request, "dhcp", lambda p: ours(p, DHCP_ACK, DHCP_NAK))
        if _dhcp_opts(ack)["message-type"] == DHCP_NAK:
            raise RuntimeError(f"DHCP  Server NAKed our request for {offered_ip}")
        self.ip = ack[BOOTP].yiaddr
        ack_opts = _dhcp_opts(ack)
        self.gateway_ip = ack_opts.get("router", server_id)
        self.dns_server = ack_opts.get("name_server", self.gateway_ip)
        self.subnet_mask = ack_opts.get("subnet_mask", "255.255.0.0")
        self._server_id = server_id
        logger.info(
            f"DHCP  ACK  ip={self.ip}  gw={self.gateway_ip}  "
            f"dns={self.dns_server}  mask={self.subnet_mask}"
        )

    async def dhcp_release(self):
        """Send DHCP Release to free the lease."""
        if not self.ip or not self._server_id:
            return
        logger.info(f"DHCP  Releasing {self.ip}...")
        chaddr = bytes.fromhex(self.mac.replace(":", ""))
        release = (
            Ether(src=self.mac, dst=BROADCAST_MAC)
            / IP(src=self.ip, dst=self._server_id)
            / UDP(sport=68, dport=67)
            / BOOTP(
                chaddr=chaddr,
                xid=self._xid,
                ciaddr=self.ip,
            )
            / DHCP(
                options=[
                    ("message-type", "release"),
                    ("server_id", self._server_id),
                    "end",
                ]
            )
        )
        await self.send_frame(raw(release))
        logger.info(f"DHCP  Released {self.ip}")

    # ── ARP ──────────────────────────────────────────────────────────

    async def arp_resolve(self, target_ip):
        logger.info(f"ARP   Who has {target_ip}?")
        pkt = Ether(src=self.mac, dst=BROADCAST_MAC) / ARP(
            op="who-has",
            hwsrc=self.mac,
            psrc=self.ip,
            hwdst="00:00:00:00:00:00",
            pdst=target_ip,
        )
        reply = await self._exchange(
            pkt, "arp", lambda p: p[ARP].psrc == target_ip, timeout=5
        )
        mac = reply[ARP].hwsrc
        logger.info(f"ARP   {target_ip} is-at {mac}")
        return mac

    # ── DNS ──────────────────────────────────────────────────────────

    async def dns_resolve(self, hostname):
        logger.info(f"DNS   Resolving {hostname}...")
        sport = random.randint(1024, 65535)
        query_id = random.randint(0, 0xFFFF)
        pkt = (
            Ether(src=self.mac, dst=self.gateway_mac)
            / IP(src=self.ip, dst=self.dns_server)
            / UDP(sport=sport, dport=53)
            / DNS(id=query_id, rd=1, qd=DNSQR(qname=hostname))
        )
        reply = await self._exchange(
            pkt,
            "dns",
            lambda p: p[DNS].id == query_id and p.haslayer(UDP) and p[UDP].dport == sport,
            timeout=5,
        )
        for ans in reply[DNS].an:
            if ans.type == 1:  # A record (possibly after CNAMEs)
                logger.info(f"DNS   {hostname} -> {ans.rdata}")
                return ans.rdata
        raise RuntimeError(f"No A record in DNS response for {hostname}")

    # ── ICMP ping ────────────────────────────────────────────────────

    async def ping(self, target_ip, count=4, timeout=5):
        results = []
        ping_id = random.randint(0, 0xFFFF)
        for seq in range(1, count + 1):
            pkt = (
                Ether(src=self.mac, dst=self.gateway_mac)
                / IP(src=self.ip, dst=target_ip)
                / ICMP(type=8, id=ping_id, seq=seq)
                / Raw(load=bytes(56))
            )
            t0 = time.monotonic()
            try:
                await self._exchange(
                    pkt,
                    "icmp",
                    lambda p, seq=seq: (
                        p[IP].src == target_ip
                        and p[ICMP].id == ping_id
                        and p[ICMP].seq == seq
                    ),
                    timeout=timeout,
                )
                rtt = (time.monotonic() - t0) * 1000
                logger.info(f"PING  Reply from {target_ip}: seq={seq} time={rtt:.1f}ms")
                results.append(rtt)
            except asyncio.TimeoutError:
                logger.info(f"PING  Request timeout: seq={seq}")
                results.append(None)
            if seq < count:
                await asyncio.sleep(1)
        return results


def _dhcp_opts(pkt):
    """Extract DHCP options into a dict."""
    return {
        opt[0]: opt[1]
        for opt in pkt[DHCP].options
        if isinstance(opt, tuple) and len(opt) >= 2
    }


# ── main ─────────────────────────────────────────────────────────────


async def main():
    url = sys.argv[1] if len(sys.argv) > 1 else "ws://localhost:8080"
    hostname = sys.argv[2] if len(sys.argv) > 2 else "www.google.com"

    try:
        target_ip = ipaddress.ip_address(hostname)
    except ValueError:
        target_ip = None  # a hostname; resolved via DNS below
    if target_ip is not None and target_ip.version != 4:
        logger.error(f"IPv6 targets aren't supported: {hostname}")
        return 2

    logger.info(f"Connecting to {url} ...")
    async with websockets.connect(url) as ws:
        nic = WebSocketNIC(ws)
        await nic.start()
        try:
            await nic.dhcp_acquire()
            nic.gateway_mac = await nic.arp_resolve(nic.gateway_ip)
            if target_ip is None:
                target_ip = await nic.dns_resolve(hostname)
            else:
                target_ip = str(target_ip)

            logger.info(f"PING  {hostname} ({target_ip}) ...")
            results = await nic.ping(target_ip, count=4)

            # Summary
            received = [r for r in results if r is not None]
            lost = len(results) - len(received)
            print(f"\n--- {hostname} ping statistics ---")
            print(
                f"{len(results)} transmitted, {len(received)} received, "
                f"{lost / len(results) * 100:.0f}% loss"
            )
            if received:
                print(
                    f"rtt min/avg/max = "
                    f"{min(received):.1f}/"
                    f"{sum(received) / len(received):.1f}/"
                    f"{max(received):.1f} ms"
                )
            return 0 if received else 1
        finally:
            await nic.dhcp_release()
            await nic.stop()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
