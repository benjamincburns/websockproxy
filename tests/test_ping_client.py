import asyncio

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, Ether, raw

import test_ping
from test_ping import WebSocketNIC

GATEWAY_MAC = '02:00:00:00:00:01'
GATEWAY_IP = '10.5.0.1'
OUR_IP = '10.5.0.50'


class FakeNetwork:
    """Stand-in for the relay's websocket.

    Each frame sent is passed to ``responder``, which returns reply frames;
    the replies are delivered to the NIC on the next event loop iteration.
    """

    def __init__(self, responder=lambda pkt: []):
        self.responder = responder
        self.nic = None
        self.sent = []

    async def send(self, frame_bytes):
        pkt = Ether(frame_bytes)
        self.sent.append(pkt)
        loop = asyncio.get_running_loop()
        for reply in self.responder(pkt):
            loop.call_soon(self.nic._dispatch, Ether(raw(reply)))


def make_nic(responder=lambda pkt: []):
    net = FakeNetwork(responder)
    nic = WebSocketNIC(net)
    net.nic = nic
    nic.ip = OUR_IP
    nic.gateway_ip = GATEWAY_IP
    nic.gateway_mac = GATEWAY_MAC
    nic.dns_server = GATEWAY_IP
    return nic, net


def dns_reply(query, answers):
    """Build a reply to ``query`` carrying the given resource records."""
    return (
        Ether(src=GATEWAY_MAC, dst=query[Ether].src)
        / IP(src=query[IP].dst, dst=query[IP].src)
        / UDP(sport=53, dport=query[UDP].sport)
        / DNS(id=query[DNS].id, qr=1, rd=1, ra=1, qd=query[DNS].qd, an=answers)
    )


async def test_dns_resolve_follows_cname_to_a_record():
    def responder(pkt):
        return [dns_reply(pkt, [
            DNSRR(rrname='www.example.com', type='CNAME', rdata='example.com'),
            DNSRR(rrname='example.com', type='A', rdata='93.184.216.34'),
        ])]

    nic, _ = make_nic(responder)

    assert await nic.dns_resolve('www.example.com') == '93.184.216.34'
