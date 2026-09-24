import asyncio

import pytest
from scapy.all import ARP, BOOTP, DHCP, DNS, DNSRR, ICMP, IP, UDP, Ether, raw

import test_ping
from test_ping import WebSocketNIC

GATEWAY_MAC = '02:00:00:00:00:01'
GATEWAY_IP = '10.5.0.1'
OUR_IP = '10.5.0.50'
TARGET_IP = '93.184.216.34'


class FakeNetwork:
    """Stand-in for the relay's websocket.

    Each frame sent is passed to ``responder``, which returns reply frames;
    the replies are delivered to the NIC on the next event loop iteration.
    """

    def __init__(self, responder, yield_after_send=False):
        self.responder = responder
        self.yield_after_send = yield_after_send
        self.nic = None
        self.sent = []

    async def send(self, frame_bytes):
        pkt = Ether(frame_bytes)
        self.sent.append(pkt)
        loop = asyncio.get_running_loop()
        for reply in self.responder(pkt):
            loop.call_soon(self.nic._dispatch, Ether(raw(reply)))
        if self.yield_after_send:
            # Like a real websocket send() waiting for the transport to drain
            await asyncio.sleep(0)


def lan(pkt):
    """Answer the NIC's requests like the relay's LAN would."""
    if pkt.haslayer(BOOTP) and pkt[BOOTP].op == 1:
        return [dhcp_reply(pkt, _dhcp_type(pkt) == 1 and 'offer' or 'ack')]
    if pkt.haslayer(ARP) and pkt[ARP].op == 1:
        return [arp_reply(pkt)]
    if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
        return [dns_reply(pkt, [DNSRR(rrname=pkt[DNS].qd[0].qname, type='A', rdata=TARGET_IP)])]
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
        return [echo_reply(pkt)]
    return []


def _dhcp_type(pkt):
    return dict(o for o in pkt[DHCP].options if isinstance(o, tuple))['message-type']


def dhcp_reply(request, message_type, xid=None, yiaddr=OUR_IP):
    return (
        Ether(src=GATEWAY_MAC, dst='ff:ff:ff:ff:ff:ff')
        / IP(src=GATEWAY_IP, dst='255.255.255.255')
        / UDP(sport=67, dport=68)
        / BOOTP(op=2, xid=request[BOOTP].xid if xid is None else xid,
                yiaddr=yiaddr, siaddr=GATEWAY_IP, chaddr=request[BOOTP].chaddr)
        / DHCP(options=[('message-type', message_type), ('server_id', GATEWAY_IP),
                        ('router', GATEWAY_IP), ('name_server', GATEWAY_IP),
                        ('subnet_mask', '255.255.0.0'), 'end'])
    )


def arp_reply(request, psrc=None, hwsrc=GATEWAY_MAC):
    return Ether(src=hwsrc, dst=request[Ether].src) / ARP(
        op='is-at', hwsrc=hwsrc, psrc=psrc or request[ARP].pdst,
        hwdst=request[ARP].hwsrc, pdst=request[ARP].psrc,
    )


def echo_reply(request, **icmp_overrides):
    icmp = {'id': request[ICMP].id, 'seq': request[ICMP].seq, **icmp_overrides}
    return (
        Ether(src=GATEWAY_MAC, dst=request[Ether].src)
        / IP(src=request[IP].dst, dst=request[IP].src)
        / ICMP(type=0, **icmp)
        / request[ICMP].payload
    )


def make_nic(responder=lan, yield_after_send=False):
    net = FakeNetwork(responder, yield_after_send)
    nic = WebSocketNIC(net)
    net.nic = nic
    nic.ip = OUR_IP
    nic.gateway_ip = GATEWAY_IP
    nic.gateway_mac = GATEWAY_MAC
    nic.dns_server = GATEWAY_IP
    return nic, net


def dns_reply(query, answers, id=None, dport=None):
    """Build a reply to ``query`` carrying the given resource records."""
    return (
        Ether(src=GATEWAY_MAC, dst=query[Ether].src)
        / IP(src=query[IP].dst, dst=query[IP].src)
        / UDP(sport=53, dport=query[UDP].sport if dport is None else dport)
        / DNS(id=query[DNS].id if id is None else id, qr=1, rd=1, ra=1,
              qd=query[DNS].qd, an=answers)
    )


async def test_dns_resolve_follows_cname_to_a_record():
    def responder(pkt):
        return [dns_reply(pkt, [
            DNSRR(rrname='www.example.com', type='CNAME', rdata='example.com'),
            DNSRR(rrname='example.com', type='A', rdata='93.184.216.34'),
        ])]

    nic, _ = make_nic(responder)

    assert await nic.dns_resolve('www.example.com') == '93.184.216.34'


OPERATIONS = {
    'dhcp': lambda nic: nic.dhcp_acquire(),
    'arp': lambda nic: nic.arp_resolve(GATEWAY_IP),
    'dns': lambda nic: nic.dns_resolve('example.com'),
    'ping': lambda nic: nic.ping(TARGET_IP, count=1, timeout=1),
}


@pytest.mark.parametrize('operation', OPERATIONS)
async def test_reply_arriving_while_send_is_in_progress_is_not_lost(operation):
    nic, _ = make_nic(yield_after_send=True)

    result = await asyncio.wait_for(OPERATIONS[operation](nic), 3)

    if operation == 'ping':
        assert None not in result


def answering(decoys_for, then=lan):
    """A responder that sends decoy replies ahead of the genuine ones."""
    def responder(pkt):
        return decoys_for(pkt) + then(pkt)
    return responder


def is_dhcp(pkt, message_type):
    return pkt.haslayer(BOOTP) and pkt[BOOTP].op == 1 and _dhcp_type(pkt) == message_type


async def test_dhcp_ignores_offers_for_other_transactions_and_clients():
    def decoys(pkt):
        if not is_dhcp(pkt, 1):
            return []
        other_client = dhcp_reply(pkt, 'offer', yiaddr='10.5.0.98')
        other_client[BOOTP].chaddr = bytes.fromhex('02bbbbbbbbbb')
        return [dhcp_reply(pkt, 'offer', xid=pkt[BOOTP].xid ^ 1, yiaddr='10.5.0.99'), other_client]

    nic, net = make_nic(answering(decoys))
    await nic.dhcp_acquire()

    requested = dict(o for o in net.sent[1][DHCP].options if isinstance(o, tuple))
    assert requested['requested_addr'] == OUR_IP
    assert nic.ip == OUR_IP


async def test_dhcp_does_not_mistake_repeated_offer_for_ack():
    def decoys(pkt):
        return [dhcp_reply(pkt, 'offer', yiaddr='10.5.0.99')] if is_dhcp(pkt, 3) else []

    nic, _ = make_nic(answering(decoys))
    await nic.dhcp_acquire()

    assert nic.ip == OUR_IP


async def test_dhcp_nak_is_an_error():
    def responder(pkt):
        if is_dhcp(pkt, 3):
            return [dhcp_reply(pkt, 'nak', yiaddr='0.0.0.0')]
        return lan(pkt)

    nic, _ = make_nic(responder)

    with pytest.raises(RuntimeError, match='NAK'):
        await nic.dhcp_acquire()


async def test_arp_ignores_replies_for_other_addresses():
    def decoys(pkt):
        if pkt.haslayer(ARP):
            return [arp_reply(pkt, psrc='10.5.0.77', hwsrc='02:77:77:77:77:77')]
        return []

    nic, _ = make_nic(answering(decoys))

    assert await nic.arp_resolve(GATEWAY_IP) == GATEWAY_MAC


async def test_dns_ignores_replies_to_other_queries():
    def decoys(pkt):
        if not pkt.haslayer(DNS):
            return []
        wrong = [DNSRR(rrname='example.com', type='A', rdata='6.6.6.6')]
        return [
            dns_reply(pkt, wrong, id=pkt[DNS].id ^ 1),
            dns_reply(pkt, wrong, dport=pkt[UDP].sport ^ 1),
        ]

    nic, _ = make_nic(answering(decoys))

    assert await nic.dns_resolve('example.com') == TARGET_IP


@pytest.mark.parametrize('field', ['id', 'seq'])
async def test_ping_ignores_echo_replies_for_other_requests(field):
    def responder(pkt):
        if pkt.haslayer(ICMP):
            return [echo_reply(pkt, **{field: pkt[ICMP].getfieldval(field) ^ 1})]
        return lan(pkt)

    nic, _ = make_nic(responder)

    assert await nic.ping(TARGET_IP, count=1, timeout=0.3) == [None]


def test_each_nic_gets_its_own_unicast_locally_administered_mac():
    macs = {WebSocketNIC(None).mac for _ in range(20)}

    assert len(macs) == 20
    for mac in macs:
        first_octet = int(mac.split(':')[0], 16)
        assert first_octet & 0x01 == 0  # unicast
        assert first_octet & 0x02 == 0x02  # locally administered
