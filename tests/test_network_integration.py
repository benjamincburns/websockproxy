"""Real packets in disposable namespaces; opt in explicitly and run as root.

WEBSOCKPROXY_RUN_NETWORK_TESTS=1 python -m pytest tests/test_network_integration.py
Requires iproute2, iptables/ip6tables, ipset and network namespace privileges.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

import pytest


pytestmark = pytest.mark.skipif(
    os.environ.get('WEBSOCKPROXY_RUN_NETWORK_TESTS') != '1' or os.geteuid() != 0,
    reason='opt-in root/network-namespace integration tests',
)
ROOT = Path(__file__).resolve().parents[1]


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True)


class Network:
    def __init__(self):
        prefix = 'wsp-test-' + uuid.uuid4().hex[:8]
        self.guest, self.relay, self.remote = [prefix + '-' + name for name in ('g', 'r', 's')]
        self.namespaces = []
        self.processes = []

    def command(self, namespace, *args):
        return run('ip', 'netns', 'exec', namespace, *args)

    def create(self):
        for namespace in (self.guest, self.relay, self.remote):
            run('ip', 'netns', 'add', namespace)
            self.namespaces.append(namespace)
            self.command(namespace, 'ip', 'link', 'set', 'lo', 'up')
        self.command(self.relay, 'ip', 'link', 'add', 'tap0', 'type', 'veth',
                     'peer', 'name', 'guest0')
        self.command(self.relay, 'ip', 'link', 'set', 'guest0', 'netns', self.guest)
        self.command(self.relay, 'ip', 'link', 'add', 'eth0', 'type', 'veth',
                     'peer', 'name', 'remote0')
        self.command(self.relay, 'ip', 'link', 'set', 'remote0', 'netns', self.remote)
        for namespace, interface, addresses in (
            (self.guest, 'guest0', ['10.5.0.2/16', '10.5.0.3/16']),
            (self.relay, 'eth0', ['192.0.2.254/24']),
            (self.remote, 'remote0', ['192.0.2.1/24', '192.0.2.2/24']),
        ):
            for address in addresses:
                self.command(namespace, 'ip', 'addr', 'add', address, 'dev', interface)
            self.command(namespace, 'ip', 'link', 'set', interface, 'up')
        self.command(self.guest, 'ip', 'route', 'add', 'default', 'via', '10.5.0.1')
        server = r'''
import selectors, socket
selector = selectors.DefaultSelector()
for address in ('192.0.2.1', '192.0.2.2'):
    for port in (23456, 23457):
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            sock = socket.socket(type=kind)
            sock.bind((address, port))
            if kind == socket.SOCK_STREAM:
                sock.listen()
            selector.register(sock, selectors.EVENT_READ, kind)
print('ready', flush=True)
while True:
    for key, _ in selector.select():
        if key.data == socket.SOCK_STREAM:
            conn, _ = key.fileobj.accept()
            conn.close()
        else:
            data, address = key.fileobj.recvfrom(65535)
            key.fileobj.sendto(data, address)
'''
        process = subprocess.Popen(['ip', 'netns', 'exec', self.remote, sys.executable,
                                    '-u', '-c', server], stdout=subprocess.PIPE, text=True)
        self.processes.append(process)
        assert process.stdout.readline().strip() == 'ready'

    def setup(self, **settings):
        env = {key: value for key, value in os.environ.items() if not key.startswith('WEBSOCKPROXY_')}
        env['WEBSOCKPROXY_EGRESS_INTERFACES'] = 'eth0'
        env.update({'WEBSOCKPROXY_' + key: str(value) for key, value in settings.items()})
        return subprocess.run(['ip', 'netns', 'exec', self.relay, 'bash',
                               str(ROOT / 'scripts/setup-network.sh')], env=env,
                              check=True, capture_output=True, text=True)

    def dns_server(self, state_file):
        server = r'''
import json, socket, sys
import dns.message, dns.rcode, dns.rdatatype, dns.rrset
sock = socket.socket(type=socket.SOCK_DGRAM)
sock.bind(('192.0.2.1', 53))
print('ready', flush=True)
while True:
    wire, address = sock.recvfrom(65535)
    query = dns.message.from_wire(wire)
    response = dns.message.make_response(query)
    state = json.loads(open(sys.argv[1]).read())
    response.set_rcode(dns.rcode.from_text(state['rcode']))
    if state['rcode'] == 'NOERROR':
        response.authority.append(dns.rrset.from_text('example.', 0, 'IN', 'SOA',
                                  'ns.example. hostmaster.example. 1 60 60 60 0'))
        if state['ips'] and query.question[0].rdtype == dns.rdatatype.A:
            response.answer.append(dns.rrset.from_text(query.question[0].name,
                                   0, 'IN', 'CNAME', 'target.example.'))
            response.answer.append(dns.rrset.from_text('target.example.', 0, 'IN',
                                                      'A', *state['ips']))
    sock.sendto(response.to_wire(), address)
'''
        process = subprocess.Popen(['ip', 'netns', 'exec', self.remote, sys.executable,
                                    '-u', '-c', server, str(state_file)],
                                   stdout=subprocess.PIPE, text=True)
        self.processes.append(process)
        assert process.stdout.readline().strip() == 'ready'

    def requests(self, requests, tcp=False, size=20):
        client = r'''
import json, socket, sys
requests, tcp, size = json.loads(sys.argv[1])
results = []
for source, destination, port in requests:
    with socket.socket(type=socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.15)
        sock.bind((source, 0 if tcp else 40000))
        try:
            sock.connect((destination, port))
            if not tcp:
                sock.send(b'x' * size)
                assert sock.recv(65535) == b'x' * size
            results.append(True)
        except OSError:
            results.append(False)
print(json.dumps(results))
'''
        result = self.command(self.guest, sys.executable, '-c', client,
                              json.dumps([requests, tcp, size]))
        return json.loads(result.stdout)

    def close(self):
        for process in self.processes:
            process.terminate()
            process.wait(timeout=5)
        for namespace in reversed(self.namespaces):
            run('ip', 'netns', 'del', namespace)


@pytest.fixture
def network():
    network = Network()
    try:
        network.create()
        yield network
    finally:
        network.close()


def test_disabled_policy_allows_traffic_and_setup_is_repeatable(network):
    network.setup()
    network.setup()
    assert all(network.requests([('10.5.0.2', '192.0.2.1', 23456)] * 10))
    rules = network.command(network.relay, 'iptables-save').stdout
    assert '--hashlimit' not in rules
    assert '--match-set' not in rules
    assert rules.count('-A FORWARD -i tap0 -j GUEST_FORWARD') == 1
    network.command(network.relay, 'bash', str(ROOT / 'scripts/setup-network.sh'), '--remove')
    assert 'GUEST_' not in network.command(network.relay, 'iptables-save').stdout


@pytest.mark.parametrize('tcp', [True, False])
def test_limit_is_shared_by_sources_and_ports_but_not_destinations(network, tcp):
    feature = 'CONNECT' if tcp else 'PACKET'
    network.setup(**{f'DESTINATION_{feature}_RATE': '2/minute',
                     f'DESTINATION_{feature}_BURST': 2})
    requests = [
        ('10.5.0.2', '192.0.2.1', 23456),
        ('10.5.0.3', '192.0.2.1', 23457),
        ('10.5.0.2', '192.0.2.1', 23456),
        ('10.5.0.3', '192.0.2.2', 23456),
    ]
    assert network.requests(requests, tcp=tcp) == [True, True, False, True]


def test_byte_limit_covers_established_udp_and_is_per_destination(network):
    network.setup(DESTINATION_BYTE_RATE=1024, DESTINATION_BYTE_BURST=4096)
    results = network.requests([('10.5.0.2', '192.0.2.1', 23456)] * 12, size=1200)
    assert results[0]
    assert not all(results)
    assert network.requests([('10.5.0.3', '192.0.2.2', 23457)], size=1200) == [True]


def test_ipset_update_blocks_established_traffic_and_removal_restores_it(network):
    network.setup(BLOCKED_DOMAINS='victim.example', ALLOWED_PRIVATE_NETS='192.0.2.1/32')
    request = [('10.5.0.2', '192.0.2.1', 23456)]
    assert network.requests(request) == [True]
    # Same UDP 5-tuple is already ESTABLISHED; the denylist must still apply.
    network.command(network.relay, 'ipset', 'add', 'wsp_block4', '192.0.2.1')
    assert network.requests(request) == [False]
    assert network.requests(request, tcp=True) == [False]
    assert network.requests([('10.5.0.2', '192.0.2.2', 23456)]) == [True]
    network.command(network.relay, 'ipset', 'del', 'wsp_block4', '192.0.2.1')
    assert network.requests(request) == [True]


def test_dns_poller_updates_real_firewall_and_retains_on_failure(network, tmp_path):
    network.setup(BLOCKED_DOMAINS='victim.example')
    # Real DNS messages, CNAMEs, persistent history, atomic IP sets and packets;
    # everything stays inside these namespaces, with no public DNS or victims.
    dns_state = tmp_path / 'dns.json'
    network.dns_server(dns_state)
    for rcode, ips, allowed in [
        ('NOERROR', ['192.0.2.1', '192.0.2.2'], [False, False]),
        ('SERVFAIL', [], [False, False]),
        ('NOERROR', ['192.0.2.2'], [True, False]),
        ('NXDOMAIN', [], [True, True]),
    ]:
        dns_state.write_text(json.dumps({'rcode': rcode, 'ips': ips}))
        network.command(network.relay, 'env', 'WEBSOCKPROXY_BLOCKED_DOMAINS=victim.example',
                        'WEBSOCKPROXY_BLOCKLIST_DNS_SERVERS=192.0.2.1',
                        'WEBSOCKPROXY_BLOCKLIST_RETIRE_GRACE=0',
                        f'WEBSOCKPROXY_BLOCKLIST_STATE={tmp_path / "state.json"}',
                        sys.executable, '-m', 'websockproxy.blocklist', '--once')
        assert network.requests([('10.5.0.2', ip, 23456) for ip in
                                 ('192.0.2.1', '192.0.2.2')]) == allowed
