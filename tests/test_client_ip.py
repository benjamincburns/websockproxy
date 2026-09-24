import ipaddress

import pytest

from websockproxy import switchedrelay
from websockproxy.switchedrelay import ClientHandler

from conftest import FakeWebSocket


@pytest.fixture
def trust(monkeypatch):
    def set_trusted(*networks):
        monkeypatch.setattr(switchedrelay, 'TRUSTED_PROXIES',
                            [ipaddress.ip_network(n) for n in networks])
    return set_trusted


def remote_ip(peer, forwarded_for=None):
    headers = {'X-Forwarded-For': forwarded_for} if forwarded_for else {}
    return ClientHandler(FakeWebSocket((peer, 1234), headers)).remote_ip


def test_forwarded_for_is_ignored_from_untrusted_peer(trust):
    trust()
    assert remote_ip('198.51.100.1', '203.0.113.9') == '198.51.100.1'


def test_uses_peer_address_without_header(trust):
    trust('127.0.0.1/32')
    assert remote_ip('127.0.0.1') == '127.0.0.1'


def test_trusted_proxy_uses_rightmost_address(trust):
    trust('127.0.0.1/32')
    # The client controls everything left of what our proxy appended.
    assert remote_ip('127.0.0.1', '192.0.2.66, 203.0.113.9') == '203.0.113.9'


def test_skips_chained_trusted_proxies(trust):
    trust('10.0.0.0/8')
    assert remote_ip('10.0.0.1', '203.0.113.9, 10.0.0.2') == '203.0.113.9'


def test_ignores_malformed_forwarded_for_entry(trust):
    trust('127.0.0.1/32')
    assert remote_ip('127.0.0.1', 'not-an-ip') == '127.0.0.1'
