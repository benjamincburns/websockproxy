import asyncio
import base64
import os
import socket

import pytest

from websockproxy import switchedrelay


GATEWAY_MAC = b'\x02\x00\x00\x00\x00\x01'
MAC_A = b'\x02\xaa\xaa\xaa\xaa\xaa'
MAC_B = b'\x02\xbb\xbb\xbb\xbb\xbb'
MAC_C = b'\x02\xcc\xcc\xcc\xcc\xcc'
BROADCAST = b'\xff\xff\xff\xff\xff\xff'


def frame(dst, src, payload=b'\x08\x00' + b'\x00' * 46):
    """Build a minimal Ethernet frame."""
    return dst + src + payload


class FakeTap:
    """Stand-in for pytun.TunTapDevice.

    Backed by a socketpair so the event loop can watch a real fd. Queue
    frames (or exceptions to raise) with inject(); each one makes the fd
    readable once and is returned (or raised) by the next read().
    """

    def __init__(self, hwaddr=GATEWAY_MAC):
        self.hwaddr = hwaddr
        self.mtu = 1500
        self.written = []
        self.closed = False
        self._queue = []
        self._rsock, self._wsock = socket.socketpair()

    def inject(self, item):
        self._queue.append(item)
        self._wsock.send(b'x')

    def fileno(self):
        return self._rsock.fileno()

    def read(self, size):
        self._rsock.recv(1)
        item = self._queue.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item[:size]

    def write(self, data):
        self.written.append(bytes(data))

    def up(self):
        pass

    def close(self):
        self.closed = True
        self._rsock.close()
        self._wsock.close()


class FakeRequest:
    def __init__(self, headers):
        self.headers = headers


class FakeWebSocket:
    """Stand-in for a websockets ServerConnection."""

    def __init__(self, remote_address=('192.0.2.1', 50000), headers=None):
        self.remote_address = remote_address
        self.request = FakeRequest(headers or {})
        self.sent = []
        self.closed = False

    async def send(self, message):
        self.sent.append(message)

    async def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def clean_macmap():
    switchedrelay.macmap.clear()
    yield
    switchedrelay.macmap.clear()


@pytest.fixture
def tap(monkeypatch):
    """A started TunDevice backed by a FakeTap, installed as the relay's tundev."""
    fake = FakeTap()
    dev = switchedrelay.TunDevice(tun=fake)
    monkeypatch.setattr(switchedrelay, 'tundev', dev)
    return fake


async def raw_ws_connect(port, host='127.0.0.1'):
    """Open a WebSocket connection without a client library.

    Unlike a websockets client, nothing answers pings automatically, so
    this behaves like a peer that has silently gone away.
    """
    reader, writer = await asyncio.open_connection(host, port)
    key = base64.b64encode(os.urandom(16)).decode()
    writer.write(
        f'GET / HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\n'
        f'Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n'
        f'Sec-WebSocket-Version: 13\r\n\r\n'.encode()
    )
    await reader.readuntil(b'\r\n\r\n')
    return reader, writer


def masked_frame(opcode, payload):
    """Encode a client-to-server frame (masked with a zero key)."""
    assert len(payload) < 126
    return bytes([0x80 | opcode, 0x80 | len(payload)]) + b'\x00' * 4 + payload


async def read_frame(reader):
    """Read one server-to-client frame; returns (opcode, payload)."""
    b0, b1 = await reader.readexactly(2)
    length = b1 & 0x7f
    if length == 126:
        length = int.from_bytes(await reader.readexactly(2), 'big')
    elif length == 127:
        length = int.from_bytes(await reader.readexactly(8), 'big')
    return b0 & 0x0f, await reader.readexactly(length)


async def wait_until(predicate, timeout=2.0):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not predicate():
        if loop.time() > deadline:
            raise AssertionError('condition not met before timeout')
        await asyncio.sleep(0.01)
