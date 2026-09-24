import asyncio

import pytest
import websockets

from websockproxy import switchedrelay

from conftest import GATEWAY_MAC, MAC_A, frame, masked_frame, raw_ws_connect, read_frame, wait_until

PING, CLOSE = 0x9, 0x8


@pytest.fixture
def fast_keepalive(monkeypatch):
    monkeypatch.setattr(switchedrelay, 'PING_INTERVAL', 0.1)
    monkeypatch.setattr(switchedrelay, 'PING_TIMEOUT', 0.1)


async def read_opcodes_until_eof(reader):
    opcodes = []
    try:
        while True:
            opcodes.append((await read_frame(reader))[0])
    except asyncio.IncompleteReadError:
        return opcodes


async def test_unresponsive_client_is_pinged_then_dropped(fast_keepalive, tap):
    async with switchedrelay.serve('127.0.0.1', 0) as server:
        port = server.sockets[0].getsockname()[1]
        reader, writer = await raw_ws_connect(port)
        writer.write(masked_frame(0x2, frame(GATEWAY_MAC, MAC_A)))
        await wait_until(lambda: MAC_A in switchedrelay.macmap)

        opcodes = await asyncio.wait_for(read_opcodes_until_eof(reader), 2)
        writer.close()

        assert PING in opcodes
        await wait_until(lambda: MAC_A not in switchedrelay.macmap)


async def test_responsive_client_stays_connected(fast_keepalive, tap):
    async with switchedrelay.serve('127.0.0.1', 0) as server:
        port = server.sockets[0].getsockname()[1]
        async with websockets.connect(f'ws://127.0.0.1:{port}', ping_interval=None) as ws:
            await asyncio.sleep(0.5)  # several ping intervals

            f = frame(GATEWAY_MAC, MAC_A)
            await ws.send(f)
            await wait_until(lambda: tap.written == [f])
