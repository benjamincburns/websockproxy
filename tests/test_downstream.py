import asyncio

import pytest

from websockproxy import switchedrelay
from websockproxy.switchedrelay import ClientHandler

from conftest import BROADCAST, GATEWAY_MAC, MAC_A, MAC_B, MAC_C, FakeWebSocket, frame


class StalledWebSocket(FakeWebSocket):
    """A client that has stopped reading: send() never completes."""

    async def send(self, message):
        self.sent.append(message)
        await asyncio.get_running_loop().create_future()


@pytest.mark.parametrize('dst', [MAC_C, BROADCAST])
async def test_client_to_client_traffic_respects_receiver_downstream_limit(tap, dst):
    receiver_ws = FakeWebSocket()
    receiver = ClientHandler(receiver_ws)
    receiver.on_message(frame(GATEWAY_MAC, MAC_C))
    a, b = ClientHandler(FakeWebSocket()), ClientHandler(FakeWebSocket())

    # Each sender stays within its own upstream limit, but together they
    # send the receiver ~1.5x its downstream rate.
    payload = b'\x08\x00' + bytes(998)
    for _ in range(30):
        a.on_message(frame(dst, MAC_A, payload))
        b.on_message(frame(dst, MAC_B, payload))
    await asyncio.sleep(0)

    received = sum(len(m) for m in receiver_ws.sent)
    assert received <= switchedrelay.RATE + len(payload) + 12


async def test_pending_sends_to_stalled_client_are_bounded():
    ws = StalledWebSocket()
    client = ClientHandler(ws)
    try:
        for _ in range(500):
            client.rate_limited_downstream(frame(MAC_A, GATEWAY_MAC))
            await asyncio.sleep(0)

        assert len(ws.sent) <= switchedrelay.MAX_PENDING_SENDS
    finally:
        for task in list(switchedrelay._background_tasks):
            task.cancel()
        await asyncio.sleep(0)
