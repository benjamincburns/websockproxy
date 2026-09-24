import asyncio

from websockproxy import switchedrelay
from websockproxy.switchedrelay import ClientHandler, TunDevice

from conftest import BROADCAST, GATEWAY_MAC, MAC_A, MAC_B, MAC_C, FakeTap, FakeWebSocket, frame


async def settle():
    """Let fire-and-forget send tasks run."""
    for _ in range(3):
        await asyncio.sleep(0)


async def test_unicast_frame_to_gateway_is_written_to_tap(tap):
    client = ClientHandler(FakeWebSocket())
    f = frame(GATEWAY_MAC, MAC_A)

    client.on_message(f)

    assert tap.written == [f]


async def test_tun_device_start_uses_running_loop():
    fake = FakeTap()
    dev = TunDevice(tun=fake)
    ws = FakeWebSocket()
    client = ClientHandler(ws)
    switchedrelay.macmap[MAC_A] = client

    dev.start()
    try:
        f = frame(BROADCAST, GATEWAY_MAC)
        fake.inject(f)
        await asyncio.sleep(0.05)
        await settle()
    finally:
        dev.stop()

    assert ws.sent == [f]
    assert fake.closed


async def test_disconnect_leaves_mac_owned_by_another_client(tap):
    a = ClientHandler(FakeWebSocket())
    b = ClientHandler(FakeWebSocket())
    a.on_message(frame(GATEWAY_MAC, MAC_A))
    b.on_message(frame(GATEWAY_MAC, MAC_A))

    a.on_close()

    assert switchedrelay.macmap.get(MAC_A) is b


async def test_mac_change_leaves_mac_owned_by_another_client(tap):
    a = ClientHandler(FakeWebSocket())
    b = ClientHandler(FakeWebSocket())
    a.on_message(frame(GATEWAY_MAC, MAC_A))
    b.on_message(frame(GATEWAY_MAC, MAC_A))

    a.on_message(frame(GATEWAY_MAC, MAC_C))

    assert switchedrelay.macmap.get(MAC_A) is b
    assert switchedrelay.macmap.get(MAC_C) is a
