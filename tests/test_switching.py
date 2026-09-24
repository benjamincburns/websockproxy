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


async def test_rejected_claimant_disconnect_leaves_owner_entry(tap):
    a = ClientHandler(FakeWebSocket())
    b = ClientHandler(FakeWebSocket())
    a.on_message(frame(GATEWAY_MAC, MAC_A))
    b.on_message(frame(GATEWAY_MAC, MAC_A))

    b.on_close()

    assert switchedrelay.macmap.get(MAC_A) is a


async def test_rejected_claimant_mac_change_leaves_owner_entry(tap):
    a = ClientHandler(FakeWebSocket())
    b = ClientHandler(FakeWebSocket())
    a.on_message(frame(GATEWAY_MAC, MAC_A))
    b.on_message(frame(GATEWAY_MAC, MAC_A))

    b.on_message(frame(GATEWAY_MAC, MAC_C))

    assert switchedrelay.macmap.get(MAC_A) is a
    assert switchedrelay.macmap.get(MAC_C) is b


async def test_client_cannot_hijack_mac_of_another_client(tap):
    a_ws, b_ws, c_ws = FakeWebSocket(), FakeWebSocket(), FakeWebSocket()
    a, b, c = ClientHandler(a_ws), ClientHandler(b_ws), ClientHandler(c_ws)
    a.on_message(frame(GATEWAY_MAC, MAC_A))
    c.on_message(frame(GATEWAY_MAC, MAC_C))
    tap.written.clear()

    spoofed = frame(GATEWAY_MAC, MAC_A)
    b.on_message(spoofed)
    to_a = frame(MAC_A, MAC_C)
    c.on_message(to_a)
    await settle()

    assert switchedrelay.macmap[MAC_A] is a
    assert tap.written == []
    assert a_ws.sent == [to_a]
    assert b_ws.sent == []


async def test_client_cannot_claim_gateway_mac(tap):
    a_ws, b_ws = FakeWebSocket(), FakeWebSocket()
    a, b = ClientHandler(a_ws), ClientHandler(b_ws)
    a.on_message(frame(GATEWAY_MAC, MAC_A))
    tap.written.clear()

    b.on_message(frame(BROADCAST, GATEWAY_MAC))
    to_gateway = frame(GATEWAY_MAC, MAC_A)
    a.on_message(to_gateway)
    await settle()

    assert GATEWAY_MAC not in switchedrelay.macmap
    assert tap.written == [to_gateway]
    assert a_ws.sent == []


async def test_client_cannot_use_multicast_source_mac(tap):
    client = ClientHandler(FakeWebSocket())

    client.on_message(frame(GATEWAY_MAC, b'\x01\x00\x5e\x00\x00\x01'))
    client.on_message(frame(GATEWAY_MAC, BROADCAST))

    assert switchedrelay.macmap == {}
    assert tap.written == []


async def test_mac_can_be_reused_after_owner_disconnects(tap):
    a = ClientHandler(FakeWebSocket())
    b = ClientHandler(FakeWebSocket())
    a.on_message(frame(GATEWAY_MAC, MAC_A))
    a.on_close()

    b.on_message(frame(GATEWAY_MAC, MAC_A))

    assert switchedrelay.macmap[MAC_A] is b


async def test_broadcast_goes_to_other_clients_and_tap_but_not_sender(tap):
    a_ws, b_ws = FakeWebSocket(), FakeWebSocket()
    a, b = ClientHandler(a_ws), ClientHandler(b_ws)
    b.on_message(frame(GATEWAY_MAC, MAC_B))
    tap.written.clear()

    f = frame(BROADCAST, MAC_A)
    a.on_message(f)
    await settle()

    assert a_ws.sent == []
    assert b_ws.sent == [f]
    assert tap.written == [f]


async def test_text_message_is_dropped(tap):
    client = ClientHandler(FakeWebSocket())

    client.on_message('x' * 60)

    assert switchedrelay.macmap == {}
    assert tap.written == []


async def test_runt_frame_is_dropped(tap):
    client = ClientHandler(FakeWebSocket())

    client.on_message(GATEWAY_MAC + MAC_A[:4])
    client.on_message(GATEWAY_MAC + MAC_A + b'\x08')

    assert switchedrelay.macmap == {}
    assert tap.written == []


async def test_throttled_frames_do_not_change_mac(tap):
    client = ClientHandler(FakeWebSocket())
    client.on_message(frame(GATEWAY_MAC, MAC_A))
    client.upstream.allowance = -1e9  # far over its upstream limit

    client.on_message(frame(GATEWAY_MAC, MAC_B))

    assert switchedrelay.macmap == {MAC_A: client}
