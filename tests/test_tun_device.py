import asyncio
import errno
import logging

import pytest

from websockproxy import switchedrelay
from websockproxy.switchedrelay import ClientHandler, TunDevice

from conftest import BROADCAST, GATEWAY_MAC, MAC_A, FakeTap, FakeWebSocket, frame, wait_until


@pytest.fixture
async def started():
    fake = FakeTap()
    dev = TunDevice(tun=fake)
    dev.start()
    yield fake, dev
    dev.stop()


@pytest.fixture
def client_ws():
    ws = FakeWebSocket()
    switchedrelay.macmap[MAC_A] = ClientHandler(ws)
    return ws


@pytest.mark.parametrize('code', [errno.EAGAIN, errno.EINTR])
async def test_transient_read_error_keeps_device_running(started, client_ws, code):
    fake, dev = started
    fake.inject(OSError(code, 'transient'))
    f = frame(BROADCAST, GATEWAY_MAC)
    fake.inject(f)

    await wait_until(lambda: client_ws.sent == [f])
    assert not fake.closed


async def test_fatal_read_error_is_logged_and_reported(started, caplog):
    fake, dev = started
    fake.inject(OSError(errno.EIO, 'device gone'))

    with caplog.at_level(logging.ERROR, logger='relay'):
        with pytest.raises(OSError) as excinfo:
            await asyncio.wait_for(dev.failed, 1)

    assert excinfo.value.errno == errno.EIO
    assert fake.closed
    assert any(r.exc_info for r in caplog.records)


async def test_run_exits_when_tap_device_fails(monkeypatch, tap):
    monkeypatch.setattr(switchedrelay, 'HOST', '127.0.0.1')
    monkeypatch.setattr(switchedrelay, 'PORT', 0)
    task = asyncio.create_task(switchedrelay.run())
    await asyncio.sleep(0.05)

    tap.inject(OSError(errno.EIO, 'device gone'))

    with pytest.raises(OSError) as excinfo:
        await asyncio.wait_for(task, 1)
    assert excinfo.value.errno == errno.EIO
    assert tap.closed
