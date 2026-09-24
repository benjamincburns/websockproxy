import socket

import pytest

from websockproxy import switchedrelay

from conftest import FakeTap


@pytest.fixture
def fake_tap(monkeypatch):
    taps = []

    def make_tap(**kwargs):
        taps.append(FakeTap())
        return taps[-1]

    monkeypatch.setattr(switchedrelay, 'TunTapDevice', make_tap)
    return taps


def test_main_exits_nonzero_when_port_is_in_use(monkeypatch, fake_tap):
    with socket.socket() as busy:
        busy.bind(('127.0.0.1', 0))
        busy.listen()
        monkeypatch.setattr(switchedrelay, 'HOST', '127.0.0.1')
        monkeypatch.setattr(switchedrelay, 'PORT', busy.getsockname()[1])

        with pytest.raises(SystemExit) as excinfo:
            switchedrelay.main()

    assert excinfo.value.code != 0
    assert fake_tap[0].closed
