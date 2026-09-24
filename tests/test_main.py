import os
import signal
import socket
import subprocess
import sys

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


RELAY_WITH_FAKE_TAP = '''
import sys
sys.path.insert(0, {tests_dir!r})
from conftest import FakeTap
from websockproxy import switchedrelay
switchedrelay.TunTapDevice = lambda **kwargs: FakeTap()
switchedrelay.HOST = '127.0.0.1'
switchedrelay.PORT = 0
switchedrelay.main()
'''


def test_sigterm_shuts_down_cleanly():
    tests_dir = os.path.dirname(__file__)
    proc = subprocess.Popen(
        [sys.executable, '-c', RELAY_WITH_FAKE_TAP.format(tests_dir=tests_dir)],
        stderr=subprocess.PIPE, text=True,
    )
    try:
        for line in proc.stderr:
            if 'listening' in line:
                break
        proc.send_signal(signal.SIGTERM)
        output = proc.stderr.read()
        proc.wait(timeout=5)
    finally:
        proc.kill()

    assert proc.returncode == 0, output
    assert 'Goodbye' in output
