import os
import subprocess
import sys

import pytest

from websockproxy import switchedrelay
from websockproxy.switchedrelay import ClientHandler

from conftest import GATEWAY_MAC, MAC_A, FakeWebSocket, frame


def relay_setting(name, env):
    """Import the relay in a fresh interpreter and return a setting.

    ``env`` overrides environment variables; a value of None unsets one.
    """
    full_env = {**os.environ, **env}
    for key in [k for k, v in env.items() if v is None]:
        del full_env[key]
    result = subprocess.run(
        [sys.executable, '-c', f'from websockproxy import switchedrelay; print(repr(switchedrelay.{name}))'],
        env=full_env, capture_output=True, text=True,
    )
    return result.returncode, result.stdout.strip(), result.stderr


@pytest.mark.parametrize('value, expected', [
    (None, '40980.0'),
    ('', '40980.0'),
    ('0', '0.0'),
    ('1234.5', '1234.5'),
])
def test_rate_limit_setting(value, expected):
    code, out, err = relay_setting('RATE', {'WEBSOCKPROXY_RATE_LIMIT': value})

    assert code == 0, err
    assert out == expected


@pytest.mark.parametrize('value', ['fast', '-1', 'nan'])
def test_invalid_rate_limit_is_rejected(value):
    code, _, err = relay_setting('RATE', {'WEBSOCKPROXY_RATE_LIMIT': value})

    assert code != 0
    assert 'WEBSOCKPROXY_RATE_LIMIT' in err


async def test_zero_rate_limit_lets_clients_send_unthrottled(monkeypatch, tap):
    monkeypatch.setattr(switchedrelay, 'RATE', 0)
    client = ClientHandler(FakeWebSocket())
    frames = [frame(GATEWAY_MAC, MAC_A, b'\x08\x00' + bytes(1498)) for _ in range(200)]

    for f in frames:
        client.on_message(f)

    assert len(tap.written) == 200


@pytest.mark.parametrize('value, expected', [
    (None, "'0.0.0.0'"),
    ('127.0.0.1', "'127.0.0.1'"),
    ('::', "'::'"),
])
def test_host_setting(value, expected):
    code, out, err = relay_setting('HOST', {'WEBSOCKPROXY_HOST': value})

    assert code == 0, err
    assert out == expected


@pytest.mark.parametrize('value, expected', [(None, '80'), ('8080', '8080'), (' 443 ', '443')])
def test_port_setting(value, expected):
    code, out, err = relay_setting('PORT', {'WEBSOCKPROXY_PORT': value})

    assert code == 0, err
    assert out == expected


@pytest.mark.parametrize('value', ['http', '0', '65536', '-80', '80.5', '8²'])
def test_invalid_port_is_rejected(value):
    code, _, err = relay_setting('PORT', {'WEBSOCKPROXY_PORT': value})

    assert code != 0
    assert 'WEBSOCKPROXY_PORT' in err
