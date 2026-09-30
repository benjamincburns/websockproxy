import os
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('setting,value', [
    ('DESTINATION_CONNECT_RATE', '-1'), ('DESTINATION_CONNECT_RATE', '100'),
    ('DESTINATION_CONNECT_RATE', '1/second;true'), ('DESTINATION_PACKET_RATE', '1/day'),
    ('DESTINATION_CONNECT_BURST', '0'), ('DESTINATION_PACKET_BURST', '-1'),
    ('DESTINATION_BYTE_RATE', '1'), ('DESTINATION_BYTE_BURST', '1'),
    ('DESTINATION_BYTE_RATE', '1mb/s'),
])
def test_bad_rate_configuration_fails_before_network_changes(setting, value):
    env = {key: val for key, val in os.environ.items() if not key.startswith('WEBSOCKPROXY_')}
    env['WEBSOCKPROXY_' + setting] = value
    # Validation precedes even the ip6tables probe and device creation.
    result = subprocess.run(['bash', str(ROOT / 'scripts/setup-network.sh')], env=env,
                            capture_output=True, text=True)
    assert result.returncode != 0
    assert 'WEBSOCKPROXY_' + setting in result.stderr


def test_disabled_configuration_needs_no_optional_commands():
    env = {key: val for key, val in os.environ.items() if not key.startswith('WEBSOCKPROXY_')}
    result = subprocess.run(['bash', '-euc', 'source "$1"; test "$ABUSE_ENABLED" = 0',
                             'test', str(ROOT / 'scripts/abuse-network.sh')],
                            env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
