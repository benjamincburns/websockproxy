import subprocess
from unittest.mock import Mock

import dns.exception
import dns.message
import dns.rcode
import dns.resolver
import dns.rrset
import pytest

from websockproxy.blocklist import Config, DNSResolver, IPSet, Poller, State


@pytest.fixture
def config(tmp_path):
    return Config(('one.example', 'two.example'), refresh=60, grace=30,
                  state_file=tmp_path / 'blocklist.json')


def test_config_is_opt_in_and_normalizes_names():
    assert Config.from_env({}).names == ()
    config = Config.from_env({'WEBSOCKPROXY_BLOCKED_DOMAINS':
                             ' Example.COM., *.Example.COM example.com '})
    assert config.names == ('*.example.com', 'example.com')


@pytest.mark.parametrize('value', ['https://example.com', 'x.*.example.com',
                                  'example.com/evil', '-bad.example', '192.0.2.1',
                                  'example..com', 'a' * 64 + '.example'])
def test_invalid_domains_are_rejected(value):
    with pytest.raises(ValueError):
        Config.from_env({'WEBSOCKPROXY_BLOCKED_DOMAINS': value})


@pytest.mark.parametrize('setting,value', [
    ('BLOCKLIST_REFRESH', '0'), ('BLOCKLIST_REFRESH', 'nan'),
    ('BLOCKLIST_RETIRE_GRACE', '-1'), ('BLOCKLIST_DNS_SERVERS', 'example.com'),
])
def test_invalid_settings_are_rejected(setting, value):
    with pytest.raises(ValueError):
        Config.from_env({'WEBSOCKPROXY_' + setting: value})


def test_rotation_adds_immediately_and_retires_after_ttl_and_grace(config):
    state = State(config)
    state.success('one.example/A', {'192.0.2.1', '192.0.2.2'}, ttl=100, now=0)
    state.success('one.example/A', {'192.0.2.3'}, ttl=5, now=80)
    assert state.addresses(4) == {'192.0.2.1', '192.0.2.2', '192.0.2.3'}
    state.success('one.example/A', {'192.0.2.3'}, ttl=5, now=109)
    assert '192.0.2.1' in state.addresses(4)
    state.success('one.example/A', {'192.0.2.3'}, ttl=5, now=110)
    assert state.addresses(4) == {'192.0.2.3'}


def test_a_long_ttl_outlives_the_grace_period(config):
    state = State(config)
    state.success('one.example/A', {'192.0.2.1'}, ttl=1000, now=0)
    state.success('one.example/A', set(), ttl=60, now=10)
    state.success('one.example/A', set(), ttl=60, now=100)
    assert state.addresses(4) == {'192.0.2.1'}
    state.success('one.example/A', set(), ttl=60, now=1000)
    assert state.addresses(4) == set()


def test_address_is_retained_while_another_name_still_uses_it(config):
    state = State(config)
    for name in config.names:
        state.success(name + '/A', {'192.0.2.1'}, ttl=5, now=0)
    state.success('one.example/A', set(), ttl=5, now=5)
    state.success('one.example/A', set(), ttl=5, now=40)
    assert state.addresses(4) == {'192.0.2.1'}
    state.success('two.example/A', set(), ttl=5, now=40)
    state.success('two.example/A', set(), ttl=5, now=70)
    assert state.addresses(4) == set()


def test_reappearing_address_resets_retirement(config):
    state = State(config)
    state.success('one.example/A', {'192.0.2.1'}, ttl=5, now=0)
    state.success('one.example/A', set(), ttl=5, now=10)
    state.success('one.example/A', {'192.0.2.1'}, ttl=5, now=30)
    state.success('one.example/A', set(), ttl=5, now=50)
    assert state.addresses(4) == {'192.0.2.1'}


def test_state_survives_restart_and_prunes_removed_configuration(config):
    state = State(config)
    state.success('one.example/A', {'192.0.2.1'}, ttl=5, now=0)
    state.success('two.example/A', {'192.0.2.2'}, ttl=5, now=0)
    state.success('one.example/AAAA', {'2001:db8::1'}, ttl=5, now=0)
    state.success('one.example/A', set(), ttl=5, now=10)
    state.save()
    restored = State.load(Config(('one.example',), grace=30, state_file=config.state_file))
    assert restored.addresses(4) == {'192.0.2.1'}
    assert restored.addresses(6) == {'2001:db8::1'}
    restored.success('one.example/A', set(), ttl=5, now=40)
    assert restored.addresses(4) == set()


@pytest.mark.parametrize('content', ['{', '{"version":2,"records":{}}',
    '{"version":1,"records":{"one.example/A":{"addresses":{"bad":{}},"next_poll":0}}}',
])
def test_corrupt_state_is_not_silently_discarded(config, content):
    config.state_file.write_text(content)
    with pytest.raises(ValueError):
        State.load(config)


class FakeResolver:
    def __init__(self, result):
        self.result = result

    async def resolve(self, name, kind):
        result = self.result[name, kind]
        if isinstance(result, Exception):
            raise result
        return result


async def test_dns_failure_preserves_expired_addresses_but_successful_negative_retires(config):
    state = State(config)
    results = {}
    for name in config.names:
        for kind in ('A', 'AAAA'):
            state.success(f'{name}/{kind}', set(), ttl=5, now=0)
            results[name, kind] = (set(), 5)
    state.success('one.example/A', {'192.0.2.1'}, ttl=5, now=0)
    state.success('one.example/A', set(), ttl=5, now=10)
    results['one.example', 'A'] = dns.exception.Timeout()
    ipset = Mock()
    poller = Poller(config, state, FakeResolver(results), ipset)
    await poller.refresh(initial=True)
    assert state.addresses(4) == {'192.0.2.1'}
    assert 'one.example/A' in poller.retry_at
    results['one.example', 'A'] = (set(), 5)
    await poller.refresh(initial=True)
    assert state.addresses(4) == set()


async def test_initial_failure_without_saved_answer_prevents_startup(config):
    results = {(name, kind): dns.exception.Timeout() for name in config.names
               for kind in ('A', 'AAAA')}
    with pytest.raises(RuntimeError, match='No saved DNS result'):
        await Poller(config, State(config), FakeResolver(results), Mock()).refresh(initial=True)


async def test_refresh_preserves_other_family_when_one_lookup_fails(config):
    state = State(config)
    results = {(name, kind): (set(), 5) for name in config.names for kind in ('A', 'AAAA')}
    for key in ('one.example/A', 'one.example/AAAA'):
        state.success(key, {'192.0.2.1'} if key.endswith('/A') else {'2001:db8::1'}, 5, 0)
    results['one.example', 'AAAA'] = dns.exception.Timeout()
    results['one.example', 'A'] = ({'192.0.2.2'}, 5)
    await Poller(config, state, FakeResolver(results), Mock()).refresh(initial=True)
    assert state.addresses(6) == {'2001:db8::1'}
    assert '192.0.2.2' in state.addresses(4)


def make_answer(name, kind, rrsets, negative=False):
    query = dns.message.make_query(name, kind)
    response = dns.message.make_response(query)
    if negative:
        response.set_rcode(dns.rcode.NXDOMAIN)
    response.answer.extend(rrsets)
    response.authority.append(dns.rrset.from_text('example.', 120, 'IN', 'SOA',
                             'ns.example. hostmaster.example. 1 60 60 60 30'))
    # Parse as a real resolver would, rebuilding dnspython's RRset index.
    return query, dns.message.from_wire(response.to_wire())


async def test_dns_resolver_follows_cname_and_collects_all_addresses(config):
    resolver = DNSResolver(config)
    query, response = make_answer('one.example.', 'A', [
        dns.rrset.from_text('one.example.', 10, 'IN', 'CNAME', 'target.example.'),
        dns.rrset.from_text('target.example.', 100, 'IN', 'A', '192.0.2.1', '192.0.2.2'),
    ])

    async def resolve(*args, **kwargs):
        return dns.resolver.Answer(query.question[0].name, 1, 1, response)

    resolver.resolver.resolve = resolve
    addresses, ttl = await resolver.resolve('one.example', 'A')
    assert addresses == {'192.0.2.1', '192.0.2.2'}
    assert 0 < ttl <= 10


@pytest.mark.parametrize('nxdomain', [False, True])
async def test_negative_dns_answers_are_successful_empty_results(config, nxdomain):
    resolver = DNSResolver(config)
    query, response = make_answer('one.example.', 'A', [], negative=nxdomain)

    async def resolve(*args, **kwargs):
        if nxdomain:
            raise dns.resolver.NXDOMAIN(qnames=[query.question[0].name],
                                       responses={query.question[0].name: response})
        return dns.resolver.Answer(query.question[0].name, 1, 1, response)

    resolver.resolver.resolve = resolve
    addresses, ttl = await resolver.resolve('one.example', 'A')
    assert addresses == set()
    assert 0 < ttl <= 30


def test_failed_ipset_restore_never_swaps_or_flushes_live_set(monkeypatch):
    run = Mock()
    monkeypatch.setattr(IPSet, 'run', run)
    ipset = IPSet()
    run.reset_mock()
    run.side_effect = subprocess.CalledProcessError(1, 'ipset restore')
    with pytest.raises(subprocess.CalledProcessError):
        ipset.publish({'192.0.2.1'})
    assert run.call_count == 1
    assert run.call_args.args == ('restore',)
    assert 'flush wsp_block4\n' not in run.call_args.kwargs['input']


def test_poller_honors_ttl_and_refresh_ceiling(config):
    state = State(config)
    state.success('one.example/A', {'192.0.2.1'}, ttl=10, now=100)
    state.success('one.example/AAAA', set(), ttl=1000, now=100)
    assert state.records['one.example/A']['next_poll'] == 110
    assert state.records['one.example/AAAA']['next_poll'] == 160
