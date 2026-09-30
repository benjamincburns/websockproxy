"""Poll configured DNS names and atomically maintain an IPv4 firewall ipset.

Guest DNS is not involved. Wildcard *records* can be queried, but DNS cannot
enumerate arbitrary subdomains. See the README for coverage and retirement.
"""

import argparse
import asyncio
from dataclasses import dataclass
import fcntl
import ipaddress
import json
import logging
import math
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time


logger = logging.getLogger(__name__)
SET_NAME = 'wsp_block4'
STAGING_SET = 'wsp_block4_next'
MAX_ADDRESSES = 65536


def setting_int(env, name, default, minimum, maximum):
    value = env.get('WEBSOCKPROXY_' + name) or str(default)
    if not re.fullmatch(r'[0-9]+', value) or not minimum <= int(value) <= maximum:
        raise ValueError(f'Invalid WEBSOCKPROXY_{name}: expected {minimum}..{maximum}')
    return int(value)


def domain_name(value):
    name = value.rstrip('.').lower().encode('idna').decode('ascii')
    labels = name.split('.')
    host_labels = labels[1:] if labels[0] == '*' else labels
    if len(host_labels) < 2 or len(name) > 253 or any(
        not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
        for label in host_labels
    ):
        raise ValueError(f'Invalid DNS name in WEBSOCKPROXY_BLOCKED_DOMAINS: {value}')
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return name
    raise ValueError(f'Expected a DNS name, not an IP address: {value}')


@dataclass(frozen=True)
class Config:
    names: tuple
    refresh: int = 300
    grace: int = 3600
    state_file: Path = Path('/var/lib/websockproxy/blocklist.json')
    nameservers: tuple = ()

    @classmethod
    def from_env(cls, env=None):
        env = os.environ if env is None else env
        names = tuple(sorted({domain_name(name) for name in
                              env.get('WEBSOCKPROXY_BLOCKED_DOMAINS', '').replace(',', ' ').split()}))
        if len(names) > 256:
            raise ValueError('WEBSOCKPROXY_BLOCKED_DOMAINS supports at most 256 names')
        servers = tuple(str(ipaddress.ip_address(server)) for server in
                        env.get('WEBSOCKPROXY_BLOCKLIST_DNS_SERVERS', '').replace(',', ' ').split())
        return cls(
            names,
            setting_int(env, 'BLOCKLIST_REFRESH', 300, 5, 86400),
            setting_int(env, 'BLOCKLIST_RETIRE_GRACE', 3600, 0, 604800),
            Path(env.get('WEBSOCKPROXY_BLOCKLIST_STATE') or '/var/lib/websockproxy/blocklist.json'),
            servers,
        )


class State:
    """Each name/type owns its addresses; the firewall sees their union."""

    def __init__(self, config, records=None):
        self.config = config
        keys = {f'{name}/{kind}' for name in config.names for kind in ('A', 'AAAA')}
        self.records = {key: value for key, value in (records or {}).items() if key in keys}

    def success(self, key, addresses, ttl, now):
        record = self.records.setdefault(key, {'addresses': {}, 'next_poll': 0})
        previous = record['addresses']
        for address in addresses:
            previous[address] = {'expires': now + ttl, 'missing_since': None}
        for address in list(previous):
            if address in addresses:
                continue
            item = previous[address]
            if item['missing_since'] is None:
                item['missing_since'] = now
            # TTL expiry alone never retires an IP. Only a successful lookup
            # which still omits it may retire it, after TTL and grace expire.
            if now >= max(item['expires'], item['missing_since'] + self.config.grace):
                del previous[address]
        record['next_poll'] = now + max(5, min(ttl, self.config.refresh))

    def addresses(self, version):
        return {ip for record in self.records.values() for ip in record['addresses']
                if ipaddress.ip_address(ip).version == version}

    @classmethod
    def load(cls, config):
        try:
            raw = json.loads(config.state_file.read_text())
        except FileNotFoundError:
            return cls(config)
        # Corrupt state is fatal: silently discarding it could unblock victims.
        try:
            if raw['version'] != 1 or not isinstance(raw['records'], dict):
                raise ValueError('unsupported format')
            state = cls(config, raw['records'])
            for key, record in state.records.items():
                valid_timestamp(record['next_poll'])
                version = 4 if key.endswith('/A') else 6
                for ip, item in record['addresses'].items():
                    if ipaddress.ip_address(ip).version != version:
                        raise ValueError('address family mismatch')
                    valid_timestamp(item['expires'])
                    if item['missing_since'] is not None:
                        valid_timestamp(item['missing_since'])
            return state
        except (KeyError, TypeError, AttributeError, ValueError) as exc:
            raise ValueError(f'Invalid blocklist state in {config.state_file}: {exc}') from exc

    def save(self):
        path = self.config.state_file
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as output:
                temporary = Path(output.name)
                json.dump({'version': 1, 'records': self.records}, output, sort_keys=True)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)


def valid_timestamp(value):
    if not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ValueError('invalid timestamp')


class DNSResolver:
    def __init__(self, config):
        # Only users of this optional helper need the abuse extra.
        import dns.asyncresolver
        self.resolver = dns.asyncresolver.Resolver()
        if config.nameservers:
            self.resolver.nameservers = list(config.nameservers)
        self.resolver.lifetime = 5
        self.config = config

    async def resolve(self, name, kind):
        import dns.resolver
        try:
            answer = await self.resolver.resolve(name + '.', kind, search=False,
                                                 raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN as exc:
            # NXDOMAIN is a successful negative answer, unlike SERVFAIL or a
            # timeout. Use the negative TTL, including CNAME-chain TTLs.
            ttls = [response.resolve_chaining().minimum_ttl
                    for response in exc.responses().values()]
            return set(), min(ttls, default=self.config.refresh)
        addresses = {str(ipaddress.ip_address(item.address)) for item in answer}
        # Answer.expiration includes the shortest TTL in a CNAME/DNAME chain.
        ttl = max(0, answer.expiration - time.time())
        return addresses, ttl


class IPSet:
    def __init__(self):
        for name in (SET_NAME, STAGING_SET):
            self.run('create', name, 'hash:ip', 'family', 'inet',
                     'maxelem', str(MAX_ADDRESSES), '-exist')

    @staticmethod
    def run(*args, **kwargs):
        return subprocess.run(['ipset', *args], check=True, timeout=30, **kwargs)

    def publish(self, addresses):
        if len(addresses) > MAX_ADDRESSES:
            raise ValueError('DNS blocklist exceeds the 65536-address limit')
        # The live set is never flushed. A failed restore leaves it untouched.
        commands = [f'flush {STAGING_SET}']
        for address in sorted(addresses):
            address = str(ipaddress.IPv4Address(address))
            if address == '0.0.0.0':
                # hash:ip cannot contain zero; guest special-address rules
                # already block 0.0.0.0/8.
                continue
            commands.append(f'add {STAGING_SET} {address}')
        self.run('restore', input='\n'.join(commands) + '\n', text=True)
        self.run('swap', STAGING_SET, SET_NAME)


class Poller:
    def __init__(self, config, state, resolver, ipset):
        self.config, self.state = config, state
        self.resolver, self.ipset = resolver, ipset
        self.retry_at = {}

    async def refresh(self, initial=False):
        import dns.exception
        now = time.time()
        semaphore = asyncio.Semaphore(16)

        async def query(name, kind):
            key = f'{name}/{kind}'
            record = self.state.records.get(key)
            due = self.retry_at.get(key, record['next_poll'] if record else 0)
            if not initial and now < due:
                return
            async with semaphore:
                try:
                    addresses, ttl = await self.resolver.resolve(name, kind)
                except dns.exception.DNSException as exc:
                    logger.warning('DNS refresh failed for %s; retaining previous addresses: %s', key, exc)
                    self.retry_at[key] = time.time() + min(30, self.config.refresh)
                    if initial and record is None:
                        return key
                    return
            self.retry_at.pop(key, None)
            self.state.success(key, addresses, ttl, time.time())

        failures = await asyncio.gather(*(query(name, kind) for name in self.config.names
                                         for kind in ('A', 'AAAA')))
        # Save partial successes too, so repeated startup failures can recover.
        self.state.save()
        self.ipset.publish(self.state.addresses(4))
        if any(failures):
            raise RuntimeError('No saved DNS result for: ' + ', '.join(key for key in failures if key))
        logger.info('DNS blocklist: %d IPv4 addresses blocked; %d IPv6 addresses tracked '
                    '(all guest IPv6 is blocked)',
                    len(self.state.addresses(4)), len(self.state.addresses(6)))

    def delay(self):
        now = time.time()
        due = [self.retry_at.get(key, record['next_poll'])
               for key, record in self.state.records.items()]
        return max(1, min(due, default=now + self.config.refresh) - now)

    async def run(self, once):
        # Restore persisted protection before making potentially slow queries.
        self.ipset.publish(self.state.addresses(4))
        await self.refresh(initial=True)
        while not once:
            await asyncio.sleep(self.delay())
            await self.refresh()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--once', action='store_true', help='refresh once, then exit')
    parser.add_argument('--check', action='store_true', help='validate configuration without changes')
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    try:
        config = Config.from_env()
        if args.check or not config.names:
            return
        config.state_file.parent.mkdir(parents=True, exist_ok=True)
        with config.state_file.with_suffix('.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            state = State.load(config)
            asyncio.run(Poller(config, state, DNSResolver(config), IPSet()).run(args.once))
    except (ValueError, OSError, RuntimeError, ImportError, subprocess.SubprocessError) as exc:
        logger.error('Blocklist stopped: %s', exc)
        raise SystemExit(1) from exc


if __name__ == '__main__':
    main()
