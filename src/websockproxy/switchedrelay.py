import os
import sys
import errno
import time
import logging
import traceback
import asyncio
import socket as socket_module
import ipaddress

from pytun import TunTapDevice, IFF_TAP, IFF_NO_PI


from .limiter import RateLimitingState

import websockets


FORMAT = '%(asctime)-15s %(message)s'
RATE = 40980.0 #unit: bytes
ETHERNET_HEADER_LEN = 14 #dst mac, src mac, ethertype
BROADCAST = b'\xff\xff\xff\xff\xff\xff'
MAX_PENDING_SENDS = 128 #per client; frames beyond this are dropped
PING_INTERVAL = 30
PING_TIMEOUT = 30
HOST = '0.0.0.0'
# Proxies (IPs or CIDRs, comma-separated) whose X-Forwarded-For header is trusted.
TRUSTED_PROXIES = [ipaddress.ip_network(n.strip(), strict=False)
                   for n in os.environ.get('WEBSOCKPROXY_TRUSTED_PROXIES', '').split(',')
                   if n.strip()]
PORT = 80

logger = logging.getLogger('relay')


macmap = {}
tundev = None
_background_tasks = set()

def _is_trusted_proxy(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in network for network in TRUSTED_PROXIES)

def client_ip(peer_ip, forwarded_for):
    """Resolve a client's IP from X-Forwarded-For.

    The header is only honoured when the peer is a trusted proxy. Walking
    it from the right, the first address not belonging to a trusted proxy
    is the client; anything further left was supplied by the client and
    can't be trusted.
    """
    ip = peer_ip
    for hop in reversed(forwarded_for.split(',')):
        if not _is_trusted_proxy(ip):
            break
        hop = hop.strip()
        try:
            ipaddress.ip_address(hop)
        except ValueError:
            break
        ip = hop
    return ip

def format_mac(mac):
    return ':'.join('{0:02x}'.format(a) for a in mac)

def _fire_and_forget(coro):
    """Schedule a coroutine without leaving unhandled task exceptions.

    Used for ws.send() / ws.close() calls that mirror
    Tornado's synchronous write_message() — we don't await the result,
    so we suppress ConnectionClosed to avoid 'Task exception was never
    retrieved' warnings.
    """
    task = asyncio.ensure_future(coro)
    # The event loop only keeps weak references to tasks; hold a strong one
    # until the task finishes so it isn't garbage-collected mid-flight.
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    task.add_done_callback(_silence_connection_closed)
    return task

def _silence_connection_closed(task):
    exc = task.exception() if not task.cancelled() else None
    if exc and not isinstance(exc, websockets.exceptions.ConnectionClosed):
        logger.error('Unexpected send error: %s', exc)

class TunDevice:
    def __init__(self, tun=None):
        if tun is None:
            tun = TunTapDevice(name="tap0", flags= (IFF_TAP | IFF_NO_PI))
        self.tun = tun
        self.tun.addr = '10.5.0.1'
        self.tun.netmask = '255.255.0.0'
        self.tun.mtu = 1500
        self.tun.up()
        self.hwaddr = self.tun.hwaddr
        self._loop = None
        self._stopped = False
        self.failed = None  # future; gets the fatal error if the device dies

    def write(self, message):
        self.tun.write(message)

    def start(self):
        self._loop = asyncio.get_running_loop()
        self.failed = self._loop.create_future()
        self._loop.add_reader(self.tun.fileno(), self._on_readable)

    def stop(self):
        if self._stopped:
            return
        self._stopped = True
        try:
            self._loop.remove_reader(self.tun.fileno())
        except:
            pass
        self.tun.close()

    def _on_readable(self):
        try:
            buf = self.tun.read(self.tun.mtu+18) #MTU doesn't include header or CRC32
        except OSError as e:
            if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK, errno.EINTR):
                return
            logger.exception('TAP device read failed; shutting down.')
            self.stop()
            if not self.failed.done():
                self.failed.set_exception(e)
            return

        if len(buf):
            mac = buf[0:6]
            if mac == BROADCAST or (mac[0] & 0x1) == 1:
                logger.debug('tun -> broadcast/multicast (%d bytes, %d clients)', len(buf), len(macmap))
                for client in list(macmap.values()):
                    try:
                        client.rate_limited_downstream(buf)
                    except Exception:
                        logger.exception('%s: error sending to client', client.remote_ip)

            elif macmap.get(mac, False):
                logger.debug('tun -> unicast (%d bytes)', len(buf))
                try:
                    macmap[mac].rate_limited_downstream(buf)
                except Exception:
                    logger.exception('%s: error sending to client', macmap[mac].remote_ip)


class ClientHandler:
    def __init__(self, websocket):
        self.ws = websocket
        self.remote_ip = websocket.remote_address[0] if websocket.remote_address else 'unknown'
        forwarded_for = websocket.request.headers.get('X-Forwarded-For')
        if forwarded_for:
            self.remote_ip = client_ip(self.remote_ip, forwarded_for)
        logger.info('%s: connected.' % self.remote_ip)
        self.thread = None
        self.mac = b''
        self._rejected_mac = None
        self._pending_sends = 0
        self.allowance = RATE #unit: messages
        self.last_check = time.time() #floating-point, e.g. usec accuracy. Unit: seconds
        self.upstream = RateLimitingState(RATE, name='upstream', clientip=self.remote_ip)
        self.downstream = RateLimitingState(RATE, name='downstream', clientip=self.remote_ip)

    def rate_limited_downstream(self, message):
        # Drop frames for clients that aren't keeping up rather than
        # queueing an unbounded number of sends.
        if self._pending_sends >= MAX_PENDING_SENDS:
            return
        if self.downstream.do_throttle(message):
            self._pending_sends += 1
            task = _fire_and_forget(self.ws.send(message))
            task.add_done_callback(self._on_send_done)

    def _on_send_done(self, task):
        self._pending_sends -= 1

    def on_message(self, message):
        #TODO: log IP headers in the future

        if not isinstance(message, bytes) or len(message) < ETHERNET_HEADER_LEN:
            logger.debug('%s: dropping message that is not an ethernet frame', self.remote_ip)
            return

        #Logs which user is tied to which MAC so that we detect which user is acting maliciously
        if self.mac != message[6:12] and not self._claim_mac(message[6:12]):
            return

        dest = message[0:6]
        try:
            if dest == BROADCAST or (dest[0] & 0x1) == 1:
                if self.upstream.do_throttle(message):
                    logger.debug('%s: ws -> broadcast/multicast (%d bytes)', self.remote_ip, len(message))
                    for client in macmap.values():
                        if client is self:
                            continue
                        client.rate_limited_downstream(message)

                    tundev.write(message)
            elif macmap.get(dest, False):
                if self.upstream.do_throttle(message):
                    logger.debug('%s: ws -> unicast client (%d bytes)', self.remote_ip, len(message))
                    macmap[dest].rate_limited_downstream(message)
            else:
                if self.upstream.do_throttle(message):
                    logger.debug('%s: ws -> tun (%d bytes)', self.remote_ip, len(message))
                    tundev.write(message)

        except:
            tb = traceback.format_exc()
            logger.error('%s: error on receive. Closing\n%s' % (self.remote_ip, tb))
            try:
                _fire_and_forget(self.ws.close())
            except:
                pass

    def on_close(self):
        logger.info('%s: disconnected.' % self.remote_ip)

        if self.thread is not None:
            self.thread.running = False

        self._release_mac()

    def _claim_mac(self, mac):
        # Refuse MACs another client is using, the gateway's own MAC, and
        # group (multicast/broadcast) addresses, none of which a client may
        # send from. Otherwise a client could redirect traffic meant for
        # someone else to itself.
        owner = macmap.get(mac)
        if (mac[0] & 0x1) or mac == tundev.hwaddr or (owner is not None and owner is not self):
            if mac != self._rejected_mac:
                self._rejected_mac = mac
                logger.warning('%s: dropping frames from mac %s (in use or reserved)',
                               self.remote_ip, format_mac(mac))
            return False

        self._release_mac()
        self.mac = mac
        macmap[mac] = self
        logger.info('%s: using mac %s', self.remote_ip, format_mac(mac))
        return True

    def _release_mac(self):
        # Another client may have taken over this MAC; only remove our own entry.
        if macmap.get(self.mac) is self:
            del macmap[self.mac]

async def handler(websocket):
    client = ClientHandler(websocket)
    # Set TCP_NODELAY (equivalent to open() + set_nodelay(True))
    try:
        sock = websocket.transport.get_extra_info('socket')
        if sock:
            sock.setsockopt(socket_module.IPPROTO_TCP, socket_module.TCP_NODELAY, 1)
    except (AttributeError, OSError):
        pass
    try:
        async for message in websocket:
            client.on_message(message)
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        client.on_close()

def serve(host, port):
    # websockets pings every PING_INTERVAL seconds and closes connections
    # whose pong doesn't arrive within PING_TIMEOUT, so dead peers are
    # dropped (and their macmap entries released).
    return websockets.serve(handler, host, port,
                            ping_interval=PING_INTERVAL, ping_timeout=PING_TIMEOUT)

async def run():
    tundev.start()
    logger.info('TAP device registered with event loop.')
    try:
        async with serve(HOST, PORT):
            logger.info('WebSocket relay listening on %s:%d', HOST, PORT)
            await tundev.failed  # Runs until the TAP device fails
    finally:
        tundev.stop()

def main():
    global tundev

    logging.basicConfig(format=FORMAT, level=logging.INFO)

    logger.info('Creating TAP device tap0 (10.5.0.1/16, mtu 1500)...')
    tundev = TunDevice()
    logger.info('TAP device tap0 is up.')

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        logger.info('Shutting down (KeyboardInterrupt)...')
    except Exception:
        logger.exception('Relay stopped due to an error.')
        sys.exit(1)

    logger.info('TAP device closed. Goodbye.')

if __name__ == '__main__':
    main()
