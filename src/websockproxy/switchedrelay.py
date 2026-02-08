import sys
import time
import logging
import traceback
import asyncio
import socket as socket_module

from pytun import TunTapDevice, IFF_TAP, IFF_NO_PI


from .limiter import RateLimitingState

import websockets


FORMAT = '%(asctime)-15s %(message)s'
RATE = 40980.0 #unit: bytes
BROADCAST = b'\xff\xff\xff\xff\xff\xff'
PING_INTERVAL = 30

logger = logging.getLogger('relay')


macmap = {}

def _fire_and_forget(coro):
    """Schedule a coroutine without leaving unhandled task exceptions.

    Used for ws.send() / ws.ping() / ws.close() calls that mirror
    Tornado's synchronous write_message() — we don't await the result,
    so we suppress ConnectionClosed to avoid 'Task exception was never
    retrieved' warnings.
    """
    task = asyncio.ensure_future(coro)
    task.add_done_callback(_silence_connection_closed)

def _silence_connection_closed(task):
    exc = task.exception() if not task.cancelled() else None
    if exc and not isinstance(exc, websockets.exceptions.ConnectionClosed):
        logger.error('Unexpected send error: %s', exc)

def delay_future(t, callback=None):
    future = asyncio.Future()
    timestamp = time.time()
    if timestamp < t:
        return future
    else:
        future.set_result(t)
        if callback:
            callback(t)
        return future

class TunDevice:
    def __init__(self):
        self.tun = TunTapDevice(name="tap0", flags= (IFF_TAP | IFF_NO_PI))
        self.tun.addr = '10.5.0.1'
        self.tun.netmask = '255.255.0.0'
        self.tun.mtu = 1500
        self.tun.up()

    def write(self, message):
        self.tun.write(message)

    def start(self):
        loop.add_reader(self.tun.fileno(), self._on_readable)

    def stop(self):
        try:
            loop.remove_reader(self.tun.fileno())
        except:
            pass
        self.tun.close()

    def _on_readable(self):
        try:
            buf = self.tun.read(self.tun.mtu+18) #MTU doesn't include header or CRC32
            if len(buf):
                mac = buf[0:6]
                if mac == BROADCAST or (mac[0] & 0x1) == 1:
                    logger.debug('tun -> broadcast/multicast (%d bytes, %d clients)', len(buf), len(macmap))
                    for client in macmap.values():
                        try:
                            client.rate_limited_downstream(buf)
                        except:
                            pass

                elif macmap.get(mac, False):
                    logger.debug('tun -> unicast (%d bytes)', len(buf))
                    try:
                        macmap[mac].rate_limited_downstream(buf)
                    except:
                        pass
        except:
            logger.error('closing due to tun error')
            self.stop()


class ClientHandler:
    def __init__(self, websocket):
        self.ws = websocket
        self.remote_ip = websocket.remote_address[0] if websocket.remote_address else 'unknown'
        if hasattr(websocket, 'request') and websocket.request is not None:
            forwarded_for = websocket.request.headers.get('X-Forwarded-For')
            if forwarded_for:
                self.remote_ip = forwarded_for
        logger.info('%s: connected.' % self.remote_ip)
        self.thread = None
        self.mac = b''
        self.allowance = RATE #unit: messages
        self.last_check = time.time() #floating-point, e.g. usec accuracy. Unit: seconds
        self.upstream = RateLimitingState(RATE, name='upstream', clientip=self.remote_ip)
        self.downstream = RateLimitingState(RATE, name='downstream', clientip=self.remote_ip)

        ping_future = delay_future(time.time()+PING_INTERVAL, self.do_ping)
        ping_future.add_done_callback(lambda: None)

    def do_ping(self, timestamp):
        _fire_and_forget(self.ws.ping(str(timestamp).encode()))

        ping_future = delay_future(time.time()+PING_INTERVAL, self.do_ping)
        ping_future.add_done_callback(lambda: None)

    def on_pong(self, data):
        pass

    def rate_limited_downstream(self, message):
        if self.downstream.do_throttle(message):
            _fire_and_forget(self.ws.send(message))

    def on_message(self, message):
        #TODO: log IP headers in the future

        #Logs which user is tied to which MAC so that we detect which user is acting maliciously
        if self.mac != message[6:12]:
            if macmap.get(self.mac, False):
                del macmap[self.mac]

            self.mac = message[6:12]
            formatted_mac = ':'.join('{0:02x}'.format(a) for a in message[6:12]) 
            logger.info('%s: using mac %s' % (self.remote_ip, formatted_mac))

            macmap[self.mac] = self

        dest = message[0:6]
        try:
            if dest == BROADCAST or (dest[0] & 0x1) == 1:
                if self.upstream.do_throttle(message):
                    logger.debug('%s: ws -> broadcast/multicast (%d bytes)', self.remote_ip, len(message))
                    for client in macmap.values():
                        try:
                                _fire_and_forget(client.ws.send(message))
                        except:
                            pass

                    tundev.write(message)
            elif macmap.get(dest, False):
                if self.upstream.do_throttle(message):
                    logger.debug('%s: ws -> unicast client (%d bytes)', self.remote_ip, len(message))
                    try:
                        _fire_and_forget(macmap[dest].ws.send(message))
                    except:
                        pass
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

        try:
            del macmap[self.mac]
        except:
            pass

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

if __name__ == '__main__':

    args = sys.argv
    logging.basicConfig(format=FORMAT, level=logging.INFO)

    logger.info('Creating TAP device tap0 (10.5.0.1/16, mtu 1500)...')
    tundev = TunDevice()
    logger.info('TAP device tap0 is up.')

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    tundev.start()
    logger.info('TAP device registered with event loop.')

    async def main():
        async with websockets.serve(handler, "0.0.0.0", 80, ping_interval=None, ping_timeout=None):
            logger.info('WebSocket relay listening on 0.0.0.0:80')
            await asyncio.Future()  # Run forever

    try:
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        logger.info('Shutting down (KeyboardInterrupt)...')
    except:
        pass

    tundev.stop()
    logger.info('TAP device closed. Goodbye.')
