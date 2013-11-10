import threading
from select import select

import tornado.ioloop
import tornado.web

from tornado import websocket
from pytun import TunTapDevice, IFF_TAP, IFF_NO_PI

class TunThread(threading.Thread):
    def __init__(self, tun, socket, *args, **kwargs):
        super(TunThread, self).__init__(*args, **kwargs)
        self.tun = tun
        self.socket = socket
        self.running = True;

    def run(self):
        while(self.running):
            readable, writable, excepted = select([self.tun], [], [self.tun], 0.01)
            for tun in readable:
                buf = tun.read(tun.mtu)
                print('read %s byte message from %s' % (len(buf), tun.name))
                print(':'.join('{0:x}'.format(ord(c)) for c in str(buf)))
                self.socket.write_message(str(buf), binary=True)
            for tun in excepted:
                self.running = False

        self.tun.close()

class MainHandler(websocket.WebSocketHandler):
    def __init__(self, *args, **kwargs):
        super(MainHandler, self).__init__(*args,**kwargs)
        self.thread = None

    def open(self):
        self.set_nodelay(True)
        self.tun = TunTapDevice(flags= (IFF_TAP | IFF_NO_PI))
        self.tun.addr = '192.168.1.1'
        self.tun.dstaddr = '192.168.1.2'
        self.tun.netmask = '255.255.255.0'
        self.tun.mtu = 1500
        self.tun.up()
        self.thread = TunThread(tun=self.tun, socket = self)
        self.thread.start()

    def on_message(self, message):
        print('wrote %s byte message to %s' % (len(message), self.tun.name))
        print(':'.join('{0:x}'.format(ord(c)) for c in message))
        self.tun.write(message)

    def on_close(self):
        print('Closing %s' % self.tun.name)
        self.tun.close()
        if self.thread is not None:
            self.thread.running = False

application = tornado.web.Application([(r'/', MainHandler)])

if __name__ == '__main__':
    application.listen(9999)
    tornado.ioloop.IOLoop.instance().start()
