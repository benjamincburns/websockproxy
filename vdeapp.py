import time
import threading
from select import poll
from VdePlug import VdePlug, VdeStream

from select import POLLIN, POLLOUT, POLLHUP, POLLERR, POLLNVAL

import tornado.ioloop
import tornado.web

from tornado import websocket

class TunThread(threading.Thread):
    def __init__(self, plug, socket, *args, **kwargs):
        super(TunThread, self).__init__(*args, **kwargs)
        self.plug = plug
        self.socket = socket
        self.running = True

    def run(self):
        p = poll()
        p.register(self.plug.datafd().fileno(), POLLIN)
        while(self.running):
            pollret = p.poll(1000)
            for (f,e) in pollret:
                if f == self.plug.datafd().fileno() and (e & POLLIN):
                    buf = self.plug.recv(2000)
                    if len(buf):
                        print('read %s byte message' % len(buf))
                        print(':'.join('{0:02x}'.format(ord(c)) for c in str(buf)))
                        self.socket.write_message(str(buf), binary=True)

        self.plug.close()

class MainHandler(websocket.WebSocketHandler):
    def __init__(self, *args, **kwargs):
        super(MainHandler, self).__init__(*args,**kwargs)
        self.thread = None

    def open(self):
        self.set_nodelay(True)
        self.plug = VdePlug('/tmp/myvde.ctl')

        self.thread = TunThread(plug=self.plug, socket = self)
        self.thread.start()

    def on_message(self, message):
        print('wrote %s byte message' % len(message))
        print(':'.join('{0:02x}'.format(ord(c)) for c in message))
        self.plug.send(message)

    def on_close(self):
        print('Closing connection')

        if self.thread is not None:
            self.thread.running = False
            self.thread.join()
        else:
            self.plug.close()

application = tornado.web.Application([(r'/', MainHandler)])

if __name__ == '__main__':
    application.listen(9999)
    tornado.ioloop.IOLoop.instance().start()
