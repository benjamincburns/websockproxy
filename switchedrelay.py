import sys
import time
import threading
import logging
from select import poll

from pytun import TunTapDevice, IFF_TAP, IFF_NO_PI

from select import POLLIN, POLLOUT, POLLHUP, POLLERR, POLLNVAL

import tornado.ioloop
import tornado.web
import tornado.options

from tornado import websocket


FORMAT = '%(asctime)-15s %(message)s'
RATE = 40980.0 #unit: bytes
PER  = 1.0 #unit: seconds
BROADCAST = '%s%s%s%s%s%s' % (chr(0xff),chr(0xff),chr(0xff),chr(0xff),chr(0xff),chr(0xff))

logger = logging.getLogger('relay')


macmap = {}

class TunThread(threading.Thread):
    def __init__(self, *args, **kwargs):
        super(TunThread, self).__init__(*args, **kwargs)
        self.running = True
        self.tun = TunTapDevice(flags= (IFF_TAP | IFF_NO_PI))
        self.tun.addr = '10.5.0.1'
        self.tun.netmask = '255.255.0.0'
        self.tun.mtu = 1500
        self.tun.up()

    def run(self):
        p = poll()
        p.register(self.tun, POLLIN)
        try:
            while(self.running):
                #TODO: log IP headers in the future
                pollret = p.poll(1000)
                for (f,e) in pollret:
                    if f == self.tun.fileno() and (e & POLLIN):
                        buf = self.tun.read(self.tun.mtu+18) #MTU doesn't include header or CRC32
                        if len(buf):
                            mac = buf[0:6]
                            if mac == BROADCAST or (ord(mac[0]) & 0x1) == 1:
                                #print 'sending broadcast frame:'
                                #print ':'.join('{0:02x}'.format(ord(c)) for c in buf)
                                for socket in macmap.values():
                                    def send_message():
                                        try:
                                            socket.write_message(str(buf),binary=True)
                                        except:
                                            pass

                                    loop.add_callback(send_message)

                            elif macmap.get(mac, False):
                                def send_message():
                                    try:
                                        macmap[mac].write_message(str(buf),binary=True)
                                    except:
                                        pass

                                loop.add_callback(send_message)
                            else:
                                print("couldn't find recipient for mac %s from %s " % (':'.join('{0:02x}'.format(ord(c)) for c in mac), ':'.join('{0:02x}'.format(ord(c)) for c in buf[6:12])))
        except:
            print 'closing due to tun error'
        finally:
            self.tun.close()


class MainHandler(websocket.WebSocketHandler):
    def __init__(self, *args, **kwargs):
        super(MainHandler, self).__init__(*args,**kwargs)
        self.remote_ip = self.request.headers.get('X-Forwarded-For', self.request.remote_ip)
        logger.info('%s: connected.' % self.remote_ip)
        self.thread = None
        self.mac = ''
        self.allowance = RATE #unit: messages
        self.last_check = time.time() #floating-point, e.g. usec accuracy. Unit: seconds


    def open(self):
        self.set_nodelay(True)

    def on_message(self, message):
        #TODO: log IP headers in the future

        #Logs which user is tied to which MAC so that we detect which user is acting maliciously
        if self.mac != message[6:12]:
            if macmap.get(self.mac, False):
                del macmap[self.mac]

            self.mac = message[6:12]
            formatted_mac = ':'.join('{0:02x}'.format(ord(a)) for a in message[6:12]) 
            logger.info('%s: using mac %s' % (self.remote_ip, formatted_mac))

            macmap[self.mac] = self

        dest = message[0:6]
        try:
            #rate limiting algorithm from http://stackoverflow.com/a/668327/203705
            #stolen with love ;-)
            current = time.time()
            time_passed = current - self.last_check
            self.last_check = current
            self.allowance += time_passed * (RATE / PER)
            if self.allowance > RATE:
                self.allowance = RATE #throttle
            if self.allowance < 1.0:
                return
            else:
                if dest == BROADCAST or (ord(dest[0]) & 0x1) == 1:
                    for socket in macmap.values():
                        try:
                            socket.write_message(str(message),binary=True)
                        except:
                            pass

                    tunthread.tun.write(message)
                elif macmap.get(dest, False):
                    try:
                        macmap[dest].write_message(str(message),binary=True)
                    except:
                        print('macmap %s not found' % dest)
                        pass
                else:
                    tunthread.tun.write(message)

                self.allowance -= len(message)
        except:
            try:
                self.close()
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

application = tornado.web.Application([(r'/', MainHandler)])

if __name__ == '__main__':

    tunthread = TunThread()
    tunthread.start()
 
    args = sys.argv
    args.append('--log_file_prefix=/var/log/relay/relay-server2.log')
    tornado.options.parse_command_line(args)
    application.listen(9999)
    loop = tornado.ioloop.IOLoop.instance()
    try:
        loop.start()
    except:
        pass

    tunthread.running = False;

