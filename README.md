#WebSockets Proxy

This is two different Python WebSockets servers which handle sending/receivng
ethernet frames. tuntapapp.py works with TAP devices (creates one device per
connection) and vdeapp.py connects to a VDE2 switch. Both are written using
Tornado's awesome websocket server support.

Please note that these aren't super awesome, super configurable productioni
ready services. These are just two quick hacks I put together to set up a demo.

Also, to use vdeapp.py, make sure you've built VDE2 from source and installed
the python bindings in order to enable VdePlug.
