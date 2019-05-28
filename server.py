# Example file for testing rdpy as honeypot

from rdpy.protocol.rdp import rdp
from rdpy.core import log
import sys

log._LOG_LEVEL = log.Level.DEBUG

class MyRDPFactory(rdp.ServerFactory):
    def __init__(self, colorDepth, privateKeyFilePath, certificateFilePath, serverSecurity=None):
        rdp.ServerFactory.__init__(
            self, colorDepth, privateKeyFilePath, certificateFilePath)
        self._serverSecurity = serverSecurity

    def buildObserver(self, controller, addr):

        class MyObserver(rdp.RDPServerObserver):

            def onReady(self):
                """
                @summary: Call when server is ready
                to send and receive messages
                """
                domain, username, password = self._controller.getCredentials()
                log.info("Credentials: "+str(username)+" "+str(password))
                self._controller.close()

            def onKeyEventScancode(self, code, isPressed):
                """
                @summary: Event call when a keyboard event is catch in scan code format
                @param code: scan code of key
                @param isPressed: True if key is down
                @see: rdp.RDPServerObserver.onKeyEventScancode
                """

            def onKeyEventUnicode(self, code, isPressed):
                """
                @summary: Event call when a keyboard event is catch in unicode format
                @param code: unicode of key
                @param isPressed: True if key is down
                @see: rdp.RDPServerObserver.onKeyEventUnicode
                """

            def onPointerEvent(self, x, y, button, isPressed):
                """
                @summary: Event call on mouse event
                @param x: x position
                @param y: y position
                @param button: 1, 2, 3, 4 or 5 button
                @param isPressed: True if mouse button is pressed
                @see: rdp.RDPServerObserver.onPointerEvent
                """

            def onClose(self):
                """
                @summary: Call when human client close connection
                @see: rdp.RDPServerObserver.onClose
                """

        return MyObserver(controller)


def mapSecurityLayer(layer):
    return {
        "rdp": rdp.SecurityLevel.RDP_LEVEL_RDP,
        "tls": rdp.SecurityLevel.RDP_LEVEL_SSL,
        "nla": rdp.SecurityLevel.RDP_LEVEL_NLA
    }[layer]


iface = '0.0.0.0'
key = cert = None
sec = 'rdp'
print sys.argv
if len(sys.argv) == 2:
    iface = sys.argv[1]
elif len(sys.argv) == 4:
    key = sys.argv[2]
    cert = sys.argv[3]
elif len(sys.argv) == 5:
    key = sys.argv[2]
    cert = sys.argv[3]
    sec = sys.argv[4]


from twisted.internet import reactor
reactor.listenTCP(3389, MyRDPFactory(32,key,cert, mapSecurityLayer(sec)),interface=iface)
reactor.run()
