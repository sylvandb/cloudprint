# Copyright 2014 Jason Michalski <armooo@armooo.net>
# This file is part of cloudprint.
#
# cloudprint is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# cloudprint is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License

import base64
import logging
import ssl
import socket
import select
import time

from collections import deque
from xml.etree.ElementTree import XMLParser, TreeBuilder

LOGGER = logging.getLogger('cloudprint.xmpp')


class XmppXmlHandler(object):
    STREAM_TAG = '{http://etherx.jabber.org/streams}stream'

    def __init__(self):
        self._stack = 0
        self._builder = TreeBuilder()
        self._results = deque()

    def data(self, data):
        self._builder.data(data)

    def start(self, tag, attrib):
        if tag == self.STREAM_TAG:
            return

        self._builder.start(tag, attrib)
        self._stack += 1

    def end(self, tag):
        self._stack -= 1
        elem = self._builder.end(tag)

        if self._stack == 0:
            self._results.append(elem)

    def get_elem(self):
        """If a top-level XML element has been completed since the last call to
        get_elem, return it; else return None."""
        try:
            elem = self._results.popleft()

            if elem.tag.endswith('failure') or elem.tag.endswith('error'):
                raise Exception("XMPP Error received - %s" % elem.tag)

            return elem

        except IndexError:
            return None


class XmppConnection(object):
    def __init__(self, keepalive_period=60.0):
        self._connected = False
        self._wrappedsock = None
        self._keepalive_period = keepalive_period
        self._nextkeepalive = 0

    def _read_socket(self):
        """read pending data from the socket, and send it to the XML parser.
        return False if the socket is closed, True if it is ok"""
        try:
            data = self._wrappedsock.recv(1024)
            if data is None or len(data) == 0:
                # socket closed
                raise Exception("xmpp socket closed")
        except:
            self._connected = False
            raise

        self._nextkeepalive = (time.time() + self._keepalive_period) if self._keepalive_period > 0 else 0
        LOGGER.debug('<<< %s' % data)
        self._xmlparser.feed(data)

    def _write_socket(self, msg):
        """write a message to the XMPP server"""
        LOGGER.debug('>>> %s' % msg)
        try:
            self._wrappedsock.sendall(msg)
        except:
            self._connected = False
            raise

        self._nextkeepalive = (time.time() + self._keepalive_period) if self._keepalive_period > 0 else 0

    def _msg(self, msg=None):
        """send a message to the XMPP server, and wait for a response
        returns the XML element tree of the response"""
        if msg is not None:
            self._write_socket(msg)

        while True:
            elem = self._handler.get_elem()

            if elem is not None:
                return elem

            # need more data; block until it becomes available
            self._read_socket()

    def _check_for_notification(self):
        """Check for any notifications which have already been received"""
        return(self._handler.get_elem() is not None)

    def _send_keepalive(self):
        LOGGER.info("Sending XMPP keepalive")
        self._write_socket(" ")

    def connect(self, host, port, auth):
        """Establish a new connection to the XMPP server"""
        # first close any existing socket
        self.close()

        LOGGER.info("Establishing connection to xmpp server %s:%i" %
                    (host, port))
        self._xmppsock = socket.socket()
        self._wrappedsock = self._xmppsock
        auth_string = base64.b64encode('\0{0}\0{1}'.format(auth.xmpp_jid, auth.access_token))

        try:
            self._wrappedsock = ssl.wrap_socket(self._xmppsock)
            self._wrappedsock.connect((host, port))

            self._handler = XmppXmlHandler()
            self._xmlparser = XMLParser(target=self._handler)

            # https://developers.google.com/cloud-print/docs/rawxmpp
            self._msg('<stream:stream to="gmail.com" xml:lang="en" version="1.0" xmlns:stream="http://etherx.jabber.org/streams" xmlns="jabber:client">')
            self._msg('<auth xmlns="urn:ietf:params:xml:ns:xmpp-sasl" mechanism="X-OAUTH2">%s</auth>' % auth_string)
            self._msg('<stream:stream to="gmail.com" xml:lang="en" version="1.0" xmlns:stream="http://etherx.jabber.org/streams" xmlns="jabber:client">')
            iq = self._msg('<iq type="set" id="0"><bind xmlns="urn:ietf:params:xml:ns:xmpp-bind"><resource>cloud_print</resource></bind></iq>')
            bare_jid = iq[0][0].text.split('/')[0]
            self._msg('<iq type="set" id="2"><session xmlns="urn:ietf:params:xml:ns:xmpp-session"/></iq>')
            self._msg('<iq type="set" id="3" to="%s"><subscribe xmlns="google:push"><item channel="cloudprint.google.com" from="cloudprint.google.com"/></subscribe></iq>' % bare_jid)
        except:
            self.close()
            raise

        LOGGER.info("xmpp connection established")
        self._connected = True

    def close(self):
        """Close the connection to the XMPP server"""
        try:
            self._wrappedsock.shutdown(socket.SHUT_RDWR)
            self._wrappedsock.close()
        except:
            # close() is best effort. Don't respond to failures
            LOGGER.debug("Error encountered closing XMPP socket")
        finally:
            self._connected = False
            self._nextkeepalive = 0
            self._wrappedsock = None

    def is_connected(self):
        """Check if we are connected to the XMPP server
        returns true if the connection is active; false otherwise"""
        return self._connected

    def await_notification(self, timeout):
        """wait for a timeout or event notification"""
        now = time.time()
        timeoutend = now + timeout if timeout is not None else None

        while True:
            try:
                if self._check_for_notification():
                    return True

                if timeoutend is not None and timeoutend - now <= 0:
                    # timeout
                    return False

                waittime = 0

                if self._nextkeepalive:
                    waittime = self._nextkeepalive - now
                    LOGGER.debug("%f seconds until next keepalive" % waittime)

                if timeoutend is not None:
                    remaining = timeoutend - now
                    if remaining > 0 and (remaining < waittime or not waittime):
                        waittime = remaining
                        LOGGER.debug("%f seconds until timeout" % waittime)

                (r, w, e) = select.select([self._xmppsock], [], [self._xmppsock], waittime)
                now = time.time()

                if self._nextkeepalive and self._nextkeepalive - now <= 0:
                    self._send_keepalive()

                if self._xmppsock in r:
                    self._read_socket()

                if self._xmppsock in e:
                    LOGGER.warn("Error in xmpp connection")
                    raise Exception("xmpp connection errror")

            except:
                self.close()
                raise
