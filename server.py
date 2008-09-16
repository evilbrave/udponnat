#! /usr/bin/env python

#############################################################################
#                                                                           #
#   File: server.py                                                         #
#                                                                           #
#   Copyright (C) 2008 Du XiaoGang <dugang@188.com>                         #
#                                                                           #
#   This file is part of UDPonNAT.                                          #
#                                                                           #
#   UDPonNAT is free software: you can redistribute it and/or modify        #
#   it under the terms of the GNU General Public License as                 #
#   published by the Free Software Foundation, either version 3 of the      #
#   License, or (at your option) any later version.                         #
#                                                                           #
#   UDPonNAT is distributed in the hope that it will be useful,             #
#   but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#   GNU General Public License for more details.                            #
#                                                                           #
#   You should have received a copy of the GNU General Public License       #
#   along with UDPonNAT.  If not, see <http://www.gnu.org/licenses/>.       #
#                                                                           #
#############################################################################

from stunclient import *
from threading import Thread
import xmpp, random, re, socket, Queue, time, select
from common import *

# global messages list
messages = []

class ServerConf(object):
    '''server configuration'''
    def __init__(self, confFile):
        self.confFile = confFile

    def getTo(self):
        return ('127.0.0.1', 1194)

    def getNetType(self):
        return NET_TYPE_OPENED
    
    def getStunServer(self):
        return ('stunserver.org', 3478)
    
    def getLoginInfo(self):
        return ('openvpn.nat.server', '***')

    def getAdminUser(self):
        return ('openvpn.nat@gmail.com')

    def getAllowedUser(self):
        return ('openvpn.nat.user@gmail.com')

def xmppMessageCB(cnx, msg):
    u = msg.getFrom()
    m = msg.getBody()
    #print u, m
    if u and m:
        messages.append((str(u).strip(), str(m).strip()))
        #messages.append((unicode(u), unicode(m)))

def xmppListen(user, passwd):
    cnx = xmpp.Client('gmail.com', debug=[])
    cnx.connect(server=('talk.google.com', 443))
    cnx.auth(user, passwd, 'UDPonNAT')
    cnx.sendInitPresence()
    cnx.RegisterHandler('message', xmppMessageCB)
    return cnx

def randStr():
    s = ''
    for i in range(sessionIDLength):
        s += random.choice('abcdefghijklmnopqrstuvwxyz')
    return s

class WorkerThread(Thread):
    '''worker thread'''
    def __init__(self, to, myNetType, iQueue, oQueue, sessKey, \
                 srcNetType, src):
        Thread.__init__(self)
        self.to = to
        self.myNetType = myNetType 
        self.iQueue = iQueue
        self.oQueue = oQueue
        self.sessKey = sessKey 
        self.srcNetType = srcNetType 
        self.src = src
        # other
        self.timeout = 30
        self.toSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)

    def run(self):
        fromSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
        sc = STUNClient()
        (myIP, myPort) = sc.getMappedAddr(fromSock)
        #print 'myAddr(%s:%d)' % (myIP, myPort)

        # have server and client got the same mapped ip?
        if myIP == self.src[0]:
            self.failedToEstablish(0)
            return
        # opened or fullcone nat?
        elif self.myNetType == NET_TYPE_OPENED \
             or self.myNetType == NET_TYPE_FULLCONE_NAT:
            # tell client to connect
            if not self.establishIA((myIP, myPort), fromSock):
                return
        elif self.srcNetType == NET_TYPE_OPENED \
             or self.srcNetType == NET_TYPE_FULLCONE_NAT:
            if not self.establishIB((myIP, myPort), fromSock):
                return
        # restrict?
        elif self.myNetType == NET_TYPE_REST_FIREWALL \
             or self.myNetType == NET_TYPE_REST_NAT:
            return
        elif self.srcNetType == NET_TYPE_REST_FIREWALL \
             or self.srcNetType == NET_TYPE_REST_NAT:
            return
        # both port restrict?
        elif (self.myNetType == NET_TYPE_PORTREST_FIREWALL \
              or self.myNetType == NET_TYPE_PORTREST_NAT) \
             and (self.srcNetType == NET_TYPE_PORTREST_FIREWALL \
                  or self.srcNetType == NET_TYPE_PORTREST_NAT):
            return
        # one port restrict and one symmetric with localization
        elif (self.myNetType == NET_TYPE_PORTREST_FIREWALL \
              or self.myNetType == NET_TYPE_PORTREST_NAT) \
             and self.srcNetType == NET_TYPE_PORTREST_SYM_NAT_LOCAL:
            return
        elif (self.srcNetType == NET_TYPE_PORTREST_FIREWALL \
              or self.srcNetType == NET_TYPE_PORTREST_NAT) \
             and self.myNetType == NET_TYPE_PORTREST_SYM_NAT_LOCAL:
            return
        # one port restrict and one symmetric
        elif (self.myNetType == NET_TYPE_PORTREST_FIREWALL \
              or self.myNetType == NET_TYPE_PORTREST_NAT) \
             and self.srcNetType == NET_TYPE_SYM_NAT:
            return
        elif (self.srcNetType == NET_TYPE_PORTREST_FIREWALL \
              or self.srcNetType == NET_TYPE_PORTREST_NAT) \
             and self.myNetType == NET_TYPE_SYM_NAT:
            return
        else:
            self.failedToEstablish(1)
            return

        # non-blocking IO
        fromSock.setblocking(False)
        self.toSock.setblocking(False)
        lastCheck = time.time()
        # transfer
        while True:
            # check to/from socket
            (rs, _, es) = select.select([fromSock, self.toSock], [], [], 1)
            if len(es) != 0:
                # error
                print 'Transfer error.'
                break
            if fromSock in rs:
                # fromSock is ready for read
                while True:
                    try:
                        (d, _) = fromSock.recvfrom(2048)
                        if d == '':
                            # preserve connection
                            continue
                    except socket.error:
                        # EAGAIN
                        break
                    self.toSock.sendto(d, self.to)
            if self.toSock in rs:
                # toSock is ready for read
                while True:
                    try:
                        (d, _) = self.toSock.recvfrom(2048)
                    except socket.error:
                        # EAGAIN
                        break
                    fromSock.sendto(d, self.src)
            # check iQueue
            t = time.time()
            if t - lastCheck >= 1:
                lastCheck = t
                # iQueue, mainly for management
                # preserve connection
                fromSock.sendto('', self.src)

    def sendXmppMessage(self, m):
        self.oQueue.put(m)

    def waitXmppMessage(self):
        try:
            return self.iQueue.get(timeout=self.timeout)
        except Queue.Empty:
            return None

    def failedToEstablish(self, reason):
        print 'failedToEstablish(%d)' % reason
        self.sendXmppMessage('Cannot;%d' % reason)

    def establishIA(self, addr, sock):
        print 'establishIA()'
        self.sendXmppMessage('Do;IA;%s:%d' % addr)
        # wait for udp packet
        sock.settimeout(1)
        ct = time.time()
        while time.time() - ct < self.timeout:
            try:
                (data, fro) = sock.recvfrom(2048)
            except socket.timeout:
                continue
            # got some data
            if data == 'Hi;%s' % self.sessKey:
                sock.sendto('Welcome;%s' % self.sessKey, fro)
                self.src = fro
                return True
        # timeout
        print 'Failed to establish connection: Timout.'
        return False

    def establishIB(self, sock):
        print 'establishIB()'
        # tell client to wait for udp request
        self.sendXmppMessage('Do;IB')
        # wait for client's ack
        ct = time.time()
        while time.time() - ct < self.timeout:
            m = self.waitXmppMessage()
            if not m:
                continue
            # got message
            if m == 'Ack;IB;%s' % self.sessKey:
                break
        else:
            # timeout
            return False

        # try to send udp packet
        sock.sendto('Hi;%s' % self.sessKey, self.src)
        sock.settimeout(1)
        ct = time.time()
        while time.time() - ct < self.timeout:
            try:
                (data, fro) = sock.recvfrom(2048)
            except socket.timeout:
                continue
            # got some data
            if fro == self.src and data == 'Welcome;%s' % self.sessKey:
                return True
        # timeout
        return False

def processInputMessages(sc, ms, ss):
    while True:
        try:
            # FIFO
            (u, c) = ms.pop(0)
        except IndexError:
            break
        # check client user
        #print 'user:', u
        if u.rpartition('/')[0] not in sc.getAllowedUser():
            continue
        # process content 
        #print 'content:', c
        if re.match(r'^Hello;\d+;\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}$', c):
            # client hello
            iq = Queue.Queue()
            oq = Queue.Queue()
            # get a new session key
            while True:
                k = randStr()
                if k not in ss.keys():
                    break
            # parse client hello
            t = int(c.split(';')[1])
            ip = c.split(';')[2].split(':')[0]
            try:
                socket.inet_aton(ip)
            except socket.error:
                # invalid ip
                continue
            p = int(c.split(';')[2].split(':')[1])
            wt = WorkerThread(sc.getTo(), sc.getNetType(), iq, oq, k, t, \
                              (ip, p))
            ss[k] = (u, iq, oq)
            wt.start()
        elif re.match(r'^Ack;[A-Z]{2,3};[a-z]{%d}$' % sessionIDLength, c):
            # Ack
            k = c.split(';')[2]
            if k in ss.keys():
                (mu, iq, oq) = ss[k]
                if mu == u:
                    iq.put(c)

def processOutputMessage(cnx, ss):
    # for each session
    for k in ss.keys():
        (u, _, oq) = ss[k]
        # for each message
        while True:
            try:
                m = oq.get_nowait()
            except Queue.Empty:
                break
            # send
            cnx.send(xmpp.Message(u, '%s;%s' % (m, k)))

def main():
    sessions = {}

    # open server configuration file
    serverConf = ServerConf('./server.conf')

    # get network type
    netType = serverConf.getNetType()
    if netType == NET_TYPE_UDP_BLOCKED:
        # blocked
        print 'UDP is blocked by the firewall, QUIT!'
        return
    if netType == NET_TYPE_REST_SYM_NAT_LOCAL:
        netType = NET_TYPE_PORTREST_SYM_NAT_LOCAL
    
    # get user info of xmpp(gtalk) 
    (user, passwd) = serverConf.getLoginInfo()
    # wait for messages from xmpp
    while True:
        # the outer 'while' is for connection lost.
        cnx = xmppListen(user, passwd)
        while True:
            ret = cnx.Process(1)
            if not ret:
                print 'Lost connection.'
                break
            # process messages
            processInputMessages(serverConf, messages, sessions)
            processOutputMessage(cnx, sessions)

if __name__ == '__main__':
    main()
