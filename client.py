#! /usr/bin/env python

#############################################################################
#                                                                           #
#   File: client.py                                                         #
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
from parseconf import *
from threading import Thread
import xmpp, random, re, socket, Queue, time, select, common, getpass

# global messages list
messages = []

class ClientConf(ParseConf):
    '''client configuration'''
    def getListenAddr(self):
        addr = self.getValue('listen')
        (h, _, p) = addr.partition(':')
        return (h, int(p))

    def getNetType(self):
        t = self.getValue('net_type')
        return int(t)
    
    def getStunServer(self):
        addr = self.getValue('stun_server')
        (h, _, p) = addr.partition(':')
        if p == '':
            return (h, 3478)
        else:
            return (h, int(p))
    
    def getLoginInfo(self):
        u = self.getValue('i')
        p = getpass.getpass('Password for %s: ' % u)
        return (u, p)

    def getServerUser(self):
        return self.getValue('server_user')

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

def gotReply(ms, user):
    while True:
        try:
            (u, c) = ms.pop(0)
        except IndexError:
            break
        # check client user
        if u.rpartition('/')[0] != user:
            continue
        return c
    return None

def main():
    listenAddr = None
    serverAddr = None
    fromAddr = None

    # open client configuration file
    clientConf = ClientConf('./client.conf')

    # get network type
    netType = clientConf.getNetType()
    if netType == NET_TYPE_UDP_BLOCKED:
        # blocked
        print 'UDP is blocked by the firewall, QUIT!'
        return
    if netType == NET_TYPE_REST_SYM_NAT_LOCAL:
        netType = NET_TYPE_PORTREST_SYM_NAT_LOCAL
    
    # create listened socket 
    listenSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    listenAddr = clientConf.getListenAddr()
    listenSock.bind(listenAddr)

    # create socket and get mapped address
    toSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    sc = STUNClient()
    (mappedIP, mappedPort) = sc.getMappedAddr(toSock)

    # get user info of xmpp(gtalk) 
    (user, passwd) = clientConf.getLoginInfo()
    serverUser = clientConf.getServerUser()

    # send client hello
    cnx = xmppListen(user, passwd)
    cnx.send(xmpp.Message(serverUser, 'Hello;%d;%s:%d' \
                                      % (netType, mappedIP, mappedPort)))
    # wait for reply
    ct = time.time()
    while time.time() - ct < common.timeout:
        ret = cnx.Process(1)
        if not ret:
            print 'Lost connection.'
            return
        # process messages
        content = gotReply(messages, serverUser)
        if content:
            break
    else:
        print 'Failed to establish new connection: Timeout.'
        return

    # process reply
    if re.match(r'^Cannot;\d+;[a-z]{%d}$' % common.sessionIDLength, content):
        # Cannot
        print 'Failed to establish new connection: NetType dismatched.'
        return
    elif re.match(r'^Do;IA;\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5};[a-z]{%d}$' \
                  % common.sessionIDLength, content):
        # IA, prepare to connect server
        # parse server reply
        ip = content.split(';')[2].split(':')[0]
        try:
            socket.inet_aton(ip)
        except socket.error:
            # invalid ip
            print 'Failed to establish new connection: Invalid Server Reply.'
            return
        p = int(content.split(';')[2].split(':')[1])
        s = content.split(';')[3]
        # send client hi (udp)
        toSock.sendto('Hi;%s' % s, (ip, p))
        # wait for server's 'Welcome' (udp)
        toSock.settimeout(1)
        ct = time.time()
        while time.time() - ct < common.timeout:
            try:
                (data, fro) = toSock.recvfrom(2048)
            except socket.timeout:
                continue
            # got some data
            if fro == (ip, p) and data == 'Welcome;%s' % s:
                # connection established
                serverAddr = fro
                break
        else:
            print 'Failed to establish new connection: Timout.'
            return
    elif re.match(r'^Do;IB;[a-z]{%d}$' % common.sessionIDLength, content):
        # IB, wait for server's request
        # parse server reply
        s = content.split(';')[2]
        # wait for server's 'Hi' (udp)
        toSock.settimeout(1)
        ct = time.time()
        while time.time() - ct < common.timeout:
            try:
                (data, fro) = toSock.recvfrom(2048)
            except socket.timeout:
                continue
            # got some data
            if data == 'Hi;%s' % s:
                # connection established
                serverAddr = fro
                break
        else:
            print 'Failed to establish new connection: Timout.'
            return
        # send client hi (udp)
        toSock.sendto('Welcome;%s' % s, serverAddr)
    else:
        # wrong reply
        print 'Failed to establish new connection: Invalid Server Reply.'
        return

    print 'Connection established.'
    # non-blocking IO
    listenSock.setblocking(False)
    toSock.setblocking(False)
    lastCheck = time.time()
    # transfer
    while True:
        # check listenSock/toSock
        (rs, _, es) = select.select([listenSock, toSock], [], [], 1)
        if len(es) != 0:
            # error
            print 'Transfer error.'
            break
        if listenSock in rs:
            #print 'listenSock has got some data:', 
            # listenSock is ready for read
            while True:
                try:
                    (d, fromAddr) = listenSock.recvfrom(2048)
                    #print d
                except socket.error:
                    # EAGAIN
                    break
                toSock.sendto(d, serverAddr)
        if toSock in rs:
            #print 'toSock has got some data:', 
            # toSock is ready for read
            while True:
                try:
                    (d, _) = toSock.recvfrom(2048)
                    if d == '':
                        # preserve connection
                        continue
                    #print d
                except socket.error:
                    # EAGAIN
                    break
                if fromAddr:
                    listenSock.sendto(d, fromAddr)
        # preserve connection
        t = time.time()
        if t - lastCheck >= 1:
            lastCheck = t
            toSock.sendto('', serverAddr)

if __name__ == '__main__':
    main()
