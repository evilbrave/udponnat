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

import random, re, socket, Queue, time, select, getpass, sys, errno
from threading import Thread

import xmpp

import common
from stunclient import *
from parseconf import *

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
    
    #def getStunServer(self):
    #    addr = self.getValue('stun_server')
    #    (h, _, p) = addr.partition(':')
    #    if p == '':
    #        return (h, 3478)
    #    else:
    #        return (h, int(p))
    
    def getGTalkServer(self):
        addr = self.getValue('gtalk_server')
        (h, _, p) = addr.partition(':')
        return (h, int(p))

    def getLoginInfo(self):
        u = self.getValue('i')
        p = getpass.getpass('Password for %s: ' % u)
        return (u, p)

    def getServerUser(self):
        return self.getValue('server_user') + '@gmail.com'

def xmppMessageCB(cnx, msg):
    u = msg.getFrom()
    m = msg.getBody()
    #print u, m
    if u and m:
        messages.append((str(u).strip(), str(m).strip()))
        #messages.append((unicode(u), unicode(m)))

def xmppListen(gtalkServerAddr, user, passwd):
    cnx = xmpp.Client('gmail.com', debug=[])
    cnx.connect(server=gtalkServerAddr)
    cnx.auth(user, passwd, 'UDPonNAT_Client')
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
        if u.partition('/')[0] != user:
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
    
    # create listened socket 
    listenSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    listenSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listenAddr = clientConf.getListenAddr()
    listenSock.bind(listenAddr)

    # create socket and get mapped address
    toSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    toSock.settimeout(1)
    sc = STUNClient()
    (mappedIP, mappedPort) = sc.getMappedAddr(toSock)

    # get gtalk server's addr
    gtalkServerAddr = clientConf.getGTalkServer()
    # get user info of xmpp(gtalk) 
    (user, passwd) = clientConf.getLoginInfo()
    serverUser = clientConf.getServerUser()

    # send client hello
    cnx = xmppListen(gtalkServerAddr, user, passwd)
    cnx.send(xmpp.Message(serverUser, 'Hello;%d;%s:%d' % (netType, mappedIP, mappedPort)))
    # wait for reply
    ct = time.time()
    while time.time() - ct < common.TIMEOUT:
        if not cnx.Process(1):
            print 'XMPP lost connection.'
            return
        # process messages
        content = gotReply(messages, serverUser)
        if content:
            break
    else:
        print 'Failed to connect server: Timeout.'
        return

    # process reply
    if re.match(r'^Cannot;[a-zA-Z0-9_\ \t]+;[a-z]{%d}$' % common.SESSION_ID_LENGTH, content):
        # Cannot
        print 'Failed to connect server: %s.' % content.split(';')[1]
        return
    elif re.match(r'^Do;IA;\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5};[a-z]{%d}$' \
                  % common.SESSION_ID_LENGTH, content):
        # IA, prepare to connect server
        # parse server reply
        ip = content.split(';')[2].split(':')[0]
        try:
            socket.inet_aton(ip)
        except socket.error:
            # invalid ip
            print 'Failed to connect server: Invalid Server Reply.'
            return
        p = int(content.split(';')[2].split(':')[1])
        s = content.split(';')[3]
        # send client hi (udp)
        toSock.sendto('Hi;%s' % s, (ip, p))
        # wait for server's 'Welcome' (udp)
        toSock.settimeout(1)
        ct = time.time()
        while time.time() - ct < common.TIMEOUT:
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
            print 'Failed to connect server: Timeout.'
            return
    elif re.match(r'^Do;IB;[a-z]{%d}$' % common.SESSION_ID_LENGTH, content):
        # IB, wait for server's request
        # parse server reply
        s = content.split(';')[2]
        # wait for server's 'Hi' (udp)
        toSock.settimeout(1)
        ct = time.time()
        while time.time() - ct < common.TIMEOUT:
            try:
                (data, fro) = toSock.recvfrom(2048)
            except socket.timeout:
                continue
            # got some data
            if data == 'Hi;%s' % s:
                # connection established
                serverAddr = fro
                # send client Welcome (udp)
                toSock.sendto('Welcome;%s' % s, serverAddr)
                break
        else:
            print 'Failed to connect server: Timeout.'
            return
    elif re.match(r'^Do;IIA;\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5};[a-z]{%d}$' \
                  % common.SESSION_ID_LENGTH, content):
        # IIA, prepare to connect server
        # parse server reply
        ip = content.split(';')[2].split(':')[0]
        try:
            socket.inet_aton(ip)
        except socket.error:
            # invalid ip
            print 'Failed to connect server: Invalid Server Reply.'
            return
        p = int(content.split(';')[2].split(':')[1])
        s = content.split(';')[3]
        # send client hi (udp)
        toSock.sendto('Hi;%s' % s, (ip, p))
        # wait for server's 'Welcome' (udp)
        toSock.settimeout(1)
        ct = time.time()
        while time.time() - ct < common.TIMEOUT:
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
            print 'Failed to connect server: Timeout.'
            return
    elif re.match(r'^Do;IIB;\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5};[a-z]{%d}$' \
                  % common.SESSION_ID_LENGTH, content):
        # IIB, punch and wait for server's request
        # parse server reply
        ip = content.split(';')[2].split(':')[0]
        try:
            socket.inet_aton(ip)
        except socket.error:
            # invalid ip
            print 'Failed to connect server: Invalid Server Reply.'
            return
        p = int(content.split(';')[2].split(':')[1])
        s = content.split(';')[3]
        # punch
        toSock.sendto('Punch', (ip, p))
        # send Ack (xmpp)
        cnx.send(xmpp.Message(serverUser, 'Ack;IIB;%s' % s))
        # wait for server's 'Hi' (udp)
        toSock.settimeout(1)
        ct = time.time()
        while time.time() - ct < common.TIMEOUT:
            try:
                (data, fro) = toSock.recvfrom(2048)
            except socket.timeout:
                continue
            # got some data
            if data == 'Hi;%s' % s:
                # connection established
                serverAddr = fro
                # send client Welcome (udp)
                toSock.sendto('Welcome;%s' % s, serverAddr)
                break
        else:
            print 'Failed to connect server: Timeout.'
            return
    elif re.match(r'^Do;III;\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5};[a-z]{%d}$' \
                  % common.SESSION_ID_LENGTH, content):
        # III, prepare to connect server
        # parse server reply
        ip = content.split(';')[2].split(':')[0]
        try:
            socket.inet_aton(ip)
        except socket.error:
            # invalid ip
            print 'Failed to connect server: Invalid Server Reply.'
            return
        p = int(content.split(';')[2].split(':')[1])
        s = content.split(';')[3]
        # send client hi (udp)
        toSock.sendto('Hi;%s' % s, (ip, p))
        # wait for server's 'Welcome' (udp)
        toSock.settimeout(1)
        ct = time.time()
        while time.time() - ct < common.TIMEOUT:
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
            print 'Failed to connect server: Timeout.'
            return
    elif re.match(r'^Do;IVA;\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5};[a-z]{%d}$' \
                  % common.SESSION_ID_LENGTH, content):
        # IVA
        # parse server reply
        ip = content.split(';')[2].split(':')[0]
        try:
            socket.inet_aton(ip)
        except socket.error:
            # invalid ip
            print 'Failed to connect server: Invalid Server Reply.'
            return
        p = int(content.split(';')[2].split(':')[1])
        s = content.split(';')[3]
        # new socket
        toSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
        # punch
        toSock.sendto('Punch', (ip, p))
        # get new socket's mapped addr
        toSock.settimeout(1)
        sc = STUNClient()
        (mappedIP, mappedPort) = sc.getMappedAddr(toSock)
        # tell server the new addr (xmpp)
        cnx.send(xmpp.Message(serverUser, 'Ack;IVA;%s:%d;%s' % (mappedIP, mappedPort, s)))
        # wait for server's 'Hi' (udp)
        toSock.settimeout(1)
        ct = time.time()
        while time.time() - ct < common.TIMEOUT:
            try:
                (data, fro) = toSock.recvfrom(2048)
            except socket.timeout:
                continue
            # got some data
            if fro == (ip, p) and data == 'Hi;%s' % s:
                # connection established
                serverAddr = fro
                # send client Welcome (udp)
                toSock.sendto('Welcome;%s' % s, serverAddr)
                break
        else:
            print 'Failed to connect server: Timeout.'
            return
    elif re.match(r'^Do;IVB;\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5};[a-z]{%d}$' \
                  % common.SESSION_ID_LENGTH, content):
        # IVB
        # parse server reply
        ip = content.split(';')[2].split(':')[0]
        try:
            socket.inet_aton(ip)
        except socket.error:
            # invalid ip
            print 'Failed to connect server: Invalid Server Reply.'
            return
        port = int(content.split(';')[2].split(':')[1])
        s = content.split(';')[3]
        # send client hi (udp) to a port range
        bp = port - common.LOCAL_RANGE
        if bp < 1:
            bp = 1
        ep = port + common.LOCAL_RANGE
        if ep > 65536:
            ep = 65536
        for p in range(bp, ep):
            toSock.sendto('Hi;%s' % s, (ip, p))
        # wait for server's 'Welcome' (udp)
        toSock.settimeout(1)
        ct = time.time()
        while time.time() - ct < common.TIMEOUT:
            try:
                (data, fro) = toSock.recvfrom(2048)
            except socket.timeout:
                continue
            # got some data
            if data == 'Welcome;%s' % s:
                # connection established
                serverAddr = fro
                break
        else:
            print 'Failed to connect server: Timeout.'
            return
    elif re.match(r'^Do;VA;\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5};[a-z]{%d}$' \
                  % common.SESSION_ID_LENGTH, content):
        # VA
        # parse server reply
        ip = content.split(';')[2].split(':')[0]
        try:
            socket.inet_aton(ip)
        except socket.error:
            # invalid ip
            print 'Failed to connect server: Invalid Server Reply.'
            return
        p = int(content.split(';')[2].split(':')[1])
        s = content.split(';')[3]

        while True:
            # punch
            toSock.sendto('Punch', (ip, p))
            # tell server we've punched
            cnx.send(xmpp.Message(serverUser, 'Ack;VA;%s' % s))
            # wait for DONE
            ct = time.time()
            while time.time() - ct < common.TIMEOUT:
                if not cnx.Process(1):
                    print 'XMPP lost connection.'
                    return
                # process messages
                content = gotReply(messages, serverUser)
                if content == 'Done;VASent;%s' % s:
                    break
            else:
                print 'Failed to connect server: Timeout.'
                return
            # have we received server's hello?
            toSock.setblocking(False)
            established = False
            while True:
                try:
                    (data, fro) = toSock.recvfrom(2048)
                except socket.error, e:
                    if e[0] != errno.EAGAIN and e[0] != 10035:
                        raise e
                    # EAGAIN
                    break
                # got some data
                if data == 'Hi;%s' % s:
                    toSock.sendto('Welcome;%s' % s, fro)
                    serverAddr = fro
                    established = True
                    break
            # is it ok?
            if established:
                break
    elif re.match(r'^Do;VB;\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5};[a-z]{%d}$' \
                  % common.SESSION_ID_LENGTH, content):
        # VB
        # parse server reply
        ip = content.split(';')[2].split(':')[0]
        try:
            socket.inet_aton(ip)
        except socket.error:
            # invalid ip
            print 'Failed to connect server: Invalid Server Reply.'
            return
        p = int(content.split(';')[2].split(':')[1])
        s = content.split(';')[3]

        # scan all ports of the server
        portBegin = 1
        while portBegin < 65536:
            # try to connect server's port range
            for p in range(portBegin, portBegin + common.SYM_SCAN_RANGE):
                if p < 65536:
                    # send client hi (udp)
                    toSock.sendto('Hi;%s' % s, (ip, p))
            portBegin = p + 1
            # tell server we've sent Hi
            cnx.send(xmpp.Message(serverUser, 'Ack;VB;%s' % s))
            # wait for any message, both udp and xmpp.
            toSock.setblocking(False)
            established = False
            ct = time.time()
            while time.time() - ct < common.TIMEOUT:
                if not cnx.Process(1):
                    print 'XMPP lost connection.'
                    return
                # did we receive server's 'Welcome'(udp)?
                try:
                    (data, fro) = toSock.recvfrom(2048)
                    # got some data
                    if data == 'Welcome;%s' % s:
                        # connection established
                        serverAddr = fro 
                        established = True
                        break
                except socket.error, e:
                    if e[0] != errno.EAGAIN and e[0] != 10035:
                        raise e
                    # EAGAIN, ignore
                # process messages
                content = gotReply(messages, serverUser)
                if content:
                    break
            else:
                print 'Failed to connect server: Timeout.'
                return
            # is it ok?
            if established:
                break
        else:
            print 'Failed to try.'
            return
    else:
        # wrong reply
        print 'Failed to connect server: Invalid Server Reply.'
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
            return
        if listenSock in rs:
            #print 'listenSock has got some data:', 
            # listenSock is ready for read
            while True:
                try:
                    (d, fromAddr) = listenSock.recvfrom(2048)
                    #print d
                except socket.error, e:
                    if e[0] != errno.EAGAIN and e[0] != 10035:
                        raise e
                    # EAGAIN
                    break
                toSock.sendto(d, serverAddr)
        if toSock in rs:
            #print 'toSock has got some data:', 
            # toSock is ready for read
            while True:
                try:
                    (d, a) = toSock.recvfrom(2048)
                    if d == '':
                        # preserve connection
                        continue
                    #print d
                except socket.error, e:
                    if e[0] != errno.EAGAIN and e[0] != 10035:
                        raise e
                    # EAGAIN
                    break
                if fromAddr and a == serverAddr:
                    listenSock.sendto(d, fromAddr)
        # preserve connection
        t = time.time()
        if t - lastCheck >= 1:
            lastCheck = t
            toSock.sendto('', serverAddr)

if __name__ == '__main__':
    main()
