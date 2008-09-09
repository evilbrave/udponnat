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
import xmpp, random, re, socket, Queue

# global messages list
messages = []

class ServerConf(object):
    '''server configuration'''
    def __init__(self, confFile):
        self.confFile = confFile

    def getNetType(self):
        return NET_TYPE_PORTREST_SYM_NAT_LOCAL
    
    def getLoginInfo(self):
        return ('openvpn.nat.server', '')

    def getAllowedUser(self):
        return ('openvpn.nat.user@gmail.com')

def xmppMessageCB(cnx, msg):
    u = msg.getFrom()
    m = msg.getBody()
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

def randStr(len):
    s = ''
    for i in range(len):
        s += random.choice('abcdefghijklmnopqrstuvwxyz')
    return s

class WorkerThread(Thread):
    '''worker thread'''
    def __init__(self, myNetType, iQueue, oQueue, sessKey, srcNetType, srcIP, srcPort):
        self.myNetType = myNetType 
        self.iQueue = iQueue
        self.oQueue = oQueue
        self.sessKey = sessKey 
        self.srcNetType = srcNetType 
        self.srcIP = srcIP
        self.srcPort = srcPort

    def run(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
        sc = STUNClient()
        (myIP, myPort) = sc.getMappedAddr(s)
        #print 'myAddr(%s:%d)' % (myIP, myPort)

        # have server and client got the same mapped ip?
        if myIP == self.srcIP:
            self.failedToEstablish(0)
        # opened or fullcone nat?
        elif self.myNetType == NET_TYPE_OPENED or self.myNetType == NET_TYPE_FULLCONE_NAT:
            pass
        elif self.srcNetType == NET_TYPE_OPENED or self.srcNetType == NET_TYPE_FULLCONE_NAT:
            pass
        # restrict?
        elif self.myNetType == NET_TYPE_REST_FIREWALL or self.myNetType == NET_TYPE_REST_NAT:
            pass
        elif self.srcNetType == NET_TYPE_REST_FIREWALL or self.srcNetType == NET_TYPE_REST_NAT:
            pass
        # both port restrict?
        elif (self.myNetType == NET_TYPE_PORTREST_FIREWALL or self.myNetType == NET_TYPE_PORTREST_NAT) \
             and (self.srcNetType == NET_TYPE_PORTREST_FIREWALL or self.srcNetType == NET_TYPE_PORTREST_NAT):
            pass
        # one port restrict and one symmetric with localization
        elif (self.myNetType == NET_TYPE_PORTREST_FIREWALL or self.myNetType == NET_TYPE_PORTREST_NAT) \
             and self.srcNetType == NET_TYPE_PORTREST_SYM_NAT_LOCAL:
            pass
        elif (self.srcNetType == NET_TYPE_PORTREST_FIREWALL or self.srcNetType == NET_TYPE_PORTREST_NAT) \
             and self.myNetType == NET_TYPE_PORTREST_SYM_NAT_LOCAL:
            pass
        # one port restrict and one symmetric
        elif (self.myNetType == NET_TYPE_PORTREST_FIREWALL or self.myNetType == NET_TYPE_PORTREST_NAT) \
             and self.srcNetType == NET_TYPE_SYM_NAT:
            pass
        elif (self.srcNetType == NET_TYPE_PORTREST_FIREWALL or self.srcNetType == NET_TYPE_PORTREST_NAT) \
             and self.myNetType == NET_TYPE_SYM_NAT:
            pass
        else:
            self.failedToEstablish(1)

    def failedToEstablish(self, reason):
        print 'failedToEstablish(%d)' % reason
        self.oQueue.put('Cannot;%d' % reason)

    def establishIA(self):
        print 'establishIA()'

def processMessages(sc, ms, ss):
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
            # get a new session key
            while True:
                k = randStr(20)
                if k not in ss:
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
            iq = Queue.Queue()
            oq = Queue.Queue()
            wt = WorkerThread(sc.getNetType(), iq, oq, k, t, ip, p)
            ss[k] = (u, iq, oq)
            wt.run()

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
            ret = cnx.Process(60)
            if not ret:
                print 'Lost connection.'
                break
            # process messages
            processMessages(serverConf, messages, sessions)
            processOutputMessage(cnx, sessions)

if __name__ == '__main__':
    main()
