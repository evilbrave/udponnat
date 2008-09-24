#! /usr/bin/env python

#############################################################################
#                                                                           #
#   File: cernet.py                                                         #
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

import socket, time
from stunclient import *

def main():
    stunServers = [('stun1.l.google.com', 19302),
                   ('stun2.l.google.com', 19302),
                   ('stun3.l.google.com', 19302),
                   ('stun4.l.google.com', 19302),
                  ]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    #sock.bind(('0.0.0.0', 54321))
    sock.settimeout(3)
    sc = STUNClient()
    addrs = []
    for ss in stunServers:
        try:
            addrs.append(sc.getMappedAddr(sock, ss))
        except:
            pass
    if len(addrs) >= 2:
        for a in addrs:
            if a != addrs[0]:
                print 'NET TYPE:', sc.netType2String(NET_TYPE_SYM_NAT)
                return
        print 'NET TYPE:', sc.netType2String(NET_TYPE_PORTREST_NAT)
    else:
        print 'I can\'t get enough information from different stun server.'

if __name__ == '__main__':
    main()
