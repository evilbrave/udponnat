#! /usr/bin/env python

import socket

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    s.sendto('hello', ('127.0.0.1', 1194))
    (d, f) = s.recvfrom(2048)
    print 'from %s: %s' % (str(f), d)

if __name__ == '__main__':
    main()
