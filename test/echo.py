#! /usr/bin/env python

import socket

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    s.bind(('127.0.0.1', 1194))
    while True:
        (d, f) = s.recvfrom(2048)
        s.sendto(d, f)

if __name__ == '__main__':
    main()
