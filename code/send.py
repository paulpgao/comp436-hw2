#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
from scapy.all import *

IPV4_PROTOCOL = 0x0800
QUERY_PROTOCOL = 251
TCP_PROTOCOL = 6

class Query(Packet):
    name = "Query"
    fields_desc = [
        BitField("protocol", 0, 8),
        IntField("port2count", 0),
        IntField("port2size", 0),
        IntField("port3count", 0),
        IntField("port3size", 0)]

bind_layers(IP, Query, proto = QUERY_PROTOCOL)
bind_layers(Query, TCP, protocol = TCP_PROTOCOL)

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def send_pkt(idx, flag, type):
    # if len(sys.argv)<3:
    #     print 'pass 2 arguments: <destination> "<message>"'
    #     exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    # print "sending on interface %s to %s" % (iface, str(addr))
    if type == 1:
        print idx
        pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        pkt = pkt / IP(dst=flag, proto=TCP_PROTOCOL) / TCP(dport=1234, sport=random.randint(49152,65535), seq=idx) / ("a"*random.randint(1,1000))
        # pkt.show2()
    elif type == 2:
        pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        pkt = pkt / IP(dst=addr, proto=QUERY_PROTOCOL) / Query(protocol=TCP_PROTOCOL) / TCP(dport=1234, sport=random.randint(49152,65535)) / "query"
    sendp(pkt, iface=iface, verbose=False)

def main():
    flag = '0.0.0.0'
    if len(sys.argv) > 2 and sys.argv[2] == "-pp":
        flag = '1.1.1.1'
    elif len(sys.argv) <= 1:
        print 'pass 1 arguments: <destination> [OPTIONAL]-pp'
        exit(1) 
    for i in range(200):
        send_pkt(i, flag, 1)
    time.sleep(1)
    send_pkt(i, flag, 2)
    
if __name__ == '__main__':
    main()
