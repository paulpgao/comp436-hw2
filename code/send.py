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

QUERY_PROTOCOL = 251
TCP_PROTOCOL = 6

class Query(Packet):
    name = "Query"
    fields_desc = [
        BitField("protocol", 0, 8),
        ShortField("index", 0),
        IntField("egressPort", 0),
        IntField("packetSize", 0),
        BitField("isPP", 0, 8)]

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

def send_pkt(idx, flag):
    # if len(sys.argv)<3:
    #     print 'pass 2 arguments: <destination> "<message>"'
    #     exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    print str(idx)
    # print "sending on interface %s to %s" % (iface, str(addr))
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt /IP(dst=addr, proto=QUERY_PROTOCOL) / Query(protocol=TCP_PROTOCOL, index=idx, isPP=flag) / TCP(dport=1234, sport=random.randint(49152,65535)) / "text"
    # pkt.show2()
    sendp(pkt, iface=iface, verbose=False)

def main():
    flag = 0
    if len(sys.argv) > 2 and sys.argv[2] == "-pp":
        flag = 1
    for i in range(200):
        send_pkt(i, flag)
    
if __name__ == '__main__':
    main()
