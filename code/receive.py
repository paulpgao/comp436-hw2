#!/usr/bin/env python
import sys
import struct
import os

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR
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
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]

totalCount = 0
port2pktCount = 0
port2Traffic = 0
port3pktCount = 0
port3Traffic = 0

def handle_pkt(pkt):
    global totalCount
    global port2pktCount
    global port2Traffic
    global port3pktCount
    global port3Traffic

    # pkt.show2();
    if Query in pkt:
        totalCount += 1
        if pkt["Query"].egressPort == 2:
            port2pktCount += 1
            port2Traffic += pkt["Query"].packetSize
        elif pkt["Query"].egressPort == 3:
            port3pktCount += 1
            port3Traffic += pkt["Query"].packetSize
        print " totalCount=" + str(totalCount) + " index=" + str(pkt["Query"].index) + " egressPort=" + str(pkt["Query"].egressPort) + " packetSize=" + str(pkt["Query"].packetSize)

        print " Port 2: " + str(port2pktCount) + " packets, " + str(port2Traffic) + " bytes. Port 3: " + str(port3pktCount) + " packets, " + str(port3Traffic) + " bytes. "
#    hexdump(pkt)
    sys.stdout.flush()


def main():
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
