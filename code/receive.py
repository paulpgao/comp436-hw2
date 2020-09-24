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

total_count = 0
port2_packet_order = []
port3_packet_order = []
port2_inv_count = 0
port3_inv_count = 0

def handle_pkt(pkt):
    global total_count
    global port2_packet_order
    global port3_packet_order
    global port2_inv_count
    global port3_inv_count
    # pkt.show2();

    if Query in pkt:
        for i in range(len(port2_packet_order)):
            for j in range(i+1, len(port2_packet_order)):
                if (port2_packet_order[i] > port2_packet_order[j]):
                    port2_inv_count += 1

        for i in range(len(port3_packet_order)):
            for j in range(i+1, len(port3_packet_order)):
                if (port3_packet_order[i] > port3_packet_order[j]):
                    port3_inv_count += 1

        print " Total: " + str(pkt["Query"].port2count + pkt["Query"].port3count) + " packets, " +str(pkt["Query"].port2size + pkt["Query"].port3size) + " bytes. " 
        print " Port 2: " + str(pkt["Query"].port2count) + " packets, " + str(pkt["Query"].port2size) + " bytes. Port 3: " + str(pkt["Query"].port3count) + " packets, " + str(pkt["Query"].port3size) + " bytes. "
        print " Port 2 flow packet inversions: " + str(port2_inv_count) + ", Port 3 flow packet inversions: " + str(port3_inv_count)
        total_count = 0
        port2_packet_order = []
        port3_packet_order = []
        port2_inv_count = 0
        port3_inv_count = 0

    elif TCP in pkt:
        total_count += 1
        print " total_count=" + str(total_count) + " port=" + str(pkt["TCP"].sport) + " index=" + str(pkt["TCP"].seq)
        if pkt["TCP"].sport == 2:
            port2_packet_order.append(pkt["TCP"].seq)
        elif pkt["TCP"].sport == 3:
            port3_packet_order.append(pkt["TCP"].seq)
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
