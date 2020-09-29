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

# Custom Query packet to collect statistics.
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

total_count = 0         # Total packet count.
port2_packet_count = 0  # Port 2 packet count.
port3_packet_count = 0  # Port 3 packet count.
port2_traffic_count = 0 # Port 2 traffic count.
port3_traffic_count = 0 # Port 3 traffic count.
flow0_packet_order = [] # Flow 0 packet order.
flow1_packet_order = [] # Flow 1 packet order.
flow0_inv_count = 0     # Flow 0 packet inversion count.
flow1_inv_count = 0     # Flow 1 packet inversion count.
flow0_inv_count_list = [] # List of Flow 0 packet inversion count.
flow1_inv_count_list = [] # List of packet inversion count.

def handle_pkt(pkt):
    global total_count
    global port2_packet_count
    global port3_packet_count
    global port2_traffic_count
    global port3_traffic_count
    global flow0_packet_order
    global flow1_packet_order
    global flow0_inv_count
    global flow1_inv_count
    # pkt.show2();

    # Printing the result from "query" packet.
    if Query in pkt:
        # Counting the packet inversion for each flow.
        for i in range(len(flow0_packet_order)):
            for j in range(i+1, len(flow0_packet_order)):
                if (flow0_packet_order[i] > flow0_packet_order[j]):
                    flow0_inv_count += 1

        for i in range(len(flow1_packet_order)):
            for j in range(i+1, len(flow1_packet_order)):
                if (flow1_packet_order[i] > flow1_packet_order[j]):
                    flow1_inv_count += 1

        flow0_inv_count_list.append(float(flow0_inv_count))
        flow1_inv_count_list.append(float(flow1_inv_count))
        
        port2_packet_count += pkt["Query"].port2count
        port3_packet_count += pkt["Query"].port3count
        port2_traffic_count += pkt["Query"].port2size
        port3_traffic_count += pkt["Query"].port3size

        print " Total: " + str(port2_packet_count + port3_packet_count) + " packets, " +str(port2_traffic_count + port3_traffic_count) + " bytes. " 
        print " Port 2: " + str(port2_packet_count) + " packets, " + str(port2_traffic_count) + " bytes. Port 3: " + str(port3_packet_count) + " packets, " + str(port3_traffic_count) + " bytes. "
        print " Flow 0 packet inversions: " + str(flow0_inv_count) + ", Flow 1 flow packet inversions: " + str(flow1_inv_count)
        print " Average packet inversions across runs: Flow 0: " + str(sum(flow0_inv_count_list) / len(flow0_inv_count_list)) + " Flow 1: " + str(sum(flow1_inv_count_list) / len(flow1_inv_count_list))

        flow0_packet_order = []
        flow1_packet_order = []
        flow0_inv_count = 0
        flow1_inv_count = 0
    # Regular packet.
    elif TCP in pkt:
        total_count += 1
        print " total_count=" + str(total_count) + " port=" + str(pkt["TCP"].sport) + " index=" + str(pkt["TCP"].seq)
        if pkt["TCP"].ack == 0:
            flow0_packet_order.append(pkt["TCP"].seq)
        elif pkt["TCP"].ack == 1:
            flow1_packet_order.append(pkt["TCP"].seq)
#    hexdump(pkt)
    sys.stdout.flush()


def main():
    total_count = 0
    port2_packet_count = 0
    port3_packet_count = 0
    port2_traffic_count = 0
    port3_traffic_count = 0
    flow0_packet_order = []
    flow1_packet_order = []
    flow0_inv_count = 0
    flow1_inv_count = 0
    flow0_inv_count_list = []
    flow1_inv_count_list = []

    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
