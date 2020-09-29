/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TCP_PROTOCOL = 6;
const bit<8>  QUERY_PROTOCOL = 251;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header query_t {
    bit<8> protocol;     // Protocal field for pointing to the next header.
    bit<32> port2count;  // Number of packets outbouding through port 2 of Switch 1.
    bit<32> port2size;   // Amount of traffic outbouding through port 2 of Switch 1.
    bit<32> port3count;  // Number of packets outbouding through port 3 of Switch 1.
    bit<32> port3size;   // Amount of traffic outbouding through port 3 of Switch 1.
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata {
    bit<16> group_select; // Bucket number for determine a packet's egress port from Switch 1.
    bit<16> flow_number;  // A packet's flow number.
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    query_t      query;
    tcp_t        tcp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            QUERY_PROTOCOL: parse_query;
            TCP_PROTOCOL: parse_tcp;
            default: accept;
        }
    }

    state parse_query {
        packet.extract(hdr.query);
        transition select(hdr.query.protocol) {
            TCP_PROTOCOL: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    // Registers to keep track of the switch statistcs.
    register <bit<32>>(1) port2pktCount_reg;  // Number of packets outbouding through port 2 of Switch 1.
    register <bit<32>>(1) port2Traffic_reg;   // Amount of traffic outbouding through port 2 of Switch 1.
    register <bit<32>>(1) port3pktCount_reg;  // Number of packets outbouding through port 3 of Switch 1.
    register <bit<32>>(1) port3Traffic_reg;   // Amount of traffic outbouding through port 3 of Switch 1.

    // Variables to hold the result from reading the above registers.
    bit<32> port2pktCount;
    bit<32> port2Traffic;
    bit<32> port3pktCount;
    bit<32> port3Traffic;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    // ECMP load balancing
    action set_ecmp_select() {
        hash(meta.group_select,
        HashAlgorithm.crc16,
        (bit<16>)0,
        { hdr.ipv4.srcAddr,
          hdr.ipv4.dstAddr,
          hdr.ipv4.protocol,
          hdr.tcp.srcPort,
          hdr.tcp.dstPort},
        (bit<32>)2);
        meta.flow_number = meta.group_select;
        hdr.tcp.ackNo = (bit<32>)meta.flow_number;
        hdr.tcp.srcPort = meta.group_select + 2;
    }

    // Per-packet load balancing
    action set_pp_select() {
        hash(meta.group_select,
        HashAlgorithm.crc16,
        (bit<16>)0,
        { hdr.ipv4.srcAddr,
          hdr.ipv4.dstAddr,
          hdr.ipv4.protocol,
          hdr.tcp.srcPort,
          hdr.tcp.dstPort},
        (bit<32>)2);
        meta.flow_number = meta.group_select;
        hdr.tcp.ackNo = (bit<32>)meta.flow_number;
        meta.group_select = (bit<16>)(hdr.tcp.seqNo % 2);
        hdr.tcp.srcPort = meta.group_select + 2;
    }

    // Setting the egress port and IP destination.
    action set_nhop(bit<32> nhop_ipv4, bit<9> port) {
        hdr.ipv4.dstAddr = nhop_ipv4;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    // Table matching the destination address. Only used for Switch 1.
    // "0.0.0.0": first hop for ECMP load balancing
    // "1.1.1.1": first hop for per-packet load balancing
    // Others: ignore
    table Group {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            drop;
            set_ecmp_select;
            set_pp_select;
            NoAction;
        }
        default_action = NoAction();
    }

    // Forwarding table matching the bucket number. Only used for Switch 1.
    // "0": port 2
    // "1": port 3
    table Forwarding {
        key = {
            meta.group_select: exact;
        }
        actions = {
            drop;
            set_nhop;
        }
    }

    // Forwarding table matching the IP address. Used for Switch 2, 3, 4.
    // "10.0.2.2": Each switch's correct egress port.
    table DB_forwarding {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            drop;
            set_nhop;
        }
    }

    apply {
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 0) {
            Group.apply(); 
            // Collecting data for the "query" packet.
            if (hdr.ipv4.protocol == QUERY_PROTOCOL) {
                port2pktCount_reg.read(hdr.query.port2count, 0);
                port2Traffic_reg.read(hdr.query.port2size, 0);
                port3pktCount_reg.read(hdr.query.port3count, 0);
                port3Traffic_reg.read(hdr.query.port3size, 0);

                port2pktCount_reg.write(0, 0);
                port2Traffic_reg.write(0, 0);
                port3pktCount_reg.write(0, 0);
                port3Traffic_reg.write(0, 0);
            // Regular packets.
            } else {
                if (hdr.tcp.srcPort == 2) {
                    port2pktCount_reg.read(port2pktCount, 0);
                    port2pktCount = port2pktCount + 1;
                    port2pktCount_reg.write(0, port2pktCount);

                    port2Traffic_reg.read(port2Traffic, 0);
                    port2Traffic = port2Traffic + standard_metadata.packet_length;
                    port2Traffic_reg.write(0, port2Traffic);                   
                } else {
                    port3pktCount_reg.read(port3pktCount, 0);
                    port3pktCount = port3pktCount + 1;
                    port3pktCount_reg.write(0, port3pktCount);

                    port3Traffic_reg.read(port3Traffic, 0);
                    port3Traffic = port3Traffic + standard_metadata.packet_length;
                    port3Traffic_reg.write(0, port3Traffic);
                }
            }
            Forwarding.apply();
            DB_forwarding.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.query);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
