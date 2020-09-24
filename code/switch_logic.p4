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
    bit<8> protocol;
    bit<32> port2count;
    bit<32> port2size;
    bit<32> port3count;
    bit<32> port3size;
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
    bit<16> group_select;
    bit<16> flow_number;
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

    register <bit<32>>(1) port2pktCount_reg;
    register <bit<32>>(1) port2Traffic_reg;
    register <bit<32>>(1) port3pktCount_reg;
    register <bit<32>>(1) port3Traffic_reg;

    bit<32> port2pktCount;
    bit<32> port2Traffic;
    bit<32> port3pktCount;
    bit<32> port3Traffic;

    register <bit<32>>(1) flow0Index_reg;
    register <bit<32>>(1) flow1Index_reg;

    bit<32> flow0Index;
    bit<32> flow1Index;


    action drop() {
        mark_to_drop(standard_metadata);
    }
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
        hdr.tcp.srcPort = meta.group_select + 2;
    }
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
        meta.group_select = (bit<16>)(hdr.tcp.seqNo % 2);
        hdr.tcp.srcPort = meta.group_select + 2;
    }
    action set_nhop(bit<32> nhop_ipv4, bit<9> port) {
        hdr.ipv4.dstAddr = nhop_ipv4;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    action record_flow0_data() {
        flow0Index_reg.read(flow0Index, 0);
        flow0Index = flow0Index + 1;
        flow0Index_reg.write(0, flow0Index);
        hdr.tcp.seqNo = flow0Index;
    }
    action record_flow1_data() {
        flow1Index_reg.read(flow1Index, 0);
        flow1Index = flow1Index + 1;
        flow1Index_reg.write(0, flow1Index);
        hdr.tcp.seqNo = flow1Index;
    }
    
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
    table Index {
        key = {
            meta.flow_number: exact;
        }
        actions = {
            drop;
            record_flow0_data;
            record_flow1_data;
        }
    }
    table Forwarding {
        key = {
            meta.group_select: exact;
        }
        actions = {
            drop;
            set_nhop;
        }
    }
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
            Index.apply(); 
            if (hdr.ipv4.protocol == QUERY_PROTOCOL) {
                port2pktCount_reg.read(hdr.query.port2count, 0);
                port2Traffic_reg.read(hdr.query.port2size, 0);
                port3pktCount_reg.read(hdr.query.port3count, 0);
                port3Traffic_reg.read(hdr.query.port3size, 0);

                port2pktCount_reg.write(0, 0);
                port2Traffic_reg.write(0, 0);
                port3pktCount_reg.write(0, 0);
                port3Traffic_reg.write(0, 0);

                flow0Index_reg.write(0, 0);
                flow1Index_reg.write(0, 0);
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
