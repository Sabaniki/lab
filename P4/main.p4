/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4      = 0x800;
const bit<8>  TYPE_HOMA      = 0xfd;
const bit<8>  TYPE_HOMA_DATA = 0x10;
const bit<8>  TYPE_HOMA_ACK  = 0x18;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<8>  homa_packet_t;

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

header homa_common_t {
    bit<16>         sport;
    bit<16>         dport;
    bit<32>         unused1;
    bit<32>         unused2;
    bit<8>          doff;
    homa_packet_t   type;
    bit<16>         unused3;
    bit<16>         checksum;
    bit<16>         unused4;
    bit<64>         sender_id;
}

header homa_data_t {
    // after common header
    bit<32>     message_length;
    bit<32>     incoming;
    bit<16>     cutoff_version;
    bit<8>      retransmit;
    bit<8>      pad;
    bit<32>     offset;
    bit<32>     statement_length;
    bit<64>     client_id;
    bit<16>     client_port;
    bit<16>     server_port;
}

// header homa_data_segment_t {
//     bit<32>     offset;
//     bit<32>     statement_length;
// }

// header homa_ack_t {
//     bit<64>     client_id;
//     bit<16>     client_port;
//     bit<16>     server_port;
// }

struct homa_t {
    homa_common_t       common;
    homa_data_t         data;
    // homa_data_segment_t data_segment;
    // homa_ack_t          ack;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t  ethernet;
    ipv4_t      ipv4;
    homa_t      homa;
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
            TYPE_HOMA: parse_homa;
            default: accept;
        }
    }

    state parse_homa {
        packet.extract(hdr.homa.common);
        transition select(hdr.homa.common.type) {
            TYPE_HOMA_DATA: parse_homa_data;
            // ack やその他については一度忘れる
            default: accept;
        }
    }

    state parse_homa_data {
        packet.extract(hdr.homa.data);
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
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action l2_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    table l2_table {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            l2_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    table dbg_homa {
        key = {
            hdr.homa.common.type: exact;
            hdr.homa.common.sender_id: exact;
            hdr.homa.common.sport: exact;
            hdr.homa.common.dport: exact;
            hdr.homa.data.server_port: exact;
        }
        actions = {
            NoAction;
        }
        default_action = NoAction();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            l2_table.apply();
            if (hdr.ipv4.protocol == 0xfd) {
                dbg_homa.apply();
            }
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
        // update_checksum(
        // hdr.ipv4.isValid(),
        //     { hdr.ipv4.version,
        //       hdr.ipv4.ihl,
        //       hdr.ipv4.diffserv,
        //       hdr.ipv4.totalLen,
        //       hdr.ipv4.identification,
        //       hdr.ipv4.flags,
        //       hdr.ipv4.fragOffset,
        //       hdr.ipv4.ttl,
        //       hdr.ipv4.protocol,
        //       hdr.ipv4.srcAddr,
        //       hdr.ipv4.dstAddr },
        //     hdr.ipv4.hdrChecksum,
        //     HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.homa);
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