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

typedef bit<4> FlowStatus;
const FlowStatus WAIT_REP = 0xa;
const FlowStatus DONE_MES = 0xf;

// struct tuples {
//     ip4Addr_t   srcAddr;
//     homaPort_t   common.sport;
//     ip4Addr_t   dstAddr;
//     homaPort_t   common.dport;
//     FlowStatus  status;
//     bit<48>     timestamp;
// }

//                     1        1           2
//       3  4     8  9 0        4           1
// 0     2  8     0  6 0        8           2
// +--+--+--+--+--+--+-+--+--+--+--+--+--+--+
// |  A  |B |  C  |D |E|   F    |     G     |
// +--+--+--+--+--+--+-+--+--+--+--+--+--+--+
typedef bit<212> Flow;

const int END_srcAddr     = 211;    // A
const int START_srcAddr   = 180;

const int END_sport       = 179;    // B
const int START_sport     = 164;

const int END_dstAddr     = 163;    // C
const int START_dstAddr   = 132;

const int END_dport       = 131;    // D
const int START_dport     = 116;

const int END_status      = 115;    // E
const int START_status    = 112;

const int END_timestamp   = 111;    // F
const int START_timestamp = 64;

const int END_sender_id   = 63;     // G
const int START_sender_id = 0;

register<bit<212>>(0x100000) flow_reg;    // <格納するサイズ>(レジスタのサイズ) flow の状態を管理するためのレジスタ

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
    bit<48>    tmp_rtt;      // デバッグで表示する用
    Flow       current_flow; // register から持ってきた現在の flow
    bit<32>    hash_num;     // ローカルで持っても良いが，デバッグで表示するために大きなスコープに
    ip4Addr_t  dbg_srcAddr;
    bit<16>    dbg_sport;
    ip4Addr_t  dbg_dstAddr;
    bit<16>    dbg_dport;
    FlowStatus dbg_status;
    bit<48>    dbg_timestamp;
    bit<64>    dbg_sender_id;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action l2_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    action create_flow_obj(
        out Flow   flow,
        ip4Addr_t  srcAddr,
        bit<16>    sport,
        ip4Addr_t  dstAddr,
        bit<16>    dport,
        FlowStatus status,
        bit<48>    timestamp,
        bit<64>    sender_id
    ) {
        Flow ret_val = srcAddr ++ sport ++ dstAddr ++ dport ++ status ++ timestamp ++ sender_id;
        flow = ret_val;
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

    table dbg_current_flow {
        key = {
            dbg_srcAddr  : exact;
            dbg_sport    : exact;
            dbg_dstAddr  : exact;
            dbg_dport    : exact;
            dbg_status   : exact;
            dbg_timestamp: exact;
            dbg_sender_id: exact;
        }
        actions = {
            NoAction;
        }
        default_action = NoAction();
    }

    table dbg_current_flow2 {
        key = {
            dbg_srcAddr  : exact;
            dbg_sport    : exact;
            dbg_dstAddr  : exact;
            dbg_dport    : exact;
            dbg_status   : exact;
            dbg_timestamp: exact;
            dbg_sender_id: exact;
        }
        actions = {
            NoAction;
        }
        default_action = NoAction();
    }

    table dbg_rtt {
        key = {
            tmp_rtt: exact;
        }
        actions = {
            NoAction;
        }
        default_action = NoAction();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            l2_table.apply();
            if (hdr.ipv4.protocol == TYPE_HOMA) {
                dbg_homa.apply();
                if (hdr.homa.common.type == TYPE_HOMA_DATA) {
                    // set current flow
                    // これも逆方向で見ないといけない
                    hash(
                        hash_num,
                        HashAlgorithm.crc16,
                        (bit<16>)0,
                        {hdr.ipv4.dstAddr, hdr.homa.common.dport, hdr.ipv4.srcAddr,  hdr.homa.common.sport},
                        (bit<32>)65536
                    );
                    flow_reg.read(current_flow, hash_num);
                    ///
                    dbg_srcAddr   = current_flow[END_srcAddr:START_srcAddr];
                    dbg_sport     = current_flow[END_sport:START_sport];
                    dbg_dstAddr   = current_flow[END_dstAddr:START_dstAddr];
                    dbg_dport     = current_flow[END_dport:START_dport];
                    dbg_status    = current_flow[END_status:START_status];
                    dbg_timestamp = current_flow[END_timestamp:START_timestamp];
                    dbg_sender_id = current_flow[END_sender_id:START_sender_id];
                    dbg_current_flow.apply();
                    if (
                        hdr.ipv4.srcAddr              == current_flow[END_dstAddr:START_dstAddr] && 
                        hdr.homa.common.sport         == current_flow[END_dport:START_dport] && 
                        hdr.ipv4.dstAddr              == current_flow[END_srcAddr:START_srcAddr] && 
                        hdr.homa.common.dport         == current_flow[END_sport:START_sport] &&
                        WAIT_REP                      == current_flow[END_status:START_status] &&
                        hdr.homa.common.sender_id - 1 == current_flow[END_sender_id:START_sender_id]
                        // 対応するリクエストがすでに来ているかを確認する．あれば計算
                    ) {
                        bit<48> req_time;
                        bit<48> rtt;
                        Flow before = current_flow;
                        req_time = before[111:64];
                        rtt = standard_metadata.ingress_global_timestamp - req_time;
                        current_flow[111:64] = rtt;
                        tmp_rtt = rtt;
                        dbg_rtt.apply();
                        current_flow[115:112] = DONE_MES;
                        flow_reg.write(hash_num, current_flow);
                    } else {    // なければ作成
                        hash(
                            hash_num,
                            HashAlgorithm.crc16,
                            (bit<16>)0,
                            {hdr.ipv4.srcAddr, hdr.homa.common.sport, hdr.ipv4.dstAddr,  hdr.homa.common.dport},
                            (bit<32>)65536
                        );
                        // flow_reg.read(current_flow, hash_num);
                        Flow f;
                        create_flow_obj(
                            f,
                            hdr.ipv4.srcAddr,
                            hdr.homa.common.sport,
                            hdr.ipv4.dstAddr,
                            hdr.homa.common.dport,
                            WAIT_REP,
                            standard_metadata.ingress_global_timestamp,
                            hdr.homa.common.sender_id
                        );
                        flow_reg.write(hash_num, f);
                    }
                    /// for debug
                    flow_reg.read(current_flow, hash_num);
                    dbg_srcAddr   = current_flow[END_srcAddr:START_srcAddr];
                    dbg_sport     = current_flow[END_sport:START_sport];
                    dbg_dstAddr   = current_flow[END_dstAddr:START_dstAddr];
                    dbg_dport     = current_flow[END_dport:START_dport];
                    dbg_status    = current_flow[END_status:START_status];
                    dbg_timestamp = current_flow[END_timestamp:START_timestamp];
                    dbg_sender_id = current_flow[END_sender_id:START_sender_id];
                    dbg_current_flow2.apply();
                    ///
                }
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
    apply {  }
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