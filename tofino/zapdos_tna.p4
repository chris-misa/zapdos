/*
 * ZAPDOS data plane for tofino
 *
 * Author: Chris Misa
 * Date: 2024-05-21
 *
 * See ../LICENSE for conditions.
 */


// Don't change these definitions...the code structure depends on their values.
// Would need more complex pre-processing to make these actually automatically parametric.

#define MAX_REPORT_PREFIXES 10000 // should be something like 10 or 20 k

#define CPU_PORT 64
#define RESULT_REQ_UDP_PORT 5555

#define PREFIXES_PER_EPOCH 1500
// #define PREFIXES_PER_EPOCH 4 // for testing purposes...
#define BITS_PER_EPOCH 4

#define CHILD_BITMAP_WIDTH (1 << BITS_PER_EPOCH)

// Benign MAWILab traces have O(1M) sources so use 2^20 = 1048576 bits 
#define LOOKBACK_BLOOMFILTER_IDX_BITS 20
// #define LOOKBACK_BLOOMFILTER_IDX_BITS 4 // for testing purposes...
#define LOOKBACK_BLOOMFILTER_BITS (1 << LOOKBACK_BLOOMFILTER_IDX_BITS)



#define TIMESTAMP_FIELD (ig_intr_md.ingress_mac_tstamp)

#define RRDIFF_NONE     32w0
#define RRDIFF_DNS_REQ  32w1
#define RRDIFF_DNS_RES  32w2
#define RRDIFF_NTP_REQ  32w3
#define RRDIFF_NTP_RES  32w4
#define RRDIFF_SSDP_REQ 32w5
#define RRDIFF_SSDP_RES 32w6
#define RRDIFF_TCP_REQ  32w7
#define RRDIFF_TCP_RES  32w8

#define INACTIVE_MODE 0
#define PRE_ATTACK_MODE 1
#define ACTIVE_ATTACK_MODE 2

#include <core.p4>
#if __TARGET_TOFINO__ == 3
#include <t3na.p4>
#elif __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "common/headers.p4"
#include "common/util.p4"

typedef bit<32> table_idx_t;
typedef bit<32> counter_t;
// typedef bit<48> timestamp_t;
typedef bit<32> timestamp_t;
typedef bit<BITS_PER_EPOCH> child_idx_t;
typedef bit<CHILD_BITMAP_WIDTH> child_bitmap_t;
typedef bit<8> prefix_len_t;

typedef bit<8> mode_t;

typedef bit<LOOKBACK_BLOOMFILTER_IDX_BITS> bloomfilter_idx_t;

struct metadata_t {
    counter_t fromCount;
    counter_t len;
    child_idx_t childIdx;
    child_bitmap_t childBits;
    table_idx_t idx;
    prefix_len_t prefixLen;
    timestamp_t prevTime;
    timestamp_t ipg;
    counter_t lenLpf1Out;
    counter_t lenLpf2Out;
    counter_t aveLen;
    counter_t ipgLpf1Out;
    counter_t ipgLpf2Out;
    counter_t aveIPG;
    table_idx_t rrDiffType;
    bit<1> src_matched;
    bit<1> dst_matched;
    bit<1> src_prev_seen;
    bit<1> is_result_req;
    bit<1> is_attack;

    // Nasity hack to reduce stages used for swapping src, dst on result_req packets...
    ipv4_addr_t tmp_ip;
    mac_addr_t tmp_mac;
    bit<16> tmp_port;

    // Hack to automatically clear feature registers after updating the selection tables
    bit<1> clear_src;
    bit<1> clear_dst;
}

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
packet_in pkt,
out header_t hdr,
out metadata_t ig_md,
out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;

    state start {
        ig_md = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : reject;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select (hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
            default : accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition select (ig_intr_md.ingress_port) {
            CPU_PORT : parse_result_req1;
            default : accept;
        }
    }

    state parse_result_req1 {
        transition select (hdr.udp.dst_port) {
            RESULT_REQ_UDP_PORT : parse_result_req2;
            default : accept;
        }
    }
    
    state parse_result_req2 {
        pkt.extract(hdr.result_req);
        ig_md.is_result_req = 1;
        transition accept;
    }
}


// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
packet_out pkt,
inout header_t hdr,
in metadata_t ig_md,
in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {

    Digest<bit<32>>(1) address_digest; // number given to Digest constructor must match number assigned to ig_int_dprsr_md.digest_type...
    
    apply {

        if (ig_intr_dprsr_md.digest_type == 1) {
            address_digest.pack(hdr.ipv4.src_addr);
        }
        pkt.emit(hdr); // only emits valid header fields (so we don't worry about switching for result request packets here)
    }
}

control SwitchIngress(
inout header_t hdr,
inout metadata_t ig_md,
in ingress_intrinsic_metadata_t ig_intr_md,
in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

    bit<10> vrf;

    action no_op() {
    }

    action flag_as_attack() {
        ig_md.is_attack = 1;
        ig_intr_dprsr_md.drop_ctl = 0x1; // Drop packet.
    }
    // table reported_prefixes_tbl {
    //     key = {
    //         hdr.ipv4.src_addr: ternary;
    //     }
    //     actions = {
    //         no_op();
    //         flag_as_attack();
    //     }
    //     size = MAX_REPORT_PREFIXES;
    //     default_action = no_op();
    // }

    // TODO: probably we can get rid of the mode knob:
    // we now send digests for distinct sources detected by lookback bloom filter in all modes!

    // TODO: also, it looks like we might only be sending digests in pre-attack mode which means the lookback in active-attack mode is basically non-existent (hence not pulling from active hold outs because no holdouts get marked as active in the lookback loop!)

    // ---> should send digest (in either mode) when (i) src_matched == 0 and (ii) src_prev_seen == 0 (?)
    
    //
    // Control plane sets mode to determine pre-attack or active-attack processing
    //
    // Register<mode_t, table_idx_t>(1, INACTIVE_MODE) mode;
    // mode_t cur_mode;
    
    //
    // Select packet if its source falls into a monitored prefix for per-source features
    //
    // When writting new prefix, set clearSrc to 1
    // so that the first packet matching the new prefix will trigger reset of feature registers
    //
    Register<bit<1>, table_idx_t>(PREFIXES_PER_EPOCH, 1) clearSrc;
    RegisterAction<bit<1>, table_idx_t, bit<1>>(clearSrc) getClearSrc = {
        void apply(inout bit<1> value, out bit<1> rv) {
            rv = value;
            value = 0;
        }
    };
    
    action select_by_src(table_idx_t idx, bit<8>prefixLength) {
        ig_md.idx = idx; 
        ig_md.prefixLen = prefixLength;
        ig_md.len = (counter_t)hdr.ipv4.total_len;
        ig_md.src_matched = 1;
    }
    action no_src_match() {
        ig_md.src_matched = 0;
    }
    table select_by_src_tbl {
        key = {
            hdr.ipv4.src_addr: ternary;
        }
        actions = {
            select_by_src();
            no_src_match();
            flag_as_attack();
        }
        size = PREFIXES_PER_EPOCH + MAX_REPORT_PREFIXES;
        default_action = no_src_match();
    }

    //
    // packetsFrom and bytesFrom
    //
    Register<counter_t, table_idx_t>(PREFIXES_PER_EPOCH, 0) pktsFrom;
    RegisterAction<counter_t, table_idx_t, counter_t>(pktsFrom) incrPktsFrom = {
        void apply(inout counter_t value, out counter_t rv) {
            rv = value;
            if (ig_md.clear_src == 1) {
                value = 1;
             } else {
                value = value + 1;
            }
        }
    };

    Register<counter_t, table_idx_t>(PREFIXES_PER_EPOCH, 0) bytesFrom;
    RegisterAction<counter_t, table_idx_t, counter_t>(bytesFrom) incrBytesFrom = {
        void apply(inout counter_t value, out counter_t rv) {
            rv = value;
            if (ig_md.clear_src == 1) {
                value = (counter_t)hdr.ipv4.total_len;
            } else {
                value = value + (counter_t)hdr.ipv4.total_len;
            }
        }
    };


    
    //
    // packetsTo and bytesTo
    //
    Register<counter_t, table_idx_t>(PREFIXES_PER_EPOCH, 0) pktsTo;
    RegisterAction<counter_t, table_idx_t, counter_t>(pktsTo) incrPktsTo = {
        void apply(inout counter_t value, out counter_t rv) {
            rv = value;
            if (ig_md.clear_dst == 1) {
                value = 1;
            } else {
                value = value + 1;
            }
        }
    };

    Register<counter_t, table_idx_t>(PREFIXES_PER_EPOCH, 0) bytesTo;
    RegisterAction<counter_t, table_idx_t, counter_t>(bytesTo) incrBytesTo = {
        void apply(inout counter_t value, out counter_t rv) {
            rv = value;
            if (ig_md.clear_dst == 1) {
                value = (counter_t)hdr.ipv4.total_len;
            } else {
                value = value + (counter_t)hdr.ipv4.total_len;
            }
        }
    };


    
    //
    // minLength
    //
    Register<counter_t, table_idx_t>(PREFIXES_PER_EPOCH, 0xFFFFFFFF) minLength;
    RegisterAction<counter_t, table_idx_t, counter_t>(minLength) updateMinLength = {
        void apply(inout counter_t value, out counter_t rv) {
            rv = value;
            if (ig_md.len < value || ig_md.clear_src == 1) {
                value = ig_md.len;
            }
        }
    };

    //
    // maxLength
    //
    Register<counter_t, table_idx_t>(PREFIXES_PER_EPOCH, 0) maxLength;
    RegisterAction<counter_t, table_idx_t, counter_t>(maxLength) updateMaxLength = {
        void apply(inout counter_t value, out counter_t rv) {
            rv = value;
            if (ig_md.len > value || ig_md.clear_src == 1) {
                value = ig_md.len;
            }
        }
    };

    //
    // aveLength (moving-average packet length)
    // Note this seems to implement a very-fast Lpf (around 160 ns) so it's not clear if we'll see any useful smoothing effect here...
    //
    Lpf<counter_t, table_idx_t>(PREFIXES_PER_EPOCH) lengthLpf1;
    // Lpf<counter_t, table_idx_t>(PREFIXES_PER_EPOCH) lengthLpf2;
    // Lpf<counter_t, table_idx_t>(PREFIXES_PER_EPOCH) lengthLpf3;
    Register<counter_t, table_idx_t>(PREFIXES_PER_EPOCH, 0) aveLength;
    RegisterAction<counter_t, table_idx_t, counter_t>(aveLength) updateAveLength = {
        void apply(inout counter_t value, out counter_t rv) {
            rv = value;
            if (ig_md.is_result_req == 0) {
                value = ig_md.aveLen;
            }
        }
    };

    
    
    //
    // previous time for IPG-based features
    //
    Register<timestamp_t, table_idx_t>(PREFIXES_PER_EPOCH, 0) prevTime;
    RegisterAction<timestamp_t, table_idx_t, timestamp_t>(prevTime) updatePrevTime = {
        void apply(inout timestamp_t value, out timestamp_t prevValue) {
            prevValue = value;
            value = (bit<32>)TIMESTAMP_FIELD;
        }
    };
    action computeIPG() {
        ig_md.ipg = (bit<32>)TIMESTAMP_FIELD - ig_md.prevTime;
    }
    table ipgTbl {
        key = {
            ig_md.src_matched: exact;
        }
        actions = {
            computeIPG();
        }
        size = 1;
        default_action = computeIPG();
    }
    


    //
    // minIPG
    //
    Register<counter_t, table_idx_t>(PREFIXES_PER_EPOCH, 0xFFFFFFFF) minIPG;
    RegisterAction<counter_t, table_idx_t, counter_t>(minIPG) updateMinIPG = {
        void apply(inout counter_t value, out counter_t rv) {
            rv = value;
            if (ig_md.ipg < value || ig_md.clear_src == 1) {
                value = ig_md.ipg;
            }
        }
    };

    //
    // maxIPG
    //
    Register<counter_t, table_idx_t>(PREFIXES_PER_EPOCH, 0) maxIPG;
    RegisterAction<counter_t, table_idx_t, counter_t>(maxIPG) updateMaxIPG = {
        void apply(inout counter_t value, out counter_t rv) {
            rv = value;
            if (ig_md.ipg > value || ig_md.clear_src == 1) {
                value = ig_md.ipg;
            }
        }
    };

    //
    // aveIPG (moving-average of IPG)
    // Note this seems to implement a very-fast Lpf (around 160 ns) so it's not clear if we'll see any useful smoothing effect here...
    //
    Lpf<counter_t, table_idx_t>(PREFIXES_PER_EPOCH) ipgLpf1;
    // Lpf<counter_t, table_idx_t>(PREFIXES_PER_EPOCH) ipgLpf2;
    // Lpf<counter_t, table_idx_t>(PREFIXES_PER_EPOCH) ipgLpf3;
    Register<counter_t, table_idx_t>(PREFIXES_PER_EPOCH, 0) aveIPG;
    RegisterAction<counter_t, table_idx_t, counter_t>(aveIPG) updateAveIPG = {
        void apply(inout counter_t value, out counter_t rv) {
            rv = value;
            value = ig_md.aveIPG;
        }
    };

    action set_rrDiffType(table_idx_t rrDiffType) {
        ig_md.rrDiffType = rrDiffType;
    }
    table rrDiff_classify_tbl {
        key = {
            hdr.ipv4.protocol: exact;
            hdr.udp.src_port: ternary;
            hdr.udp.dst_port: ternary;
            hdr.tcp.flags: ternary;
        }
        actions = {
            set_rrDiffType();
            no_op();
        }
        size = 8;
        default_action = no_op();
    }
    
    Register<counter_t, table_idx_t>(PREFIXES_PER_EPOCH, 0) dnsResp;
    RegisterAction<counter_t, table_idx_t, counter_t>(dnsResp) updateDnsResp = {
        void apply(inout counter_t value, out counter_t rv) {
            rv = value;
            if (ig_md.clear_src == 1) {
                value = 1;
            } else if (ig_md.rrDiffType == RRDIFF_DNS_RES) {
                value = value + 1;
            }
        }
    };
    Register<counter_t, table_idx_t>(PREFIXES_PER_EPOCH, 0) dnsReq;
    RegisterAction<counter_t, table_idx_t, counter_t>(dnsReq) updateDnsReq = {
        void apply(inout counter_t value, out counter_t rv) {
            rv = value;
            if (ig_md.clear_dst == 1) {
                value = 1;
            } else if (ig_md.rrDiffType == RRDIFF_DNS_REQ) {
                value = value + 1;
            }
        }
    };

    Register<counter_t, table_idx_t>(PREFIXES_PER_EPOCH, 0) ntpResp;
    RegisterAction<counter_t, table_idx_t, counter_t>(ntpResp) updateNtpResp = {
        void apply(inout counter_t value, out counter_t rv) {
            rv = value;
            if (ig_md.clear_src == 1) {
                value = 1;
            } else if (ig_md.rrDiffType == RRDIFF_NTP_RES) {
                value = value + 1;
            }
        }
    };
    Register<counter_t, table_idx_t>(PREFIXES_PER_EPOCH, 0) ntpReq;
    RegisterAction<counter_t, table_idx_t, counter_t>(ntpReq) updateNtpReq = {
        void apply(inout counter_t value, out counter_t rv) {
            rv = value;
            if (ig_md.clear_dst == 1) {
                value = 1;
            } else if (ig_md.rrDiffType == RRDIFF_NTP_REQ) {
                value = value + 1;
            }
        }
    };
    
    Register<counter_t, table_idx_t>(PREFIXES_PER_EPOCH, 0) ssdpResp;
    RegisterAction<counter_t, table_idx_t, counter_t>(ssdpResp) updateSsdpResp = {
        void apply(inout counter_t value, out counter_t rv) {
            rv = value;
            if (ig_md.clear_src == 1) {
                value = 1;
            } else if (ig_md.rrDiffType == RRDIFF_SSDP_RES) {
                value = value + 1;
            }
        }
    };
    Register<counter_t, table_idx_t>(PREFIXES_PER_EPOCH, 0) ssdpReq;
    RegisterAction<counter_t, table_idx_t, counter_t>(ssdpReq) updateSsdpReq = {
        void apply(inout counter_t value, out counter_t rv) {
            rv = value;
            if (ig_md.clear_dst == 1) {
                value = 1;
            } else if (ig_md.rrDiffType == RRDIFF_SSDP_REQ) {
                value = value + 1;
            }
        }
    };

    Register<counter_t, table_idx_t>(PREFIXES_PER_EPOCH, 0) tcpResp;
    RegisterAction<counter_t, table_idx_t, counter_t>(tcpResp) updateTcpResp = {
        void apply(inout counter_t value, out counter_t rv) {
            rv = value;
            if (ig_md.clear_src == 1) {
                value = 1;
            } else if (ig_md.rrDiffType == RRDIFF_TCP_RES) {
                value = value + 1;
            }
        }
    };
    Register<counter_t, table_idx_t>(PREFIXES_PER_EPOCH, 0) tcpReq;
    RegisterAction<counter_t, table_idx_t, counter_t>(tcpReq) updateTcpReq = {
        void apply(inout counter_t value, out counter_t rv) {
            rv = value;
            if (ig_md.clear_dst == 1) {
                value = 1;
            } else if (ig_md.rrDiffType == RRDIFF_TCP_REQ) {
                value = value + 1;
            }
        }
    };
    
    //
    // Select packet if its destination falls into a monitored prefix for per-destination features
    //
    // When writting new prefix, set clearDst to 1
    // so that the first packet matching the new prefix will trigger reset of feature registers
    //
    Register<bit<1>, table_idx_t>(PREFIXES_PER_EPOCH) clearDst;
    RegisterAction<bit<1>, table_idx_t, bit<1>>(clearDst) getClearDst = {
        void apply(inout bit<1> value, out bit<1> rv) {
            rv = value;
            value = 0;
        }
    };
    
    action select_by_dst(table_idx_t idx, bit<8>prefixLength) {
        ig_md.idx = idx;
        ig_md.prefixLen = prefixLength;
        ig_md.len = (counter_t)hdr.ipv4.total_len;
        ig_md.dst_matched = 1;
    }
    action no_dst_match() {
        ig_md.dst_matched = 0;
    }
    table select_by_dst_tbl {
        key = {
            hdr.ipv4.dst_addr: ternary;
        }
        actions = {
            select_by_dst();
            no_dst_match();
        }
        size = PREFIXES_PER_EPOCH + 1;
        default_action = no_dst_match();
    }


    //
    // Child index for look ahead
    //
    
    // shift amount must be a constant
    // hence, use table lookup to extract child index (which is the BITS_PER_EPOCH next bits after prefix length)
    // statically populate child_idx_tbl with one entry for each possible prefix length.
    action get_child_idx_slash4() {
        ig_md.childIdx = (child_idx_t)(hdr.ipv4.src_addr >> (32 - (4 + BITS_PER_EPOCH)));
    }
    action get_child_idx_slash8() {
        ig_md.childIdx = (child_idx_t)(hdr.ipv4.src_addr >> (32 - (8 + BITS_PER_EPOCH)));
    }
    action get_child_idx_slash12() {
        ig_md.childIdx = (child_idx_t)(hdr.ipv4.src_addr >> (32 - (12 + BITS_PER_EPOCH)));
    }
    action get_child_idx_slash16() {
        ig_md.childIdx = (child_idx_t)(hdr.ipv4.src_addr >> (32 - (16 + BITS_PER_EPOCH)));
    }
    action get_child_idx_slash20() {
        ig_md.childIdx = (child_idx_t)(hdr.ipv4.src_addr >> (32 - (20 + BITS_PER_EPOCH)));
    }
    action get_child_idx_slash24() {
        ig_md.childIdx = (child_idx_t)(hdr.ipv4.src_addr >> (32 - (24 + BITS_PER_EPOCH)));
    }
    action get_child_idx_slash28() {
        ig_md.childIdx = (child_idx_t)(hdr.ipv4.src_addr >> (32 - (28 + BITS_PER_EPOCH)));
    }
    action get_child_idx_slash32() {
        ig_md.childIdx = 0;
    }

    table child_idx_tbl {
        key = {
            ig_md.prefixLen: exact;
        }
        actions = {
            get_child_idx_slash4();
            get_child_idx_slash8();
            get_child_idx_slash12();
            get_child_idx_slash16();
            get_child_idx_slash20();
            get_child_idx_slash24();
            get_child_idx_slash28();
            get_child_idx_slash32();
            no_op();
        }
        size = 8;
        default_action = no_op();
    }

    // shift amount must be a constant
    // hence, use table lookup to convert between the child index and the child bitmap with that index's bit set, then OR them together
    // statically populate child_bits_tbl with one entry for each possible child.
    action get_child_bits(child_bitmap_t childBits) {
        ig_md.childBits = childBits;
    }
    table child_bits_tbl {
        key = {
            ig_md.childIdx: exact;
        }
        actions = {
            get_child_bits();
            no_op();
        }
        size = CHILD_BITMAP_WIDTH;
        default_action = no_op();
    }

    //
    // Look ahead
    // Just an OR of all observed childBits values.
    //

    Register<child_bitmap_t, table_idx_t>(PREFIXES_PER_EPOCH, 0) childBitmap;
    RegisterAction<child_bitmap_t, table_idx_t, child_bitmap_t>(childBitmap) updateChildBitmap = {
        void apply(inout child_bitmap_t value, out child_bitmap_t rv) {
            rv = value;
            if (ig_md.is_result_req == 1) {
                value = 0;
            } else {
                value = value | ig_md.childBits;
            }
        }
    };

    //
    // Look back and benign prefix map Bloom filter
    //
    Hash<bloomfilter_idx_t>(HashAlgorithm_t.CRC32) src_hash32;
    Register<bit<1>, bloomfilter_idx_t>(LOOKBACK_BLOOMFILTER_BITS, 0) lookback32;

    action add_to_lookback32() {
        bit<LOOKBACK_BLOOMFILTER_IDX_BITS> idx = src_hash32.get(hdr.ipv4.src_addr & 0xFFFFFFFF);
        ig_md.src_prev_seen = lookback32.read(idx);
        lookback32.write(idx, 1);
    }
    
    //
    // Start normal ipv4 dst-based routing
    //

    action hit(PortId_t port) {
        ig_intr_tm_md.ucast_egress_port = port;
    }
    
    action miss() {
        ig_intr_dprsr_md.drop_ctl = 0x1; // Drop packet.
    }
    
    table forward {
        key = {
            vrf : exact;
            hdr.ipv4.dst_addr : lpm;
        }
    
        actions = {
            hit;
            miss;
        }
    
        const default_action = miss;
        size = 1024;
    }

    //
    // Main control-flow logic
    //
    
    apply {
        vrf = 10w0;

        // reported_prefixes_tbl.apply();
        // (ig_md.is_attack == 0)
        
        if (ig_md.is_result_req == 1) {
            ig_md.idx = hdr.result_req.prefix_idx;
            ig_md.src_matched = 1;
            ig_md.dst_matched = 1;

            ig_md.tmp_ip = hdr.ipv4.src_addr;
            ig_md.tmp_mac = hdr.ethernet.src_addr;
            ig_md.tmp_port = hdr.udp.src_port;
        }
            
        // cur_mode = mode.read(0);
        
        rrDiff_classify_tbl.apply();
        
        //
        // Source-based features
        //
        if (ig_md.is_result_req == 0) {
            select_by_src_tbl.apply();
        }
        // if (ig_md.src_matched == 1 && cur_mode == ACTIVE_ATTACK_MODE)
        if (ig_md.src_matched == 1 && ig_md.is_attack == 0) {
            ig_md.clear_src = getClearSrc.execute(ig_md.idx);
            
            hdr.result_req.pktsFrom = incrPktsFrom.execute(ig_md.idx);
            hdr.result_req.bytesFrom = incrBytesFrom.execute(ig_md.idx);
            
            hdr.result_req.minLen = updateMinLength.execute(ig_md.idx);
            hdr.result_req.maxLen = updateMaxLength.execute(ig_md.idx);
            // ig_md.lenLpf1Out = lengthLpf1.execute(ig_md.len, ig_md.idx);
            // ig_md.lenLpf2Out = lengthLpf2.execute(ig_md.lenLpf1Out, ig_md.idx);
            // ig_md.aveLen = lengthLpf3.execute(ig_md.lenLpf2Out, ig_md.idx);
            ig_md.aveLen = lengthLpf1.execute(ig_md.len, ig_md.idx);
            hdr.result_req.aveLen = updateAveLength.execute(ig_md.idx);
            
            ig_md.prevTime = updatePrevTime.execute(ig_md.idx);
            ipgTbl.apply(); // Explicit table for IPG computation cause otherwise LPFs complain they can't find the field in phv (?)
            hdr.result_req.minIPG = updateMinIPG.execute(ig_md.idx);
            hdr.result_req.maxIPG = updateMaxIPG.execute(ig_md.idx);
            // ig_md.ipgLpf1Out = ipgLpf1.execute(ig_md.ipg, ig_md.idx);
            // ig_md.ipgLpf2Out = ipgLpf2.execute(ig_md.ipgLpf1Out, ig_md.idx);
            // ig_md.aveIPG = ipgLpf3.execute(ig_md.ipgLpf2Out, ig_md.idx);
            ig_md.aveIPG = ipgLpf1.execute(ig_md.ipg, ig_md.idx);
            hdr.result_req.aveIPG = updateAveIPG.execute(ig_md.idx);
            
            hdr.result_req.dnsRes = updateDnsResp.execute(ig_md.idx);
            hdr.result_req.ntpRes = updateNtpResp.execute(ig_md.idx);
            hdr.result_req.ssdpRes = updateSsdpResp.execute(ig_md.idx);
            hdr.result_req.tcpRes = updateTcpResp.execute(ig_md.idx);
            
            child_idx_tbl.apply();
            child_bits_tbl.apply();
            hdr.result_req.childBitmap = updateChildBitmap.execute(ig_md.idx);
        }
            
        // if ((ig_md.src_matched == 0 && cur_mode == ACTIVE_ATTACK_MODE) || cur_mode == PRE_ATTACK_MODE)
        if (ig_md.src_matched == 0 && ig_md.is_attack == 0) {
            // Note: the simulator applies lookback only when both source and destination don't match.
            // Try like this for now since it shouldn't make that much of a difference.
            add_to_lookback32();
            
            // Set flag to send digest in deparser if in non-attack mode and the src was not in the /32 lookback Bloom filter
            // if (cur_mode == PRE_ATTACK_MODE && ig_md.src_prev_seen == 0)
            if (ig_md.src_prev_seen == 0) {
                ig_intr_dprsr_md.digest_type = 1;
            }
        }

        
        //
        // Destination-based features
        //
        if (ig_md.is_result_req == 0 && ig_md.is_attack == 0) {
            select_by_dst_tbl.apply();
        }
        // if (ig_md.dst_matched == 1 && cur_mode == ACTIVE_ATTACK_MODE)
        if (ig_md.dst_matched == 1) {
            ig_md.clear_dst = getClearDst.execute(ig_md.idx);
            
            hdr.result_req.pktsTo = incrPktsTo.execute(ig_md.idx);
            hdr.result_req.bytesTo = incrBytesTo.execute(ig_md.idx);

            hdr.result_req.dnsReq = updateDnsReq.execute(ig_md.idx);
            hdr.result_req.ntpReq = updateNtpReq.execute(ig_md.idx);
            hdr.result_req.ssdpReq = updateSsdpReq.execute(ig_md.idx);
            hdr.result_req.tcpReq = updateTcpReq.execute(ig_md.idx);
        }
        
        if (ig_md.is_result_req == 1) {

            hdr.result_req.clear_src = (bit<8>)ig_md.clear_src;
            hdr.result_req.clear_dst = (bit<8>)ig_md.clear_dst;
            
            // just reflect back at port level...
            // ig_intr_tm_md.ucast_egress_port = ig_intr_md.ingress_port;

            ig_intr_tm_md.ucast_egress_port = CPU_PORT;

            
            hdr.ipv4.src_addr = hdr.ipv4.dst_addr;
            hdr.ipv4.dst_addr = ig_md.tmp_ip;

            hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
            hdr.ethernet.dst_addr = ig_md.tmp_mac;

            hdr.udp.src_port = hdr.udp.dst_port;
            hdr.udp.dst_port = ig_md.tmp_port;
            hdr.udp.checksum = 0;
            
        } else {
            forward.apply();
        }

        // No need for egress processing, skip it and use empty controls for egress.
        ig_intr_tm_md.bypass_egress = 1w1;
                        
    } // END apply (main control logic)
}

Pipeline(SwitchIngressParser(),
SwitchIngress(),
SwitchIngressDeparser(),
EmptyEgressParser(),
EmptyEgress(),
EmptyEgressDeparser()) pipe;

Switch(pipe) main;
