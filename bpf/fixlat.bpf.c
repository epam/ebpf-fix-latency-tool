#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "fixlat.h"

/* Network constants not in vmlinux.h */
#define ETH_P_IP    0x0800
#define IPPROTO_TCP 6
#define TC_ACT_OK   0
/* ASCII control characters */
#define SOH         0x01  /* Start of Header */

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} cfg_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1Mb
} ingress_tag11_rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1Mb
} egress_tag11_rb SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 8);   /* number of tail programs */
    __type(key, __u32);
    __type(value, __u32);
} ingress_jump_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 8);   /* number of tail programs */
    __type(key, __u32);
    __type(value, __u32);
} egress_jump_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);
} hist_ns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct fixlat_stats);
} stats_map SEC(".maps");


static const __u32 TAG11 = ((__u32)SOH << 24) | ((__u32)'1' << 16) | ((__u32)'1' << 8) | ((__u32)'=');

/* FIX protocol BeginString tag starts with "8=FI" - as 32-bit for direct memory read (little-endian) */
static const __u32 FIX_BEGIN_STRING_PREFIX = ((__u32)'8' << 0) | ((__u32)'=' << 8) | ((__u32)'F' << 16) | ((__u32)'I' << 24);



static __always_inline void stat_inc(__u64 *field) { __sync_fetch_and_add(field, 1); }

// static __always_inline __u32 log2_bucket(__u64 ns) {
//     if (!ns) return 0;
//     __u32 b = 0;
//     #pragma clang loop unroll(disable)
//     for (int i=0; i<64 && ns > 1; i++) {
//         ns >>= 1;
//         b++;
//     }
//     if (b > 63) b = 63;
//     return b;
// }
// static __always_inline void hist_add(__u64 delta_ns) {
//     __u32 b = log2_bucket(delta_ns);
//     __u64 *slot = bpf_map_lookup_elem(&hist_ns, &b);
//     if (slot) __sync_fetch_and_add(slot, 1);
// }

// // Common packet parsing - extract as __noinline to share code between ingress/egress
// // Returns payload pointer or NULL if packet should be ignored
// static __noinline unsigned char* parse_packet_headers(
//     struct __sk_buff *skb,
//     struct fixlat_stats *st)
// {
//     void *data = (void *)(long)skb->data;
//     void *data_end = (void *)(long)skb->data_end;

//     struct ethhdr *eth = data;
//     if ((void *)(eth + 1) > data_end) return NULL;
//     if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
//         if (st) stat_inc(&st->non_eth_ip);
//         return NULL;
//     }

//     struct iphdr *ip = (void *)(eth + 1);
//     if ((void *)(ip + 1) > data_end) return NULL;
//     if (ip->protocol != IPPROTO_TCP) {
//         if (st) stat_inc(&st->non_tcp);
//         return NULL;
//     }
//     __u32 ihl = ip->ihl * 4;

//     struct tcphdr *tcp = (void *)ip + ihl;
//     if ((void *)(tcp + 1) > data_end) return NULL;
//     __u32 doff = tcp->doff * 4;

//     __u32 z = 0;
//     struct config *cfg = bpf_map_lookup_elem(&cfg_map, &z);
//     if (!cfg) return NULL;

//     // Bidirectional TCP port filter (0 = any)
//     if (cfg->watch_port != 0) {
//         __u16 sport = bpf_ntohs(tcp->source);
//         __u16 dport = bpf_ntohs(tcp->dest);
//         if (!(sport == cfg->watch_port || dport == cfg->watch_port))
//             return NULL;
//     }

//     unsigned char *payload = (void *)tcp + doff;
//     // if (payload >= (unsigned char *)data_end) {
//     //     if (st) stat_inc(&st->empty_payload);
//     //     return NULL;
//     // }

    
//     return payload;
// }

#define CB_MAGIC        0
#define CB_SCAN_START   1
#define CB_MAGIC_MARKER 0xBEBE  
#define PER_CALL_SCAN_DEPTH 256

// We do not support Jumbo MTU 
#define MTU 1500

// Clean packet scanning function - assumes packet is valid
// Only called from payload tail functions (via tail calls)
static __always_inline int handle_payload_chunk(struct __sk_buff *skb, __u32 idx, void *ringbuf, void *jump_table)
{
    // Verify magic marker set by header validation function
    if (skb->cb[CB_MAGIC] != CB_MAGIC_MARKER)
        return TC_ACT_OK; // CB buffer was clobbered, abort

    __u8 *data_start = (__u8 *)(long)skb->data;
    __u8 *data_end   = (__u8 *)(long)skb->data_end;

    __u32 base = skb->cb[CB_SCAN_START];
    if (base > MTU) // otherwise verifier assumes base is [0, 0xffffffff]
        return TC_ACT_OK;

    bool found_tag11_start = false;
    __u32 window = 0;
    __u32 data_offset = base;

    #pragma clang loop unroll(disable)
    for (int i = 0; i < PER_CALL_SCAN_DEPTH; i++, data_offset++) {
        __u8 *p = data_start + data_offset;
        if (p + 1 > data_end)
            return TC_ACT_OK; // end of packet (normal)
        __u8 c = *p;

        window = (window << 8) | c;
        found_tag11_start = (window == TAG11);
        if (found_tag11_start) { // Tag 11 begins <SOH>11=
            break; // data_offset points to byte after '='
        }
    }


    if (found_tag11_start) {
        bool found_tag11_end = false;
        struct tag11_with_timestamp req = {};

        #pragma clang loop unroll(disable)
        for (int i = 0; i < FIXLAT_MAX_TAGVAL_LEN; i++) {
            data_offset++;

            __u8 *p = data_start + data_offset;
            if (p + 1 > data_end)
                return TC_ACT_OK; // end of packet (abnormal)

            __u8 c = *p;
        
            if (c == SOH) { // Tag 11 ends
                req.len = i;
                found_tag11_end = true;
                break;
            } else {  
                req.ord_id[i] = c;
            }
        }

        if (found_tag11_end) {
            if (req.len > 0) {
                req.ts_ns = bpf_ktime_get_ns();
                bpf_ringbuf_output(ringbuf, &req, sizeof(req), BPF_RB_NO_WAKEUP);
            }
        } else {
            // likely tag 11 length exceed FIXLAT_MAX_TAGVAL_LEN - report as error
        }
    }

    // Advance scan position for next tail call (back off 3 bytes to avoid missing patterns at boundaries)
    if (base >= data_offset - 3) {
        //TODO: "No forward advance" - Increment error counter
        return TC_ACT_OK;
    }
    skb->cb[CB_SCAN_START] = data_offset - 3;

    bpf_tail_call(skb, jump_table, idx + 1); // Tail call next chunk
    return TC_ACT_OK;
}

// Entry point - validates TCP headers and initializes scanning
SEC("tc")
int handle_ingress_headers(struct __sk_buff *skb)
{
    __u32 z = 0;
    struct fixlat_stats *st = bpf_map_lookup_elem(&stats_map, &z);
    if (st) stat_inc(&st->total_packets);

    __u8 *data_start = (__u8 *)(long)skb->data;
    __u8 *data_end   = (__u8 *)(long)skb->data_end;

    // Parse and validate TCP headers
    struct ethhdr *eth = (void *)data_start;
    if ((void *)(eth + 1) > (void *)data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        if (st) stat_inc(&st->non_eth_ip);
        return TC_ACT_OK;
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > (void *)data_end)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_TCP) {
        if (st) stat_inc(&st->non_tcp);
        return TC_ACT_OK;
    }

    __u32 ihl = ip->ihl * 4;
    if (ihl < sizeof(*ip))
        return TC_ACT_OK;

    struct tcphdr *tcp = (void *)((__u8 *)ip + ihl);
    if ((void *)(tcp + 1) > (void *)data_end)
        return TC_ACT_OK;

    __u32 doff = tcp->doff * 4;
    if (doff < sizeof(*tcp))
        return TC_ACT_OK;

    __u8 *payload = (__u8 *)tcp + doff;
    if (payload > data_end)
        return TC_ACT_OK;

    // Empty TCP payload (pure ACKs, keepalives, etc.)
    if (payload >= data_end) {
        if (st) stat_inc(&st->empty_payload);
        return TC_ACT_OK;
    }

    // FIX messages must be at least 32 bytes
    if (payload + 32 > data_end) {
        if (st) stat_inc(&st->empty_payload);
        return TC_ACT_OK;
    }

    // Verify FIX protocol prefix "8=FI"
    __u32 *prefix = (__u32 *)payload;
    if (*prefix != FIX_BEGIN_STRING_PREFIX)
        return TC_ACT_OK;

    // Port filtering
    struct config *cfg = bpf_map_lookup_elem(&cfg_map, &z);
    if (!cfg)
        return TC_ACT_OK;

    // Bidirectional TCP port filter (0 = any)
    if (cfg->watch_port != 0) {
        __u16 sport = bpf_ntohs(tcp->source);
        __u16 dport = bpf_ntohs(tcp->dest);
        if (!(sport == cfg->watch_port || dport == cfg->watch_port))
            return TC_ACT_OK;
    }

    // Initialize scan state
    skb->cb[CB_MAGIC] = CB_MAGIC_MARKER;
    skb->cb[CB_SCAN_START] = 0;

    // Start scanning via tail call
    bpf_tail_call(skb, &ingress_jump_table, 1);
    return TC_ACT_OK;
}

// Ingress payload scanning tail calls
SEC("tc") int handle_ingress_payload_1(struct __sk_buff *skb) { return handle_payload_chunk(skb, 1, &ingress_tag11_rb, &ingress_jump_table); }
SEC("tc") int handle_ingress_payload_2(struct __sk_buff *skb) { return handle_payload_chunk(skb, 2, &ingress_tag11_rb, &ingress_jump_table); }
SEC("tc") int handle_ingress_payload_3(struct __sk_buff *skb) { return handle_payload_chunk(skb, 3, &ingress_tag11_rb, &ingress_jump_table); }
SEC("tc") int handle_ingress_payload_4(struct __sk_buff *skb) { return handle_payload_chunk(skb, 4, &ingress_tag11_rb, &ingress_jump_table); }
SEC("tc") int handle_ingress_payload_5(struct __sk_buff *skb) { return handle_payload_chunk(skb, 5, &ingress_tag11_rb, &ingress_jump_table); }

// Egress payload scanning tail calls
SEC("tc") int handle_egress_payload_1(struct __sk_buff *skb) { return handle_payload_chunk(skb, 1, &egress_tag11_rb, &egress_jump_table); }
SEC("tc") int handle_egress_payload_2(struct __sk_buff *skb) { return handle_payload_chunk(skb, 2, &egress_tag11_rb, &egress_jump_table); }
SEC("tc") int handle_egress_payload_3(struct __sk_buff *skb) { return handle_payload_chunk(skb, 3, &egress_tag11_rb, &egress_jump_table); }
SEC("tc") int handle_egress_payload_4(struct __sk_buff *skb) { return handle_payload_chunk(skb, 4, &egress_tag11_rb, &egress_jump_table); }
SEC("tc") int handle_egress_payload_5(struct __sk_buff *skb) { return handle_payload_chunk(skb, 5, &egress_tag11_rb, &egress_jump_table); }

// Entry point for egress - validates TCP headers and initializes scanning
SEC("tc")
int handle_egress_headers(struct __sk_buff *skb)
{
    __u32 z = 0;
    struct fixlat_stats *st = bpf_map_lookup_elem(&stats_map, &z);
    if (st) stat_inc(&st->total_packets);

    __u8 *data_start = (__u8 *)(long)skb->data;
    __u8 *data_end   = (__u8 *)(long)skb->data_end;

    // Parse and validate TCP headers
    struct ethhdr *eth = (void *)data_start;
    if ((void *)(eth + 1) > (void *)data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        if (st) stat_inc(&st->non_eth_ip);
        return TC_ACT_OK;
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > (void *)data_end)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_TCP) {
        if (st) stat_inc(&st->non_tcp);
        return TC_ACT_OK;
    }

    __u32 ihl = ip->ihl * 4;
    if (ihl < sizeof(*ip))
        return TC_ACT_OK;

    struct tcphdr *tcp = (void *)((__u8 *)ip + ihl);
    if ((void *)(tcp + 1) > (void *)data_end)
        return TC_ACT_OK;

    __u32 doff = tcp->doff * 4;
    if (doff < sizeof(*tcp))
        return TC_ACT_OK;

    __u8 *payload = (__u8 *)tcp + doff;
    if (payload > data_end)
        return TC_ACT_OK;

    // Empty TCP payload (pure ACKs, keepalives, etc.)
    if (payload >= data_end) {
        if (st) stat_inc(&st->empty_payload);
        return TC_ACT_OK;
    }

    // FIX messages must be at least 32 bytes
    if (payload + 32 > data_end) {
        if (st) stat_inc(&st->empty_payload);
        return TC_ACT_OK;
    }

    // Verify FIX protocol prefix "8=FI"
    __u32 *prefix = (__u32 *)payload;
    if (*prefix != FIX_BEGIN_STRING_PREFIX)
        return TC_ACT_OK;

    // Port filtering
    struct config *cfg = bpf_map_lookup_elem(&cfg_map, &z);
    if (!cfg)
        return TC_ACT_OK;

    // Bidirectional TCP port filter (0 = any)
    if (cfg->watch_port != 0) {
        __u16 sport = bpf_ntohs(tcp->source);
        __u16 dport = bpf_ntohs(tcp->dest);
        if (!(sport == cfg->watch_port || dport == cfg->watch_port))
            return TC_ACT_OK;
    }

    // Initialize scan state
    skb->cb[CB_MAGIC] = CB_MAGIC_MARKER;
    skb->cb[CB_SCAN_START] = 0;

    // Start scanning via tail call
    bpf_tail_call(skb, &egress_jump_table, 1);
    return TC_ACT_OK;
}


// static int handle_ingress(struct __sk_buff *skb)
// {
//     __u8 *data_start = (__u8 *)(long)skb->data;
//     __u8 *data_end = (__u8 *)(long)skb->data_end;

//     __u64 timestamp = bpf_ktime_get_ns();
//     __u32 window = SOH;
//     size_t value_length = 0;
//     bool looking_for_tag11 = true;

//     struct pending_req req;


//     #pragma clang loop unroll(disable)
//     for (int i = 0; i < FIXLAT_MAX_SCAN; i++) {
//         if ((i & 63) == 0) {  // Every 64 iterations
//             asm volatile("" ::: "memory");
//         }
//         __u8 *p = data_start + i;
//         if (p + 1 > data_end)
//             break;

//         __u8 c = *p;

//         if (looking_for_tag11) {
//             window = (window << 8) | c;
//             if (window == TAG11) { // Tag 11 begins <SOH>11=
//                 looking_for_tag11 = false;
//                 value_length = 0;
//                 __builtin_memset(&req, 0, sizeof(req)); // Verifier likes this redundant reset
//             }
//         } else {
//             if (c == SOH) {  // Tag 11 ends
//                 req.len = value_length;
//                 req.ts_ns = timestamp;
                
//                 if (bpf_ringbuf_output(&pending_req_rb, &req, sizeof(req), BPF_RB_NO_WAKEUP) != 0)
//                     break;

//                 window = SOH; // =SOH confuses verifier
//                 looking_for_tag11 = true;

//             } else {
//                 if (value_length < sizeof(req.ord_id))
//                     req.ord_id[value_length++] = c;
//             }
//         }
//     }

//     return TC_ACT_OK;
// }

// // INGRESS: Simple path - just extract Tag 11 and push to queue
// static int handle_ingress(struct __sk_buff *skb)
// {
//     //__u32 z = 0;
//     struct fixlat_stats *st = bpf_map_lookup_elem(&stats_map, &z); //TODO: per cpu
//     if (st) stat_inc(&st->total_packets);
//
//     //unsigned char  *cursor = parse_packet_headers(skb, st);
//     //unsigned char * payload_end = (unsigned char *)(void *)(long)skb->data_end;
//     void *data     = (void *)(long)skb->data;
//     void *data_end = (void *)(long)skb->data_end;

//     if (!data || !data_end) return TC_ACT_OK;

    
//     uint32_t win = 0;
//     struct pending_req req = {};
//     __u8 req_len = 0;
//     bool reading = false;       
    

//     unsigned char *payload = data;


//     int max = (int) (data_end - data);
//     if (max > MAX_PAYLOAD_SCAN)
//         max = MAX_PAYLOAD_SCAN;

//     #pragma clang loop unroll(disable)
//     for (int i=0; i < max; i++) {
//         unsigned char c = payload[i];
//         if (reading) {
//             if (c != SOH) {
//                 if (req_len <= FIXLAT_MAX_TAGVAL_LEN) {
//                     req.tag[req_len++] = c;
//                 }
//                 continue;
//             }
            
//             //if (req_len > 0) {
//                 req.len = req_len;
//                 (void)bpf_map_push_elem(&pending_q, &req, 0);
//                 //TODO:if (st) st->inbound_total++;
                
//                 // if (tag11_count++ >= MAX_TAG11_PER_PKT) {
//                 //     break;
//                 // }
//             //}
//             reading = false; // malformed, resume scanning
//             win = 0;
//             continue;
//         } 


//         win = (win >> 8) | ((uint32_t)c << 24);
//         if (win == TAG11) {
//             reading = true;
//             //req.ts_ns = bpf_ktime_get_ns();
//             req_len = 0;
//         }
//     }
//     return TC_ACT_OK;
// }

// // EGRESS: Complex path - extract Tag 11 and match with queue
// static __always_inline int handle_egress(struct __sk_buff *skb)
// {
//     __u32 z = 0;
//     struct fixlat_stats *st = bpf_map_lookup_elem(&stats_map, &z);
//     if (st) stat_inc(&st->total_packets);

//     unsigned char *payload_end;
//     unsigned char *payload = parse_packet_headers(skb, st, &payload_end);
//     if (!payload) return TC_ACT_OK;

//     // Process every character in the payload
//     unsigned char *cursor = payload;

//     int state = LOOKING_FOR_SOH;
//     __u8 tlen = 0;
//     unsigned char *tag11_start = NULL;

//     int i = 0;
//     while (cursor < payload_end && i < MAX_PAYLOAD_SCAN) {
//         i++;

//         unsigned char c = *cursor++;

//         switch (state) {
//             case LOOKING_FOR_SOH:
//                 if (c == SOH)
//                     state = WAITING_FOR_FIRST_1_AFTER_SOH;
//                 break;
//             case WAITING_FOR_FIRST_1_AFTER_SOH:
//                 if (c == '1') {
//                     state = WAITING_FOR_SECOND_1_AFTER_SOH;
//                 } else {
//                     state = LOOKING_FOR_SOH;
//                 }
//                 break;
//             case WAITING_FOR_SECOND_1_AFTER_SOH:
//                 if (c == '1') {
//                     state = WAITING_FOR_EQUALS_AFTER_TAG11;
//                 } else {
//                     state = LOOKING_FOR_SOH;
//                 }
//                 break;
//             case WAITING_FOR_EQUALS_AFTER_TAG11:
//                 if (c == '=') {
//                     state = READING_TAG11_VALUE;
//                     tlen = 0;
//                     tag11_start = cursor;
//                 } else {
//                     state = LOOKING_FOR_SOH;
//                 }
//                 break;
//             case READING_TAG11_VALUE:
//                 if (c == SOH) {
//                     state = FINISHED_PARSING_TAG11_VALUE;
//                 } else if (tlen < FIXLAT_MAX_TAGVAL_LEN) {
//                     tlen++;
//                 }
//                 break;
//         }

//         if (state == FINISHED_PARSING_TAG11_VALUE) {
//             if (tlen > 0 && tag11_start != NULL) {
//                 // EGRESS: Match with queue and measure latency
//                 bool matched = false;
//                 struct pending_req head;
//                 if (bpf_map_peek_elem(&pending_q, &head) == 0) {
//                     bool eq = (head.len == tlen);
//                     if (eq) {
//                         #pragma clang loop unroll(disable)
//                         for (int i=0; i<tlen && i<FIXLAT_MAX_TAGVAL_LEN; i++) {
//                             if (tag11_start + i >= payload_end) {
//                                 eq = false;
//                                 break;
//                             }
//                             if (head.tag[i] != tag11_start[i]) {
//                                 eq = false;
//                                 break;
//                             }
//                         }
//                     }

//                     if (eq && bpf_map_pop_elem(&pending_q, &head) == 0) {
//                         __u64 now = bpf_ktime_get_ns();
//                         hist_add(now - head.ts_ns);
//                         matched = true;
//                     }
//                 }

//                 if (!matched) {
//                     stat_inc(&st->unmatched_outbound);
//                 }
//                 stat_inc(&st->outbound_total);

//                 tlen = 0;
//                 tag11_start = NULL;
//             }
//             state = LOOKING_FOR_SOH;
//         }
//     }
//     return TC_ACT_OK;
// }

// SEC("tc")
// int tc_ingress(struct __sk_buff *skb)
// {
//     return handle_ingress(skb);
// }

// SEC("tc")
// int tc_egress(struct __sk_buff *skb){ return handle_egress(skb); }
