#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "fixlat.h"

/* Network constants not in vmlinux.h */
#define ETH_P_IP    0x0800
#define TC_ACT_OK   0
/* ASCII control characters */
#define SOH         0x01  /* Start of Header */
/* Maximum payload scan size - reduced for verifier complexity */
#define MAX_PAYLOAD_SCAN 2048
#define MAX_TAG11_PER_PKT 4

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} cfg_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, 65536);
    __type(value, struct pending_req);
} pending_q SEC(".maps");

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

/* Tail call program array */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} prog_array SEC(".maps");

/* Tail call program indices */
#define PROG_TAG_PARSER 0
#define MAX_TAIL_CALLS 32


static const __u32 TAG11 = ((__u32)SOH << 24) | ((__u32)'1' << 16) | ((__u32)'1' << 8) | ((__u32)'=');

/* FIX protocol starts with "8=FI" - we check first 3 bytes */
#define FIX_MAGIC_8  0x38   // '8'
#define FIX_MAGIC_EQ 0x3D   // '='
#define FIX_MAGIC_F  0x46   // 'F'
#define FIX_MAGIC_I  0x49   // 'I'

/* State passed via __sk_buff.cb between tail calls */
struct parser_state {
    __u32 offset;           /* Current offset in packet to scan from */
    __u32 remaining_calls;  /* Remaining tail call iterations */
};

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




/* Helper to save parser state in __sk_buff.cb */
static __always_inline void save_state(struct __sk_buff *skb, __u32 offset, __u32 remaining)
{
    skb->cb[0] = offset;
    skb->cb[1] = remaining;
}

/* Helper to load parser state from __sk_buff.cb */
static __always_inline void load_state(struct __sk_buff *skb, __u32 *offset, __u32 *remaining)
{
    *offset = skb->cb[0];
    *remaining = skb->cb[1];
}

/* HOOK 1: Filter and FIX protocol detection
 * - Parse TCP/IP headers to find payload
 * - Check if payload starts with "8=FI" (FIX protocol)
 * - Skip TCP ACKs and other non-data packets
 * - Tail call to tag parser if FIX message detected
 */
static int handle_filter(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* Parse Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    /* Parse IP header */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < 20)
        return TC_ACT_OK;

    /* Parse TCP header */
    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    __u32 tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len < 20)
        return TC_ACT_OK;

    /* Calculate payload offset and pointer */
    __u32 payload_offset = sizeof(struct ethhdr) + ip_hdr_len + tcp_hdr_len;
    unsigned char *payload = (void *)tcp + tcp_hdr_len;

    /* Check if we have at least 4 bytes of payload for "8=FI" check */
    if (payload + 4 > (unsigned char *)data_end)
        return TC_ACT_OK;

    /* Skip TCP ACK-only packets (no payload or very small) */
    __u32 payload_len = (unsigned char *)data_end - payload;
    if (payload_len < 4)
        return TC_ACT_OK;

    /* Check for FIX protocol signature: "8=FI" (at least first 3 bytes) */
    if (payload[0] != FIX_MAGIC_8 ||
        payload[1] != FIX_MAGIC_EQ ||
        payload[2] != FIX_MAGIC_F)
        return TC_ACT_OK;

    /* FIX message detected! Set up state for tag parser */
    save_state(skb, payload_offset, MAX_TAIL_CALLS);

    /* Tail call to tag parser */
    bpf_tail_call(skb, &prog_array, PROG_TAG_PARSER);

    /* If tail call fails, just return OK */
    return TC_ACT_OK;
}

/* HOOK 2: Tag 11 parser with recursive tail calling
 * - Scans for tag 11 from current offset
 * - Extracts values and pushes to pending_q
 * - Tail calls itself if more data to scan and iterations left
 */
static int handle_tag_parser(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* Load state from cb */
    __u32 start_offset = 0;
    __u32 remaining_calls = 0;
    load_state(skb, &start_offset, &remaining_calls);

    if (remaining_calls == 0)
        return TC_ACT_OK;

    unsigned char *cursor = (unsigned char *)data + start_offset;
    unsigned char *scan_end = (unsigned char *)data_end;

    /* Limit scan size for verifier */
    __u32 max_scan = (scan_end - cursor);
    if (max_scan > MAX_PAYLOAD_SCAN)
        max_scan = MAX_PAYLOAD_SCAN;

    __u32 win = 0;
    bool copy_state = false;
    __u8 ord_id_len = 0;
    __u16 tag_start_offset = 0;

    struct pending_req req = {};
    __u8 tags_found = 0;

    #pragma clang loop unroll(disable)
    for (int i = 0; i < max_scan; i++) {
        if (cursor + i >= scan_end)
            break;

        unsigned char c = cursor[i];

        if (copy_state) {
            if (c == SOH) {
                /* Found end of tag value */
                if (ord_id_len > 0 && ord_id_len <= FIXLAT_MAX_TAGVAL_LEN) {
                    req.len = ord_id_len;
                    /* Load the tag value from packet */
                    ////bpf_skb_load_bytes(skb, tag_start_offset, req.ord_id, ord_id_len);
                    ////bpf_map_push_elem(&pending_q, &req, 0);

                    tags_found++;
                    if (tags_found >= MAX_TAG11_PER_PKT)
                        break;
                }

                copy_state = false;
                ord_id_len = 0;
                win = SOH;
            } else {
                /* Accumulate length of tag value */
                if (ord_id_len <= FIXLAT_MAX_TAGVAL_LEN)
                    ord_id_len++;
            }
        } else {
            /* Scan for TAG11 pattern */
            win = (win << 8) | c;
            if (win == TAG11) {
                copy_state = true;
                ord_id_len = 0;
                tag_start_offset = start_offset + i + 1; /* +1 to skip '=' */
            }
        }
    }

    /* If we scanned max and still have iterations left, tail call again */
    if (max_scan == MAX_PAYLOAD_SCAN && remaining_calls > 1) {
        __u32 new_offset = start_offset + max_scan;
        save_state(skb, new_offset, remaining_calls - 1);
        bpf_tail_call(skb, &prog_array, PROG_TAG_PARSER);
    }

    return TC_ACT_OK;
}

// // INGRESS: Simple path - just extract Tag 11 and push to queue
// static int handle_ingress(struct __sk_buff *skb)
// {
//     //__u32 z = 0;
//     //struct fixlat_stats *st = bpf_map_lookup_elem(&stats_map, &z); //TODO: per cpu
//     //if (st) stat_inc(&st->total_packets);

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

/* Main entry point - filter and FIX detection */
SEC("tc")
int tc_ingress(struct __sk_buff *skb)
{
    return handle_filter(skb);
}

/* Tag parser - called via tail call */
SEC("tc")
int tc_tag_parser(struct __sk_buff *skb)
{
    return handle_tag_parser(skb);
}

// SEC("tc")
// int tc_egress(struct __sk_buff *skb){ return handle_egress(skb); }
