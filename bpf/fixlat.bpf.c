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


static const __u32 TAG11 = ((__u32)SOH << 24) | ((__u32)'1' << 16) | ((__u32)'1' << 8) | ((__u32)'='); 

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




// INGRESS: Simple path - just extract Tag 11 and push to queue
static int handle_ingress(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    if (!data) return TC_ACT_OK;

    
    __u32 win = 0;
    __u8 ord_id_len = 0;
    bool copy_state = false;       
    

    unsigned char *payload = data;

    __u16 offs [MAX_TAG11_PER_PKT];
    __u16 lens [MAX_TAG11_PER_PKT];
    __u8 values_found = 0;


    int max = (int) (data_end - data);
    if (max > MAX_PAYLOAD_SCAN)
        max = MAX_PAYLOAD_SCAN;

    #pragma clang loop unroll(disable)
    for (int i=0; i < max; i++) {
        unsigned char c = payload[i];
        if (copy_state) {
            if (c == SOH) {
                // if (ord_id_len > 0) {     
                //     //req.len = ord_id_len;
                //     //bpf_map_push_elem(&pending_q, &req, 0);
                // }
                lens[values_found] = ord_id_len;
                copy_state = false; 
                win = SOH;

                if (++values_found == MAX_TAG11_PER_PKT)
                    break;
            // } else {       
                // if (ord_id_len <= FIXLAT_MAX_TAGVAL_LEN) {
                //     req.ord_id[ord_id_len++] = c;
                // }
            }
        } else {
            win = (win << 8) | c;
            if (win == TAG11) {
                copy_state = true;
                ord_id_len = 0;
                offs[values_found] = i;
            }
        }
    }

    struct pending_req req = {};
    #pragma clang loop unroll(disable)
    for (int i=0; i < values_found; i++) {
        __u8 len = lens[i];
        if (len <= FIXLAT_MAX_TAGVAL_LEN) {
            req.len = len;
            bpf_skb_load_bytes(skb, offs[i], req.ord_id, len);
            bpf_map_push_elem(&pending_q, &req, 0);
        }
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

SEC("tc")
int tc_ingress(struct __sk_buff *skb){ return handle_ingress(skb); }

// SEC("tc")
// int tc_egress(struct __sk_buff *skb){ return handle_egress(skb); }
