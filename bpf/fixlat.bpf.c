#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "fixlat.h"

/* Network constants not in vmlinux.h */
#define ETH_P_IP    0x0800
#define TC_ACT_OK   0

char LICENSE[] SEC("license") = "Dual BSD/GPL";

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

// Per-CPU array for temporary tag buffer to reduce stack usage
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[FIXLAT_MAX_TAGVAL_LEN]);
} tagbuf_map SEC(".maps");


enum tag11_state {
    LOOKING_FOR_SOH = 0,
    WAITING_FOR_FIRST_1_AFTER_SOH,
    WAITING_FOR_SECOND_1_AFTER_SOH,
    WAITING_FOR_EQUALS_AFTER_TAG11,
    READING_TAG11_VALUE,
    FINISHED_PARSING_TAG11_VALUE,
};

static __always_inline void stat_inc(__u64 *field) { __sync_fetch_and_add(field, 1); }

static __always_inline __u32 log2_bucket(__u64 ns) {
    if (!ns) return 0;
    __u32 b = 0;
    #pragma clang loop unroll(disable)
    for (int i=0; i<64 && ns > 1; i++) {
        ns >>= 1;
        b++;
    }
    if (b > 63) b = 63;
    return b;
}
static __always_inline void hist_add(__u64 delta_ns) {
    __u32 b = log2_bucket(delta_ns);
    __u64 *slot = bpf_map_lookup_elem(&hist_ns, &b);
    if (slot) __sync_fetch_and_add(slot, 1);
}

static __always_inline int handle_skb(struct __sk_buff *skb, enum fixlat_dir dir)
{
    __u32 z=0;
    struct fixlat_stats *st = bpf_map_lookup_elem(&stats_map, &z);
    if (st) stat_inc(&st->total_packets);

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        if (st) stat_inc(&st->non_eth_ip);
        return TC_ACT_OK;
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;
    if (ip->protocol != IPPROTO_TCP) {
        if (st) stat_inc(&st->non_tcp);
        return TC_ACT_OK;
    }
    __u32 ihl = ip->ihl * 4;

    struct tcphdr *tcp = (void *)ip + ihl;
    if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;
    __u32 doff = tcp->doff * 4;

    struct config *cfg = bpf_map_lookup_elem(&cfg_map, &z);
    if (!cfg) return TC_ACT_OK;

    // Bidirectional TCP port filter (0 = any)
    __u16 sport = bpf_ntohs(tcp->source);
    __u16 dport = bpf_ntohs(tcp->dest);
    if (cfg->watch_port != 0) {
        if (!(sport == cfg->watch_port || dport == cfg->watch_port))
            return TC_ACT_OK; // ignore
    }

    unsigned char *payload = (void *)tcp + doff;
    if (payload >= (unsigned char *)data_end) {
        if (st) stat_inc(&st->empty_payload);
        return TC_ACT_OK;
    }

    // Use per-CPU map for tagbuf to reduce stack usage
    char *tagbuf = bpf_map_lookup_elem(&tagbuf_map, &z);
    if (!tagbuf) return TC_ACT_OK;

    // Process multiple FIX messages in one TCP packet
    unsigned char *search_start = payload;

    int state = LOOKING_FOR_SOH;
    __u8 tlen = 0;

    #pragma clang loop unroll(disable)
    for (int msg_idx = 0; msg_idx < 10; msg_idx++) {
        if (search_start >= (unsigned char *)data_end)
            break;

        unsigned char *cursor = search_start;
        

        if (cursor >= (unsigned char *)data_end)
            break;

        unsigned char c = *cursor++;

        switch (state) {
        case LOOKING_FOR_SOH:
            if (c == 0x01)
                state = WAITING_FOR_FIRST_1_AFTER_SOH;
            break;
        case WAITING_FOR_FIRST_1_AFTER_SOH:
            if (c == '1') {
                state = WAITING_FOR_SECOND_1_AFTER_SOH;
            } else {
                state = LOOKING_FOR_SOH;
            }
            break;
        case WAITING_FOR_SECOND_1_AFTER_SOH:
            if (c == '1') {
                state = WAITING_FOR_EQUALS_AFTER_TAG11;
            } else {
                state = LOOKING_FOR_SOH;
            }
            break;
        case WAITING_FOR_EQUALS_AFTER_TAG11:
            if (c == '=') {
                state = READING_TAG11_VALUE;
                tlen = 0;
            } else {
                state = LOOKING_FOR_SOH;
            }
            break;
        case READING_TAG11_VALUE:
            if (c == 0x01) {
                state = FINISHED_PARSING_TAG11_VALUE;
            } else if (tlen < FIXLAT_MAX_TAGVAL_LEN) { 
                tagbuf[tlen++] = c; // tagbuf may contain value truncated to FIXLAT_MAX_TAGVAL_LEN
            }
            break;
        }

        if (state == FINISHED_PARSING_TAG11_VALUE) {
            if (tlen > 0) {
                /// do something with tagbuf

                if (dir == DIR_INBOUND) {
                    struct pending_req req = {.ts_ns=bpf_ktime_get_ns(), .len=tlen};
                    #pragma clang loop unroll(disable)
                    for (int i=0;i<FIXLAT_MAX_TAGVAL_LEN;i++) { 
                        if (i<tlen) req.tag[i]=tagbuf[i]; 
                    }
                    bpf_map_push_elem(&pending_q, &req, 0);
                    stat_inc(&st->inbound_total);
                } else {
                    bool matched = false;
                    struct pending_req head;
                    if (bpf_map_peek_elem(&pending_q, &head) == 0) {
                        bool eq = (head.len == tlen);
                        if (eq) {
                            #pragma clang loop unroll(disable)
                            for (int i=0; i<FIXLAT_MAX_TAGVAL_LEN; i++) {
                                if (i >= tlen) break;
                                if (head.tag[i] != tagbuf[i]) {
                                    eq = false;
                                    break;
                                }
                            }
                        }
        
                        if (eq && bpf_map_pop_elem(&pending_q, &head) == 0) {
                            __u64 now = bpf_ktime_get_ns();
                            hist_add(now - head.ts_ns);
                            matched = true;
                        }
                    }
        
                    if (!matched) {
                        stat_inc(&st->unmatched_outbound);
                    }
                    stat_inc(&st->outbound_total);
                }
                tlen = 0;
            }
            state = WAITING_FOR_SOH;
        }



        search_start = cursor;

            // // No Tag 11 found in remaining data
            // if (messages_found == 0 && st) {
            //     stat_inc(&st->no_tag11);
            // }


        
    }
    return TC_ACT_OK;
}

SEC("tc")
int tc_ingress(struct __sk_buff *skb){ return handle_skb(skb, DIR_INBOUND); }

SEC("tc")
int tc_egress(struct __sk_buff *skb){ return handle_skb(skb, DIR_OUTBOUND); }
