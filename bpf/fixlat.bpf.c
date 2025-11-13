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

// Remove __always_inline to reduce verifier complexity
static __noinline int extract_tag11(void *data, void *data_end, char out[FIXLAT_MAX_TAGVAL_LEN], __u8 *olen) {
    unsigned char *p = data, *end = data_end;
    bool at_field_start = true;  // First position is always at field start

    // Increased to 200 iterations to search deeper into FIX message
    // (Tag 11 often appears after header fields which can be 100+ bytes)
    #pragma clang loop unroll(disable)
    for (int i = 0; i < 200; i++) {
        // Explicit bounds check before access
        if (p + 3 > end)
            break;

        // FIXED: Check for proper FIX field delimiter
        // Tag 11 must be at field start (after SOH or at message beginning)
        if (at_field_start && p[0]=='1' && p[1]=='1' && p[2]=='=') {
            p += 3;
            __u8 len = 0;

            // Extract the value until SOH or end of packet
            #pragma clang loop unroll(disable)
            for (int j = 0; j < FIXLAT_MAX_TAGVAL_LEN; j++) {
                if (p >= end)
                    break;
                if (*p == 0x01)  // Stop at field delimiter
                    break;
                out[len++] = *p;
                p++;
            }
            *olen = len;
            return 0;
        }

        // Update field start flag: next position is at field start if current char is SOH
        at_field_start = (*p == 0x01);
        p++;
    }
    return -1;
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

    // // Bidirectional IP/Port filter
    // if (cfg->watch_ipv4 != 0) {
    //     if (!(ip->saddr == cfg->watch_ipv4 || ip->daddr == cfg->watch_ipv4))
    //         return TC_ACT_OK; // ignore
    // }
    // __u16 sport = bpf_ntohs(tcp->source);
    // __u16 dport = bpf_ntohs(tcp->dest);
    // if (cfg->watch_port != 0) {
    //     if (!(sport == cfg->watch_port || dport == cfg->watch_port))
    //         return TC_ACT_OK; // ignore
    // }

    unsigned char *payload = (void *)tcp + doff;
    if (payload >= (unsigned char *)data_end) {
        if (st) stat_inc(&st->empty_payload);
        return TC_ACT_OK;
    }

    // Track payload size for debugging
    __u64 payload_size = (unsigned char *)data_end - payload;
    if (st) {
        stat_inc(&st->has_payload);
        __sync_fetch_and_add(&st->payload_bytes, payload_size);
    }

    // Use per-CPU map for tagbuf to reduce stack usage
    char *tagbuf = bpf_map_lookup_elem(&tagbuf_map, &z);
    if (!tagbuf) return TC_ACT_OK;

    // Process multiple FIX messages in one TCP packet
    // TCP batches ~5 messages per packet even with TCP_NODELAY
    unsigned char *search_start = payload;
    int messages_found = 0;

    #pragma clang loop unroll(disable)
    for (int msg_idx = 0; msg_idx < 10 && messages_found < 5; msg_idx++) {
        if (search_start >= (unsigned char *)data_end)
            break;

        __u8 tlen = 0;
        int tag11_offset = extract_tag11(search_start, data_end, tagbuf, &tlen);

        if (tag11_offset != 0) {
            // No Tag 11 found in remaining data
            if (messages_found == 0 && st) {
                stat_inc(&st->no_tag11);
            }
            break;
        }

        messages_found++;

        if (dir == DIR_INBOUND) {
            struct pending_req req = {.ts_ns=bpf_ktime_get_ns(), .len=tlen};
            #pragma clang loop unroll(disable)
            for (int i=0;i<FIXLAT_MAX_TAGVAL_LEN;i++){ if (i<tlen) req.tag[i]=tagbuf[i]; }
            bpf_map_push_elem(&pending_q, &req, 0);
            stat_inc(&st->inbound_total);
        } else {
        // Reduced to 2 iterations to lower verifier complexity
        #define MAX_POPS 2
        struct pending_req head;
        bool matched = false;

        #pragma clang loop unroll(disable)
        for (int pops = 0; pops < MAX_POPS; pops++) {
            // Atomically pop element
            if (bpf_map_pop_elem(&pending_q, &head) != 0) {
                break; // queue empty
            }
            
            // Compare head.tag vs current outbound tag
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
            
            if (eq) {
                __u64 now = bpf_ktime_get_ns();
                hist_add(now - head.ts_ns);
                matched = true;
                break;
            }
            
            // Not a match: count and continue
            stat_inc(&st->fifo_missed);
        }
        
        // If we didn't match, increment unmatched counter
        if (!matched) {
            stat_inc(&st->unmatched_outbound);
        }
        
        stat_inc(&st->outbound_total);
    }
    return TC_ACT_OK;
}

SEC("tc")
int tc_ingress(struct __sk_buff *skb){ return handle_skb(skb, DIR_INBOUND); }

SEC("tc")
int tc_egress(struct __sk_buff *skb){ return handle_skb(skb, DIR_OUTBOUND); }
