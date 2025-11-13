#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "fixlat.h"

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

static __always_inline void stat_inc(__u64 *field) { __sync_fetch_and_add(field, 1); }

static __always_inline __u32 log2_bucket(__u64 ns) {
    if (!ns) return 0;
    __u32 b = 0;
    #pragma clang loop unroll(disable)
    for (int i=0;i<63 && ns;i++) { ns >>= 1; if (ns) b++; }
    if (b>63) b=63;
    return b;
}
static __always_inline void hist_add(__u64 delta_ns) {
    __u32 b = log2_bucket(delta_ns);
    __u64 *slot = bpf_map_lookup_elem(&hist_ns, &b);
    if (slot) __sync_fetch_and_add(slot, 1);
}

static __always_inline int extract_tag11(void *data, void *data_end, char out[FIXLAT_MAX_TAGVAL_LEN], __u8 *olen) {
    unsigned char *p = data, *end = data_end;
    for (; p + 3 <= end; p++) {
        if (p[0]=='1' && p[1]=='1' && p[2]=='=') {
            p += 3;
            __u8 len = 0;
            for (; p < end && *p != 0x01; p++) {
                if (len < FIXLAT_MAX_TAGVAL_LEN) out[len++] = *p; else break;
            }
            *olen = len;
            return 0;
        }
    }
    return -1;
}

static __always_inline int handle_skb(struct __sk_buff *skb, enum fixlat_dir dir)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;
    if (ip->protocol != IPPROTO_TCP) return TC_ACT_OK;
    __u32 ihl = ip->ihl * 4;

    struct tcphdr *tcp = (void *)ip + ihl;
    if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;
    __u32 doff = tcp->doff * 4;

    __u32 z=0;
    struct config *cfg = bpf_map_lookup_elem(&cfg_map, &z);
    if (!cfg || !cfg->enabled) return TC_ACT_OK;

    // Bidirectional IP/Port filter
    if (cfg->watch_ipv4 != 0) {
        if (!(ip->saddr == cfg->watch_ipv4 || ip->daddr == cfg->watch_ipv4))
            return TC_ACT_OK; // ignore
    }
    __u16 sport = bpf_ntohs(tcp->source);
    __u16 dport = bpf_ntohs(tcp->dest);
    if (cfg->watch_port != 0) {
        if (!(sport == cfg->watch_port || dport == cfg->watch_port))
            return TC_ACT_OK; // ignore
    }

    unsigned char *payload = (void *)tcp + doff;
    if (payload >= (unsigned char *)data_end) return TC_ACT_OK;

    char tagbuf[FIXLAT_MAX_TAGVAL_LEN] = {};
    __u8 tlen = 0;
    if (extract_tag11(payload, data_end, tagbuf, &tlen) != 0) {
        // Not a FIX message or doesn't contain tag 11, ignore silently
        return TC_ACT_OK;
    }

    struct fixlat_stats *st = bpf_map_lookup_elem(&stats_map, &z);
    if (!st) return TC_ACT_OK;

    if (dir == DIR_INBOUND) {
        struct pending_req req = {.ts_ns=bpf_ktime_get_ns(), .len=tlen};
        #pragma clang loop unroll(disable)
        for (int i=0;i<FIXLAT_MAX_TAGVAL_LEN;i++){ if (i<tlen) req.tag[i]=tagbuf[i]; else break; }
        bpf_map_push_elem(&pending_q, &req, 0);
        stat_inc(&st->inbound_total);
    } else {
        #define MAX_POPS 8
        int pops = 0;
        struct pending_req head;
        bool matched = false;
        bool queue_empty = false;

        while (pops++ < MAX_POPS) {
            // Atomically pop element (fixes race condition)
            if (bpf_map_pop_elem(&pending_q, &head) != 0) {
                queue_empty = true;
                break; // queue empty
            }
            
            // Compare head.tag vs current outbound tag
            bool eq = (head.len == tlen);
            #pragma clang loop unroll(disable)
            for (int i=0; eq && i<FIXLAT_MAX_TAGVAL_LEN && i<tlen; i++) {
                if (head.tag[i] != tagbuf[i]) eq = false;
            }
            
            if (eq) {
                __u64 now = bpf_ktime_get_ns();
                hist_add(now - head.ts_ns);
                matched = true;
                break;
            }
            
            // Not a match: count and continue (bounded by MAX_POPS)
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
