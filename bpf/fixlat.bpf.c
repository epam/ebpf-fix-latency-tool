#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "fixlat.h"

/* Network constants not in vmlinux.h */
#define ETH_P_IP    0x0800
#define ETH_P_8021Q  0x8100
#define ETH_P_8021AD 0x88A8

#define IPPROTO_TCP 6
#define TC_ACT_OK   0


// FIX tag delimiter
#define SOH         0x01

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
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct fixlat_stats);
} stats_map SEC(".maps");


static const __u32 TAG11 = ((__u32)SOH << 24) | ((__u32)'1' << 16) | ((__u32)'1' << 8) | ((__u32)'=');

/* FIX protocol BeginString tag starts with "8=FI" - as 32-bit for direct memory read (little-endian) */
static const __u32 FIX_BEGIN_STRING_PREFIX = ((__u32)'8' << 0) | ((__u32)'=' << 8) | ((__u32)'F' << 16) | ((__u32)'I' << 24);



static __always_inline void stat_inc(__u64 *field) { __sync_fetch_and_add(field, 1); }


#define CB_MAGIC        0
#define CB_SCAN_START   1
#define CB_MAGIC_MARKER 0xBEBE  
#define PER_CALL_SCAN_DEPTH 256

// We do not support Jumbo MTU 
#define MTU 1500

// Clean packet scanning function - assumes packet is valid
// Only called from payload tail functions (via tail calls)
static __always_inline int handle_payload_chunk(struct __sk_buff *skb, __u32 idx, void *ringbuf, void *jump_table, bool is_ingress)
{
    __u32 z = 0;
    struct fixlat_stats *st = bpf_map_lookup_elem(&stats_map, &z);

    // Verify magic marker set by header validation function
    if (skb->cb[CB_MAGIC] != CB_MAGIC_MARKER) {
        // CB buffer was clobbered, abort
        if (st) stat_inc(&st->cb_clobbered);
        return TC_ACT_OK;
    }

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
            if (p + 1 > data_end) {
                // Tag 11 value exceeded packet boundary
                if (st) stat_inc(&st->tag11_too_long);
                return TC_ACT_OK;
            }

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

                // Track successful tag 11 extraction
                if (st) {
                    if (is_ingress)
                        stat_inc(&st->inbound_total);
                    else
                        stat_inc(&st->outbound_total);
                }
            }
        } else {
            // likely tag 11 length exceed FIXLAT_MAX_TAGVAL_LEN - report as error
        }
    }

    // Advance scan position for next tail call (back off 3 bytes to avoid missing patterns at boundaries)
    if (base >= data_offset - 3) {
        // Insufficient forward progress - parser is stuck
        if (st) stat_inc(&st->parser_stuck);
        return TC_ACT_OK;
    }
    skb->cb[CB_SCAN_START] = data_offset - 3;

    bpf_tail_call(skb, jump_table, idx + 1); // Tail call next chunk
    return TC_ACT_OK;
}

static __always_inline int validate_and_scan(struct __sk_buff *skb, void *jump_table)
{
    __u32 z = 0;
    struct fixlat_stats *st = bpf_map_lookup_elem(&stats_map, &z);
    if (st) stat_inc(&st->hook_called);

    void *data_start = (void *)(long)skb->data;
    void *data_end   = (void *)(long)skb->data_end;

    // Debug: store skb->protocol (L3 protocol) for debugging
    if (st) st->mac_len_seen = bpf_ntohs(skb->protocol);

    __u16 proto = bpf_ntohs(skb->protocol);

    void *ptr = data_start;
    struct iphdr *ip = NULL;

    /*
     * Key idea:
     * - On loopback, TC often gives you L3 directly: skb->protocol == ETH_P_IP and ptr==IP header.
     * - On normal NICs, ptr usually starts with Ethernet header and skb->protocol is still set,
     *   but we can safely parse Ethernet+VLAN when proto is not ETH_P_IP.
     */
    if (proto == ETH_P_IP) {
        // Likely L3 at ptr already (loopback case)
        ip = (struct iphdr *)ptr;
    } else {
        // Assume Ethernet framing present
        struct ethhdr *eth = (struct ethhdr *)ptr;
        if ((void *)(eth + 1) > data_end) {
            if (st) stat_inc(&st->eth_truncated);
            return TC_ACT_OK;
        }

        if (st) stat_inc(&st->parsed_with_eth);

        proto = bpf_ntohs(eth->h_proto);
        ptr = (void *)(eth + 1);

        // Handle single VLAN tag (common). If you need QinQ, you can loop 2 times.
        if (proto == ETH_P_8021Q || proto == ETH_P_8021AD) {
            struct vlan_hdr *vh = (struct vlan_hdr *)ptr;
            if ((void *)(vh + 1) > data_end) {
                if (st) stat_inc(&st->eth_truncated);
                return TC_ACT_OK;
            }
            proto = bpf_ntohs(vh->h_vlan_encapsulated_proto);
            ptr = (void *)(vh + 1);
        }

        if (proto != ETH_P_IP) {
            if (st) stat_inc(&st->not_ipv4);
            return TC_ACT_OK;
        }

        ip = (struct iphdr *)ptr;
    }

    // Need at least minimal IPv4 header
    if ((void *)(ip + 1) > data_end) {
        if (st) stat_inc(&st->ip_truncated);
        return TC_ACT_OK;
    }

    // Optional sanity: make sure it's really IPv4
    if (ip->version != 4) {
        if (st) stat_inc(&st->not_ipv4);
        return TC_ACT_OK;
    }

    if (st) st->ip_proto_seen = ip->protocol;

    if (ip->protocol != IPPROTO_TCP) {
        if (st) stat_inc(&st->not_tcp);
        return TC_ACT_OK;
    }

    __u32 ihl = (__u32)ip->ihl * 4;
    if (ihl < sizeof(*ip)) {
        if (st) stat_inc(&st->ip_truncated);
        return TC_ACT_OK;
    }
    // Make sure full IP header is in bounds
    if ((void *)ip + ihl > data_end) {
        if (st) stat_inc(&st->ip_truncated);
        return TC_ACT_OK;
    }

    struct tcphdr *tcp = (struct tcphdr *)((__u8 *)ip + ihl);
    if ((void *)(tcp + 1) > data_end) {
        if (st) stat_inc(&st->tcp_truncated);
        return TC_ACT_OK;
    }

    __u32 doff = (__u32)tcp->doff * 4;
    if (doff < sizeof(*tcp)) {
        if (st) stat_inc(&st->tcp_truncated);
        return TC_ACT_OK;
    }
    if ((void *)tcp + doff > data_end) {
        if (st) stat_inc(&st->tcp_truncated);
        return TC_ACT_OK;
    }

    __u8 *payload = (__u8 *)tcp + doff;

    // Empty TCP payload (pure ACKs, keepalives, etc.)
    if ((void *)payload >= data_end) {
        if (st) stat_inc(&st->payload_zero);
        return TC_ACT_OK;
    }

    // FIX messages must be at least 32 bytes
    if ((void *)payload + 32 > data_end) {
        if (st) stat_inc(&st->payload_too_small);
        return TC_ACT_OK;
    }

    // Verify FIX protocol prefix safely (avoid unaligned u32 load)
    __u32 prefix = 0;
    __builtin_memcpy(&prefix, payload, sizeof(prefix));
    if (prefix != FIX_BEGIN_STRING_PREFIX) {
        if (st) stat_inc(&st->not_fix_protocol);
        return TC_ACT_OK;
    }

    // Port filtering
    struct config *cfg = bpf_map_lookup_elem(&cfg_map, &z);
    if (!cfg)
        return TC_ACT_OK;

    if (cfg->watch_port != 0) {
        __u16 sport = bpf_ntohs(tcp->source);
        __u16 dport = bpf_ntohs(tcp->dest);
        if (!(sport == cfg->watch_port || dport == cfg->watch_port)) {
            if (st) stat_inc(&st->wrong_port);
            return TC_ACT_OK;
        }
    }

    if (st) stat_inc(&st->total_packets);

    // Initialize scan state
    skb->cb[CB_MAGIC]      = CB_MAGIC_MARKER;
    skb->cb[CB_SCAN_START] = 0;

    bpf_tail_call(skb, jump_table, 1);
    return TC_ACT_OK;
}


// Entry point - validates TCP headers and initializes ingress scanning
SEC("tc")
int handle_ingress_headers(struct __sk_buff *skb)
{
    return validate_and_scan(skb, &ingress_jump_table);
}

// Entry point - validates TCP headers and initializes egress scanning
SEC("tc")
int handle_egress_headers(struct __sk_buff *skb)
{
    return validate_and_scan(skb, &egress_jump_table);
}

// Ingress payload scanning tail calls
SEC("tc") int handle_ingress_payload_1(struct __sk_buff *skb) { return handle_payload_chunk(skb, 1, &ingress_tag11_rb, &ingress_jump_table, true); }
SEC("tc") int handle_ingress_payload_2(struct __sk_buff *skb) { return handle_payload_chunk(skb, 2, &ingress_tag11_rb, &ingress_jump_table, true); }
SEC("tc") int handle_ingress_payload_3(struct __sk_buff *skb) { return handle_payload_chunk(skb, 3, &ingress_tag11_rb, &ingress_jump_table, true); }
SEC("tc") int handle_ingress_payload_4(struct __sk_buff *skb) { return handle_payload_chunk(skb, 4, &ingress_tag11_rb, &ingress_jump_table, true); }
SEC("tc") int handle_ingress_payload_5(struct __sk_buff *skb) { return handle_payload_chunk(skb, 5, &ingress_tag11_rb, &ingress_jump_table, true); }

// Egress payload scanning tail calls
SEC("tc") int handle_egress_payload_1(struct __sk_buff *skb) { return handle_payload_chunk(skb, 1, &egress_tag11_rb, &egress_jump_table, false); }
SEC("tc") int handle_egress_payload_2(struct __sk_buff *skb) { return handle_payload_chunk(skb, 2, &egress_tag11_rb, &egress_jump_table, false); }
SEC("tc") int handle_egress_payload_3(struct __sk_buff *skb) { return handle_payload_chunk(skb, 3, &egress_tag11_rb, &egress_jump_table, false); }
SEC("tc") int handle_egress_payload_4(struct __sk_buff *skb) { return handle_payload_chunk(skb, 4, &egress_tag11_rb, &egress_jump_table, false); }
SEC("tc") int handle_egress_payload_5(struct __sk_buff *skb) { return handle_payload_chunk(skb, 5, &egress_tag11_rb, &egress_jump_table, false); }


