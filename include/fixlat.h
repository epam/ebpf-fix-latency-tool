#ifndef FIXLAT_SHARED_H
#define FIXLAT_SHARED_H

#ifndef __BPF__
#include <linux/types.h>
#endif

#define FIXLAT_MAX_TAGVAL_LEN 24



struct tag11_with_timestamp {
    __u64 ts_ns;
    __u8  len;
    __u8  ord_id[FIXLAT_MAX_TAGVAL_LEN];
};

struct fixlat_stats {
    __u64 hook_called;     // TC hook invoked (very first thing)
    __u64 inbound_total;   // count number of tag 11 values parsed by ingresss hook
    __u64 outbound_total;  // count number of tag 11 values parsed by eresss hook
    __u64 matched_latency; // successfully matched and measured
    __u64 tag11_mismatch;  // outbound tag 11 not found in pending map
    // Error counters
    __u64 cb_clobbered;    // magic marker was overwritten
    __u64 tag11_too_long;  // tag 11 value exceeded FIXLAT_MAX_TAGVAL_LEN or packet boundary
    __u64 parser_stuck;    // tail call made insufficient forward progress
    // Filtering counters (packets dropped by validation)
    __u64 eth_truncated;
    __u64 ip_truncated;
    __u64 tcp_truncated;
    __u64 not_ipv4;
    __u64 not_tcp;
    __u64 payload_zero;
    __u64 payload_too_small;
    __u64 not_fix_protocol;
    __u64 wrong_port;
    // Debug counters
    __u64 total_packets;
    __u64 parsed_loopback;  // took loopback parsing path (no eth header)
    __u64 parsed_with_eth;  // took physical interface path (with eth header)
    __u64 ip_proto_seen;    // last ip->protocol value seen (for debugging)
    __u64 mac_len_seen;     // skb->mac_len for debugging
    __u64 first_8_bytes;    // first 8 bytes of packet data
    __u64 ihl_seen;         // IP header length
    __u64 doff_seen;        // TCP data offset
};

struct config {
    __u16 watch_port; // host order; 0 = any
};

#endif
