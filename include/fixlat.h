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
    // Core counters
    __u64 inbound_total;        // tag 11 values extracted from ingress
    __u64 outbound_total;       // tag 11 values extracted from egress

    // Traffic counters
    __u64 ingress_hook_called;  // ingress TC hook invocations
    __u64 egress_hook_called;   // egress TC hook invocations
    __u64 ingress_scan_started; // ingress packets that started tag11 scanning
    __u64 egress_scan_started;  // egress packets that started tag11 scanning

    // Filter counters (why packets were dropped)
    __u64 payload_zero;         // packets with no TCP payload
    __u64 payload_too_small;    // TCP payload < 32 bytes

    // Fragmentation counters
    __u64 ingress_fragmented;   // ingress packets that were non-linear (fragmented)
    __u64 egress_fragmented;    // egress packets that were non-linear (fragmented)

    // Error counters
    __u64 cb_clobbered;         // skb->cb magic marker was corrupted
    __u64 tag11_too_long;       // tag 11 value exceeded max length
    __u64 parser_stuck;         // tail call made no progress
    __u64 payload_defrag_fail;  // payload defragmentation failed
};

struct config {
    __u16 watch_port_min; // host order; 1-65535
    __u16 watch_port_max; // host order; 1-65535
};

#endif
