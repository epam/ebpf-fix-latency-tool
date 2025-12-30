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
    __u64 inbound_total; // count number of tag 11 parsed
    __u64 outbound_total;
    __u64 matched_latency; // successfully matched and measured
    __u64 tag11_mismatch; // outbound tag 11 not found in pending map
    // Error counters
    __u64 cb_clobbered; // magic marker was overwritten
    __u64 tag11_too_long; // tag 11 value exceeded FIXLAT_MAX_TAGVAL_LEN or packet boundary
    __u64 parser_stuck; // tail call made insufficient forward progress
    // Debug counters
    __u64 total_packets;
};

struct config {
    __u16 watch_port; // host order; 0 = any
};

#endif
