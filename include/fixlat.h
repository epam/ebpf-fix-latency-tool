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
    __u64 unmatched_outbound;
    // Debug counters
    __u64 total_packets;
    __u64 non_eth_ip;
    __u64 non_tcp;
    __u64 empty_payload;
};

struct config {
    __u16 watch_port; // host order; 0 = any
};

#endif
