#ifndef FIXLAT_SHARED_H
#define FIXLAT_SHARED_H

#ifndef __BPF__
#include <linux/types.h>
#endif

#define FIXLAT_MAX_TAGVAL_LEN 24

#define FIXLAT_MAX_SCAN 700


struct pending_req {
    __u64 ts_ns;
    __u8  len;
    __u8  ord_id[FIXLAT_MAX_TAGVAL_LEN];
};

struct fixlat_stats {
    __u64 inbound_total;
    __u64 outbound_total;
    __u64 fifo_missed;
    __u64 unmatched_outbound;
    // Debug counters
    __u64 total_packets;
    __u64 non_eth_ip;
    __u64 non_tcp;
    __u64 no_tag11;
    __u64 empty_payload;
};

struct config {
    __u16 watch_port; // host order; 0 = any
    __u8  enabled;
    __u8  pad;
};

#endif
