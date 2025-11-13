#ifndef FIXLAT_SHARED_H
#define FIXLAT_SHARED_H

#ifndef __BPF__
#include <linux/types.h>
#endif

#define FIXLAT_MAX_TAGVAL_LEN 32

enum fixlat_dir {
    DIR_INBOUND = 0,
    DIR_OUTBOUND = 1,
};

struct pending_req {
    __u64 ts_ns;
    __u8  len;
    char  tag[FIXLAT_MAX_TAGVAL_LEN];
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
    __u64 ip_port_filtered;
    __u64 no_tag11;
};

struct config {
    __u32 watch_ipv4; // network byte order; 0 = any
    __u16 watch_port; // host order; 0 = any
};

#endif
