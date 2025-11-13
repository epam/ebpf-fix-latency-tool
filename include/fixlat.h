// include/fixlat.h
#ifndef FIXLAT_SHARED_H
#define FIXLAT_SHARED_H

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
    __u64 parse_errors;
    __u64 fifo_missed;
    __u64 unmatched_outbound;
};

struct config {
    __u16 watch_sport; // 0 = any
    __u16 watch_dport; // 0 = any
    __u8  enabled;     // 1 to enable
};

#endif
