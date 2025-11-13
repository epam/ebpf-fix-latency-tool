#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <net/if.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "fixlat.skel.h"
#include "fixlat.h"

static volatile bool running = true;
static int report_every_sec = 5;

static void on_sig(int s){ (void)s; running=false; }
static uint64_t buckets[64];

static uint64_t percentile_from_buckets(double p) {
    uint64_t total = 0;
    for (int i=0;i<64;i++) total += buckets[i];
    if (total == 0) return 0;
    uint64_t rank = (uint64_t)((p/100.0)*(double)(total-1)) + 1;
    uint64_t acc = 0;
    for (int i=0;i<64;i++) {
        acc += buckets[i];
        if (acc >= rank) return (i==0) ? 1 : (1ULL<<i);  // Return 1ns for bucket 0
    }
    return (1ULL<<63);
}

static void snapshot_and_reset(int fd_hist, int fd_stats) {
    for (uint32_t i=0;i<64;i++) {
        uint64_t v=0;
        if (bpf_map_lookup_elem(fd_hist, &i, &v) == 0) {
            buckets[i]=v;
        } else {
            buckets[i]=0;
        }
    }
    for (uint32_t i=0;i<64;i++) {
        uint64_t zero=0; bpf_map_update_elem(fd_hist, &i, &zero, BPF_ANY);
    }
    uint32_t z=0; struct fixlat_stats st={0};
    bpf_map_lookup_elem(fd_stats, &z, &st); // Defaults to zeros if lookup fails
    
    // Reset statistics for next period
    struct fixlat_stats zero_stats={0};
    bpf_map_update_elem(fd_stats, &z, &zero_stats, BPF_ANY);

    uint64_t p50  = percentile_from_buckets(50.0);
    uint64_t p90  = percentile_from_buckets(90.0);
    uint64_t p99  = percentile_from_buckets(99.0);
    uint64_t p999 = percentile_from_buckets(99.9);

    uint64_t matched=0; for (int i=0;i<64;i++) matched += buckets[i];

    printf("[fixlat-kfifo] matched=%llu inbound=%llu outbound=%llu fifo_missed=%llu unmatched_out=%llu  p50=%lluns p90=%lluns p99=%lluns p99.9=%lluns\n",
        (unsigned long long)matched,
        (unsigned long long)st.inbound_total,
        (unsigned long long)st.outbound_total,
        (unsigned long long)st.fifo_missed,
        (unsigned long long)st.unmatched_outbound,
        (unsigned long long)p50,
        (unsigned long long)p90,
        (unsigned long long)p99,
        (unsigned long long)p999);
    printf("[DEBUG] total_pkts=%llu non_eth_ip=%llu non_tcp=%llu no_tag11=%llu empty_payload=%llu\n",
        (unsigned long long)st.total_packets,
        (unsigned long long)st.non_eth_ip,
        (unsigned long long)st.non_tcp,
        (unsigned long long)st.no_tag11,
        (unsigned long long)st.empty_payload);
    printf("[DEBUG] has_payload=%llu payload_bytes=%llu avg_payload=%llu\n",
        (unsigned long long)st.has_payload,
        (unsigned long long)st.payload_bytes,
        st.has_payload > 0 ? (unsigned long long)(st.payload_bytes / st.has_payload) : 0ULL);
    fflush(stdout);
}

static void usage(const char *p){
    fprintf(stderr,
        "Usage: %s -i <iface> [-p port] [-r seconds]\n"
        "  -p  TCP port to watch (0 = any)\n"
        "  -r  Report interval in seconds (default 5)\n", p);
}

int main(int argc, char **argv)
{
    const char *iface=NULL; uint16_t port=0; int opt;
    while ((opt=getopt(argc, argv, "i:p:r:")) != -1) {
        switch (opt) {
            case 'i': iface=optarg; break;
            case 'p': port=(uint16_t)atoi(optarg); break;
            case 'r': report_every_sec=atoi(optarg); break;
            default: usage(argv[0]); return 1;
        }
    }
    if (!iface){ usage(argv[0]); return 1; }

    struct rlimit rl={RLIM_INFINITY, RLIM_INFINITY}; setrlimit(RLIMIT_MEMLOCK, &rl);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    struct fixlat_bpf *skel = fixlat_bpf__open();
    if (!skel){ fprintf(stderr,"open skel failed\n"); return 1; }
    if (fixlat_bpf__load(skel)){ fprintf(stderr,"load skel failed\n"); return 1; }

    __u32 z=0;
    struct config cfg = {0};
    cfg.watch_port = port;
    if (bpf_map_update_elem(bpf_map__fd(skel->maps.cfg_map), &z, &cfg, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to update config map\n");
        return 1;
    }

    int ifindex = if_nametoindex(iface);
    if (!ifindex){ fprintf(stderr,"unknown iface %s\n", iface); return 1; }
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, ing, .ifindex=ifindex, .attach_point=BPF_TC_INGRESS);
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, egr, .ifindex=ifindex, .attach_point=BPF_TC_EGRESS);
    bpf_tc_hook_create(&ing); // May fail if already exists, ignore
    bpf_tc_hook_create(&egr);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, ing_o, .prog_fd=bpf_program__fd(skel->progs.tc_ingress));
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, egr_o, .prog_fd=bpf_program__fd(skel->progs.tc_egress));
    if (bpf_tc_attach(&ing, &ing_o)!=0){ fprintf(stderr,"attach ingress failed\n"); return 1; }
    if (bpf_tc_attach(&egr, &egr_o)!=0){ fprintf(stderr,"attach egress failed\n"); return 1; }

    signal(SIGINT, on_sig); signal(SIGTERM, on_sig);

    int fd_hist  = bpf_map__fd(skel->maps.hist_ns);
    int fd_stats = bpf_map__fd(skel->maps.stats_map);

    printf("fixlat-kfifo: attached to %s (port=%u), reporting every %ds\n",
           iface, port, report_every_sec);

    while (running) {
        sleep(report_every_sec);
        snapshot_and_reset(fd_hist, fd_stats);
    }

    bpf_tc_detach(&ing, &ing_o); bpf_tc_detach(&egr, &egr_o);
    bpf_tc_hook_destroy(&ing); bpf_tc_hook_destroy(&egr);
    fixlat_bpf__destroy(skel);
    return 0;
}
