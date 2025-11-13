// user/fixlat.c
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
    __uint128_t total = 0;
    for (int i=0;i<64;i++) total += buckets[i];
    if (total == 0) return 0;
    __uint128_t rank = (__uint128_t)((p/100.0)*(double)(total-1)) + 1;
    __uint128_t acc = 0;
    for (int i=0;i<64;i++) {
        acc += buckets[i];
        if (acc >= rank) return (i==0) ? 0 : (1ULL<<i);
    }
    return (1ULL<<63);
}

static void snapshot_and_reset(int fd_hist, int fd_stats) {
    for (uint32_t i=0;i<64;i++) {
        uint64_t v=0; bpf_map_lookup_elem(fd_hist, &i, &v); buckets[i]=v;
    }
    for (uint32_t i=0;i<64;i++) {
        uint64_t zero=0; bpf_map_update_elem(fd_hist, &i, &zero, BPF_ANY);
    }
    uint32_t z=0; struct fixlat_stats st={0};
    bpf_map_lookup_elem(fd_stats, &z, &st);

    uint64_t p50  = percentile_from_buckets(50.0);
    uint64_t p90  = percentile_from_buckets(90.0);
    uint64_t p99  = percentile_from_buckets(99.0);
    uint64_t p999 = percentile_from_buckets(99.9);

    __uint128_t matched=0; for (int i=0;i<64;i++) matched += buckets[i];

    printf("[fixlat-kfifo] matched=%llu inbound=%llu outbound=%llu fifo_missed=%llu unmatched_out=%llu  p50=%lluus p90=%lluus p99=%lluus p99.9=%lluus
",
        (unsigned long long)matched,
        (unsigned long long)st.inbound_total,
        (unsigned long long)st.outbound_total,
        (unsigned long long)st.fifo_missed,
        (unsigned long long)st.unmatched_outbound,
        (unsigned long long)p50,
        (unsigned long long)p90,
        (unsigned long long)p99,
        (unsigned long long)p999);
    fflush(stdout);
}

static void usage(const char *p){
    fprintf(stderr,"Usage: %s -i <iface> [-s sport] [-d dport] [-r seconds]\n", p);
}

int main(int argc, char **argv)
{
    const char *iface=NULL; uint16_t sport=0,dport=0; int opt;
    while ((opt=getopt(argc, argv, "i:s:d:r:")) != -1) {
        switch (opt) {
            case 'i': iface=optarg; break;
            case 's': sport=(uint16_t)atoi(optarg); break;
            case 'd': dport=(uint16_t)atoi(optarg); break;
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

    __u32 z=0; struct config cfg={ .watch_sport=sport, .watch_dport=dport, .enabled=1 };
    bpf_map_update_elem(bpf_map__fd(skel->maps.cfg_map), &z, &cfg, BPF_ANY);

    int ifindex = if_nametoindex(iface);
    if (!ifindex){ fprintf(stderr,"unknown iface %s\n", iface); return 1; }
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, ing, .ifindex=ifindex, .attach_point=BPF_TC_INGRESS);
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, egr, .ifindex=ifindex, .attach_point=BPF_TC_EGRESS);
    bpf_tc_hook_create(&ing); bpf_tc_hook_create(&egr);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, ing_o, .prog_fd=bpf_program__fd(skel->progs.tc_ingress));
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, egr_o, .prog_fd=bpf_program__fd(skel->progs.tc_egress));
    if (bpf_tc_attach(&ing, &ing_o)!=0){ fprintf(stderr,"attach ingress failed\n"); return 1; }
    if (bpf_tc_attach(&egr, &egr_o)!=0){ fprintf(stderr,"attach egress failed\n"); return 1; }

    signal(SIGINT, on_sig); signal(SIGTERM, on_sig);

    int fd_hist  = bpf_map__fd(skel->maps.hist_us);
    int fd_stats = bpf_map__fd(skel->maps.stats_map);

    printf("fixlat-kfifo: attached to %s (sport=%u, dport=%u), reporting every %ds\n", iface, sport, dport, report_every_sec);

    while (running) {
        sleep(report_every_sec);
        snapshot_and_reset(fd_hist, fd_stats);
    }

    bpf_tc_detach(&ing, &ing_o); bpf_tc_detach(&egr, &egr_o);
    bpf_tc_hook_destroy(&ing); bpf_tc_hook_destroy(&egr);
    fixlat_bpf__destroy(skel);
    return 0;
}
