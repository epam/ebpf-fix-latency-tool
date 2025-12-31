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
#include <time.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "fixlat.skel.h"
#include "fixlat.h"

static volatile bool running = true;
static int report_every_sec = 5;

// Pending inbound tag 11 map entry
struct pending_tag11 {
    char key[FIXLAT_MAX_TAGVAL_LEN + 1]; // tag 11 value as string key
    uint64_t timestamp_ns;
    struct pending_tag11 *next; // for hash table chaining
};

// Simple hash table for pending inbound tag 11s
#define PENDING_MAP_SIZE 65536
static struct pending_tag11 *pending_map[PENDING_MAP_SIZE];

// Userspace stats
static uint64_t matched_count = 0;
static uint64_t mismatch_count = 0;
static uint64_t ingress_events_received = 0;
static uint64_t egress_events_received = 0;

static void on_sig(int s){ (void)s; running=false; }
static uint64_t histogram[64];  // Latency histogram buckets (log2 scale)

// Forward declarations
static void pending_map_add(const uint8_t *ord_id, uint8_t len, uint64_t ts_ns);
static bool pending_map_remove(const uint8_t *ord_id, uint8_t len, uint64_t *out_ts_ns);
static void record_latency(uint64_t latency_ns);


static int handle_ingress_tag11(void *ctx, void *data, size_t len) {
    (void)ctx; (void)len;
    struct tag11_with_timestamp *req = data;
    ingress_events_received++;
    pending_map_add(req->ord_id, req->len, req->ts_ns);
    return 0;
}

static int handle_egress_tag11(void *ctx, void *data, size_t len) {
    (void)ctx; (void)len;
    struct tag11_with_timestamp *req = data;
    egress_events_received++;

    uint64_t inbound_ts_ns;
    if (pending_map_remove(req->ord_id, req->len, &inbound_ts_ns)) {
        uint64_t latency_ns = req->ts_ns - inbound_ts_ns;
        record_latency(latency_ns);
    } else {
        mismatch_count++;
    }
    return 0;
}


// Simple hash function for tag 11 strings
static uint32_t hash_tag11(const char *key, uint8_t len) {
    uint32_t hash = 5381;
    for (uint8_t i = 0; i < len; i++)
        hash = ((hash << 5) + hash) + key[i];
    return hash % PENDING_MAP_SIZE;
}

// Add inbound tag 11 to pending map
static void pending_map_add(const uint8_t *ord_id, uint8_t len, uint64_t ts_ns) {
    char key[FIXLAT_MAX_TAGVAL_LEN + 1] = {0};
    memcpy(key, ord_id, len);
    uint32_t hash = hash_tag11(key, len);

    struct pending_tag11 *entry = malloc(sizeof(*entry));
    if (!entry) return;

    memcpy(entry->key, key, sizeof(key));
    entry->timestamp_ns = ts_ns;

    entry->next = pending_map[hash];
    pending_map[hash] = entry;
}

// Lookup and remove outbound tag 11 from pending map
static bool pending_map_remove(const uint8_t *ord_id, uint8_t len, uint64_t *out_ts_ns) {
    char key[FIXLAT_MAX_TAGVAL_LEN + 1] = {0};
    memcpy(key, ord_id, len);
    uint32_t hash = hash_tag11(key, len);

    struct pending_tag11 **curr = &pending_map[hash];
    while (*curr) {
        if (memcmp((*curr)->key, key, len) == 0 && (*curr)->key[len] == '\0') {
            *out_ts_ns = (*curr)->timestamp_ns;
            struct pending_tag11 *to_free = *curr;
            *curr = (*curr)->next;
            free(to_free);
            return true;
        }
        curr = &(*curr)->next;
    }
    return false;
}

// Record latency into log2 histogram bucket
static void record_latency(uint64_t latency_ns) {
    if (latency_ns == 0) return;

    // Calculate log2 bucket
    uint32_t bucket = 0;
    uint64_t val = latency_ns;
    while (val > 1 && bucket < 63) {
        val >>= 1;
        bucket++;
    }

    // Increment histogram bucket
    histogram[bucket]++;
    matched_count++;
}

static uint64_t percentile_from_buckets(double p) {
    uint64_t total = 0;
    for (int i=0;i<64;i++) total += histogram[i];
    if (total == 0) return 0;
    uint64_t rank = (uint64_t)((p/100.0)*(double)(total-1)) + 1;
    uint64_t acc = 0;
    for (int i=0;i<64;i++) {
        acc += histogram[i];
        if (acc >= rank) return (i==0) ? 1 : (1ULL<<i);  // Return 1ns for bucket 0
    }
    return (1ULL<<63);
}

static void snapshot(int fd_stats) {
    // Histogram is already in userspace (histogram[] array), no need to snapshot it

    // Read per-CPU stats and aggregate
    uint32_t z=0;
    int nr_cpus = libbpf_num_possible_cpus();
    struct fixlat_stats percpu_stats[nr_cpus];
    struct fixlat_stats st={0};

    if (bpf_map_lookup_elem(fd_stats, &z, percpu_stats) == 0) {
        // Aggregate stats from all CPUs
        for (int i = 0; i < nr_cpus; i++) {
            st.inbound_total += percpu_stats[i].inbound_total;
            st.outbound_total += percpu_stats[i].outbound_total;
            st.ingress_hook_called += percpu_stats[i].ingress_hook_called;
            st.egress_hook_called += percpu_stats[i].egress_hook_called;
            st.ingress_scan_started += percpu_stats[i].ingress_scan_started;
            st.egress_scan_started += percpu_stats[i].egress_scan_started;
            st.payload_zero += percpu_stats[i].payload_zero;
            st.payload_too_small += percpu_stats[i].payload_too_small;
            st.not_fix_protocol += percpu_stats[i].not_fix_protocol;
            st.wrong_port += percpu_stats[i].wrong_port;
            st.cb_clobbered += percpu_stats[i].cb_clobbered;
            st.tag11_too_long += percpu_stats[i].tag11_too_long;
            st.parser_stuck += percpu_stats[i].parser_stuck;
        }
    }

    uint64_t p50  = percentile_from_buckets(50.0);
    uint64_t p90  = percentile_from_buckets(90.0);
    uint64_t p99  = percentile_from_buckets(99.0);
    uint64_t p999 = percentile_from_buckets(99.9);

    // Main stats line
    printf("[fixlat] matched=%llu inbound=%llu outbound=%llu mismatch=%llu | p50=%lluns p90=%lluns p99=%lluns p99.9=%lluns\n",
        (unsigned long long)matched_count,
        (unsigned long long)st.inbound_total,
        (unsigned long long)st.outbound_total,
        (unsigned long long)mismatch_count,
        (unsigned long long)p50,
        (unsigned long long)p90,
        (unsigned long long)p99,
        (unsigned long long)p999);

    // Traffic stats
    printf("[traffic] hooks: ingress=%llu egress=%llu | scanned: ingress=%llu egress=%llu\n",
        (unsigned long long)st.ingress_hook_called,
        (unsigned long long)st.egress_hook_called,
        (unsigned long long)st.ingress_scan_started,
        (unsigned long long)st.egress_scan_started);

    // Filters (only show if non-zero)
    if (st.payload_zero || st.payload_too_small || st.not_fix_protocol || st.wrong_port) {
        printf("[filters] payload_zero=%llu payload_small=%llu not_fix=%llu wrong_port=%llu\n",
            (unsigned long long)st.payload_zero,
            (unsigned long long)st.payload_too_small,
            (unsigned long long)st.not_fix_protocol,
            (unsigned long long)st.wrong_port);
    }

    // Errors (only show if non-zero)
    if (st.cb_clobbered || st.tag11_too_long || st.parser_stuck) {
        printf("[ERRORS] cb_clobbered=%llu tag11_too_long=%llu parser_stuck=%llu\n",
            (unsigned long long)st.cb_clobbered,
            (unsigned long long)st.tag11_too_long,
            (unsigned long long)st.parser_stuck);
    }
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

    // Populate ingress jump table with tail call programs (indices 1-5 for payload scanning)
    int ingress_jump_table_fd = bpf_map__fd(skel->maps.ingress_jump_table);
    __u32 idx;
    int prog_fd;

    idx = 1; prog_fd = bpf_program__fd(skel->progs.handle_ingress_payload_1);
    bpf_map_update_elem(ingress_jump_table_fd, &idx, &prog_fd, BPF_ANY);

    idx = 2; prog_fd = bpf_program__fd(skel->progs.handle_ingress_payload_2);
    bpf_map_update_elem(ingress_jump_table_fd, &idx, &prog_fd, BPF_ANY);

    idx = 3; prog_fd = bpf_program__fd(skel->progs.handle_ingress_payload_3);
    bpf_map_update_elem(ingress_jump_table_fd, &idx, &prog_fd, BPF_ANY);

    idx = 4; prog_fd = bpf_program__fd(skel->progs.handle_ingress_payload_4);
    bpf_map_update_elem(ingress_jump_table_fd, &idx, &prog_fd, BPF_ANY);

    idx = 5; prog_fd = bpf_program__fd(skel->progs.handle_ingress_payload_5);
    bpf_map_update_elem(ingress_jump_table_fd, &idx, &prog_fd, BPF_ANY);

    // Populate egress jump table with tail call programs (indices 1-5 for payload scanning)
    int egress_jump_table_fd = bpf_map__fd(skel->maps.egress_jump_table);

    idx = 1; prog_fd = bpf_program__fd(skel->progs.handle_egress_payload_1);
    bpf_map_update_elem(egress_jump_table_fd, &idx, &prog_fd, BPF_ANY);

    idx = 2; prog_fd = bpf_program__fd(skel->progs.handle_egress_payload_2);
    bpf_map_update_elem(egress_jump_table_fd, &idx, &prog_fd, BPF_ANY);

    idx = 3; prog_fd = bpf_program__fd(skel->progs.handle_egress_payload_3);
    bpf_map_update_elem(egress_jump_table_fd, &idx, &prog_fd, BPF_ANY);

    idx = 4; prog_fd = bpf_program__fd(skel->progs.handle_egress_payload_4);
    bpf_map_update_elem(egress_jump_table_fd, &idx, &prog_fd, BPF_ANY);

    idx = 5; prog_fd = bpf_program__fd(skel->progs.handle_egress_payload_5);
    bpf_map_update_elem(egress_jump_table_fd, &idx, &prog_fd, BPF_ANY);

    int ifindex = if_nametoindex(iface);
    if (!ifindex){ fprintf(stderr,"unknown iface %s\n", iface); return 1; }

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, ing, .ifindex=ifindex, .attach_point=BPF_TC_INGRESS);
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, egr, .ifindex=ifindex, .attach_point=BPF_TC_EGRESS);
    bpf_tc_hook_create(&ing); // May fail if already exists, ignore
    bpf_tc_hook_create(&egr);

    DECLARE_LIBBPF_OPTS(bpf_tc_opts, ing_o, .prog_fd=bpf_program__fd(skel->progs.handle_ingress_headers));
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, egr_o, .prog_fd=bpf_program__fd(skel->progs.handle_egress_headers));

    if (bpf_tc_attach(&ing, &ing_o)!=0){ fprintf(stderr,"attach ingress failed\n"); return 1; }
    if (bpf_tc_attach(&egr, &egr_o)!=0){ fprintf(stderr,"attach egress failed\n"); return 1; }

    signal(SIGINT, on_sig); signal(SIGTERM, on_sig);

    int fd_stats = bpf_map__fd(skel->maps.stats_map);

    // Set up ring buffer consumers
    struct ring_buffer *ingress_rb = ring_buffer__new(bpf_map__fd(skel->maps.ingress_tag11_rb),
                                                        handle_ingress_tag11, NULL, NULL);
    if (!ingress_rb) {
        fprintf(stderr, "Failed to create ingress ring buffer\n");
        return 1;
    }

    struct ring_buffer *egress_rb = ring_buffer__new(bpf_map__fd(skel->maps.egress_tag11_rb),
                                                       handle_egress_tag11, NULL, NULL);
    if (!egress_rb) {
        fprintf(stderr, "Failed to create egress ring buffer\n");
        return 1;
    }

    printf("fixlat-kfifo: attached to %s (port=%u), reporting every %ds\n",
           iface, port, report_every_sec);

    // Single-threaded main loop: busy-wait poll ringbuffers + periodic stats
    struct timespec last_report_time;
    clock_gettime(CLOCK_MONOTONIC, &last_report_time);

    while (running) {
        // Non-blocking poll of both ringbuffers (timeout=0 for immediate processing)
        ring_buffer__poll(ingress_rb, 0);
        ring_buffer__poll(egress_rb, 0);

        // Check if it's time to print stats
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        int64_t elapsed_sec = now.tv_sec - last_report_time.tv_sec;

        if (elapsed_sec >= report_every_sec) {
            snapshot(fd_stats);
            last_report_time = now;
        }
    }

    // Clean up ring buffers
    ring_buffer__free(ingress_rb);
    ring_buffer__free(egress_rb);

    bpf_tc_detach(&ing, &ing_o);
    bpf_tc_detach(&egr, &egr_o);
    bpf_tc_hook_destroy(&ing);
    bpf_tc_hook_destroy(&egr);
    fixlat_bpf__destroy(skel);
    return 0;
}
