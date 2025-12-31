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
#include <termios.h>
#include <fcntl.h>
#include <poll.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "fixlat.skel.h"
#include "fixlat.h"

static volatile bool running = true;
static int report_every_sec = 5;

#define VERSION "0.0.1"

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

// Pending map tracking and eviction
static uint64_t pending_count = 0;
static uint64_t max_pending = 65536;
static uint64_t timeout_ns = 500000000ULL;  // 500ms default
static uint64_t stale_evicted = 0;
static uint64_t forced_evicted = 0;

static void on_sig(int s){ (void)s; running=false; }

static struct termios orig_termios;
static bool termios_saved = false;

// Forward declarations
static void dump_cumulative_histogram(void);
static void reset_cumulative_histogram(void);
static void show_keyboard_help(void);
static void cleanup_stale_entries(struct timespec *now);
static bool evict_oldest_entry(void);

// Set terminal to raw mode for non-blocking keyboard input
static void enable_raw_mode(void) {
    if (tcgetattr(STDIN_FILENO, &orig_termios) == -1) return;
    termios_saved = true;

    struct termios raw = orig_termios;
    raw.c_lflag &= ~(ECHO | ICANON);  // Disable echo and canonical mode
    raw.c_cc[VMIN] = 0;  // Non-blocking
    raw.c_cc[VTIME] = 0;

    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
}

// Restore original terminal settings
static void disable_raw_mode(void) {
    if (termios_saved)
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
}

// Handle keyboard input
static void handle_keyboard(void) {
    char c;
    if (read(STDIN_FILENO, &c, 1) == 1) {
        if (c == ' ') {
            dump_cumulative_histogram();
        } else if (c == 'r' || c == 'R') {
            reset_cumulative_histogram();
        } else if (c == 27) {  // ESC
            running = false;
        } else {
            // Any other key shows help
            show_keyboard_help();
        }
    }
}

// HDR histogram: linear buckets for fine-grained measurement
// Bucket width: 100ns, covering 0-10ms with 100,000 buckets
#define BUCKET_WIDTH_NS 100
#define MAX_LATENCY_NS 10000000  // 10ms
#define NUM_BUCKETS (MAX_LATENCY_NS / BUCKET_WIDTH_NS)

// Dual histograms: interval (reset each report) and cumulative (long-term)
static uint64_t interval_histogram[NUM_BUCKETS];
static uint64_t cumulative_histogram[NUM_BUCKETS];
static uint64_t interval_sum_ns = 0;  // For AVG calculation
static uint64_t cumulative_sum_ns = 0;

// Forward declarations for pending map functions
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
    // If at limit, try to make room by evicting stale entries
    if (pending_count >= max_pending) {
        uint64_t cutoff_ns = ts_ns - timeout_ns;
        uint64_t evicted = 0;

        // Quick scan for stale entries
        for (uint32_t i = 0; i < PENDING_MAP_SIZE; i++) {
            struct pending_tag11 **curr = &pending_map[i];
            while (*curr) {
                if ((*curr)->timestamp_ns < cutoff_ns) {
                    struct pending_tag11 *to_free = *curr;
                    *curr = (*curr)->next;
                    free(to_free);
                    pending_count--;
                    evicted++;
                } else {
                    curr = &(*curr)->next;
                }
            }
        }

        if (evicted > 0) {
            stale_evicted += evicted;
        }

        // If STILL at limit after cleanup, evict oldest
        if (pending_count >= max_pending) {
            evict_oldest_entry();
        }
    }

    char key[FIXLAT_MAX_TAGVAL_LEN + 1] = {0};
    memcpy(key, ord_id, len);
    uint32_t hash = hash_tag11(key, len);

    struct pending_tag11 *entry = malloc(sizeof(*entry));
    if (!entry) return;

    memcpy(entry->key, key, sizeof(key));
    entry->timestamp_ns = ts_ns;

    entry->next = pending_map[hash];
    pending_map[hash] = entry;
    pending_count++;
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
            pending_count--;
            return true;
        }
        curr = &(*curr)->next;
    }
    return false;
}

// Evict stale entries (older than timeout) across entire hash table
// Called during idle time every 500ms
static void cleanup_stale_entries(struct timespec *now) {
    uint64_t now_ns = now->tv_sec * 1000000000ULL + now->tv_nsec;
    uint64_t cutoff_ns = now_ns - timeout_ns;
    uint64_t evicted = 0;

    for (uint32_t i = 0; i < PENDING_MAP_SIZE; i++) {
        struct pending_tag11 **curr = &pending_map[i];
        while (*curr) {
            if ((*curr)->timestamp_ns < cutoff_ns) {
                struct pending_tag11 *to_free = *curr;
                *curr = (*curr)->next;
                free(to_free);
                pending_count--;
                evicted++;
            } else {
                curr = &(*curr)->next;
            }
        }
    }

    if (evicted > 0) {
        stale_evicted += evicted;
    }
}

// Find and evict the single oldest entry in the entire table
// Used as last resort when at limit and no stale entries found
static bool evict_oldest_entry(void) {
    uint64_t oldest_ts = UINT64_MAX;
    uint32_t oldest_bucket = 0;
    struct pending_tag11 *oldest_entry = NULL;

    // Scan to find oldest
    for (uint32_t i = 0; i < PENDING_MAP_SIZE; i++) {
        struct pending_tag11 *curr = pending_map[i];
        while (curr) {
            if (curr->timestamp_ns < oldest_ts) {
                oldest_ts = curr->timestamp_ns;
                oldest_bucket = i;
                oldest_entry = curr;
            }
            curr = curr->next;
        }
    }

    if (!oldest_entry) return false;

    // Remove oldest entry
    struct pending_tag11 **curr = &pending_map[oldest_bucket];
    while (*curr) {
        if (*curr == oldest_entry) {
            *curr = oldest_entry->next;
            free(oldest_entry);
            pending_count--;
            forced_evicted++;
            return true;
        }
        curr = &(*curr)->next;
    }

    return false;
}

// Record latency into both interval and cumulative histograms
static void record_latency(uint64_t latency_ns) {
    if (latency_ns == 0) return;

    // Calculate bucket index (100ns resolution)
    uint64_t bucket = latency_ns / BUCKET_WIDTH_NS;

    // Cap at max bucket
    if (bucket >= NUM_BUCKETS)
        bucket = NUM_BUCKETS - 1;

    // Update both histograms
    interval_histogram[bucket]++;
    cumulative_histogram[bucket]++;

    // Update sums for AVG calculation
    interval_sum_ns += latency_ns;
    cumulative_sum_ns += latency_ns;

    matched_count++;
}

static uint64_t percentile_from_buckets(const uint64_t *hist, double p) {
    uint64_t total = 0;
    for (uint64_t i = 0; i < NUM_BUCKETS; i++)
        total += hist[i];

    if (total == 0) return 0;

    // Special cases for MIN (p=0.0) and MAX (p=100.0)
    if (p <= 0.0) {
        // Find first non-empty bucket
        for (uint64_t i = 0; i < NUM_BUCKETS; i++) {
            if (hist[i] > 0)
                return (i * BUCKET_WIDTH_NS) + (BUCKET_WIDTH_NS / 2);
        }
        return 0;
    }

    if (p >= 100.0) {
        // Find last non-empty bucket
        for (uint64_t i = NUM_BUCKETS; i > 0; i--) {
            if (hist[i - 1] > 0)
                return ((i - 1) * BUCKET_WIDTH_NS) + (BUCKET_WIDTH_NS / 2);
        }
        return 0;
    }

    // Normal percentile calculation
    uint64_t rank = (uint64_t)((p / 100.0) * (double)(total - 1)) + 1;
    uint64_t acc = 0;

    for (uint64_t i = 0; i < NUM_BUCKETS; i++) {
        acc += hist[i];
        if (acc >= rank) {
            // Return the midpoint of the bucket in nanoseconds
            return (i * BUCKET_WIDTH_NS) + (BUCKET_WIDTH_NS / 2);
        }
    }

    return MAX_LATENCY_NS;
}

// Format and print a latency value
static void print_latency(uint64_t ns) {
    if (ns >= 1000)
        printf("%.3fus", ns / 1000.0);
    else
        printf("%lluns", (unsigned long long)ns);
}

// Dump detailed cumulative histogram
static void dump_cumulative_histogram(void) {
    uint64_t total = 0;
    for (uint64_t i = 0; i < NUM_BUCKETS; i++)
        total += cumulative_histogram[i];

    if (total == 0) {
        printf("\n[cumulative] No latency samples recorded yet\n\n");
        return;
    }

    uint64_t avg = cumulative_sum_ns / total;

    printf("\n========== CUMULATIVE HISTOGRAM (all-time, n=%llu) ==========\n", (unsigned long long)total);
    printf("MIN:      "); print_latency(percentile_from_buckets(cumulative_histogram, 0.0)); printf("\n");
    printf("AVG:      "); print_latency(avg); printf("\n");
    printf("P50:      "); print_latency(percentile_from_buckets(cumulative_histogram, 50.0)); printf("\n");
    printf("P90:      "); print_latency(percentile_from_buckets(cumulative_histogram, 90.0)); printf("\n");
    printf("P99:      "); print_latency(percentile_from_buckets(cumulative_histogram, 99.0)); printf("\n");
    printf("P99.9:    "); print_latency(percentile_from_buckets(cumulative_histogram, 99.9)); printf("\n");
    printf("P99.99:   "); print_latency(percentile_from_buckets(cumulative_histogram, 99.99)); printf("\n");
    printf("P99.999:  "); print_latency(percentile_from_buckets(cumulative_histogram, 99.999)); printf("\n");
    printf("MAX:      "); print_latency(percentile_from_buckets(cumulative_histogram, 100.0)); printf("\n");
    printf("==============================================================\n\n");
    fflush(stdout);
}

// Reset cumulative histogram
static void reset_cumulative_histogram(void) {
    memset(cumulative_histogram, 0, sizeof(cumulative_histogram));
    cumulative_sum_ns = 0;
    printf("\n[reset] Cumulative histogram cleared\n\n");
    fflush(stdout);
}

// Show keyboard help
static void show_keyboard_help(void) {
    printf("\n========== KEYBOARD COMMANDS ==========\n");
    printf("SPACE   - Dump detailed cumulative histogram\n");
    printf("r       - Reset cumulative histogram\n");
    printf("ESC     - Exit program\n");
    printf("?       - Show this help\n");
    printf("=======================================\n\n");
    fflush(stdout);
}

static void snapshot(int fd_stats, double elapsed_sec) {
    // Calculate interval stats (simple: MIN, AVG, MAX)
    uint64_t interval_count = matched_count;
    uint64_t interval_min = 0, interval_avg = 0, interval_max = 0;
    double rate = (elapsed_sec > 0) ? (interval_count / elapsed_sec) : 0.0;

    if (interval_count > 0) {
        interval_min = percentile_from_buckets(interval_histogram, 0.0);
        interval_avg = interval_sum_ns / interval_count;
        interval_max = percentile_from_buckets(interval_histogram, 100.0);
    }

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
            st.wrong_port += percpu_stats[i].wrong_port;
            st.cb_clobbered += percpu_stats[i].cb_clobbered;
            st.tag11_too_long += percpu_stats[i].tag11_too_long;
            st.parser_stuck += percpu_stats[i].parser_stuck;
        }
    }

    // Main stats line with interval latency (simple: MIN/AVG/MAX)
    printf("[fixlat] matched=%llu inbound=%llu outbound=%llu mismatch=%llu | rate: %.0f match/sec | latency: min=",
        (unsigned long long)interval_count,
        (unsigned long long)st.inbound_total,
        (unsigned long long)st.outbound_total,
        (unsigned long long)mismatch_count,
        rate);

    if (interval_count > 0) {
        print_latency(interval_min);
        printf(" avg=");
        print_latency(interval_avg);
        printf(" max=");
        print_latency(interval_max);
    } else {
        printf("- avg=- max=-");
    }
    printf("\n");

    // Traffic stats with filters on same line
    printf("[traffic] hooks: ingress=%llu egress=%llu | scanned: ingress=%llu egress=%llu",
        (unsigned long long)st.ingress_hook_called,
        (unsigned long long)st.egress_hook_called,
        (unsigned long long)st.ingress_scan_started,
        (unsigned long long)st.egress_scan_started);

    // Append filters if any non-zero
    if (st.payload_zero || st.payload_too_small || st.wrong_port) {
        printf(" | filters: payload_zero=%llu payload_small=%llu wrong_port=%llu",
            (unsigned long long)st.payload_zero,
            (unsigned long long)st.payload_too_small,
            (unsigned long long)st.wrong_port);
    }
    printf("\n");

    // Errors (only show if non-zero)
    if (st.cb_clobbered || st.tag11_too_long || st.parser_stuck) {
        printf("[ERRORS] cb_clobbered=%llu tag11_too_long=%llu parser_stuck=%llu\n",
            (unsigned long long)st.cb_clobbered,
            (unsigned long long)st.tag11_too_long,
            (unsigned long long)st.parser_stuck);
    }

    // Pending map health (show if evictions occurred or approaching limit)
    if (stale_evicted || forced_evicted || pending_count > max_pending / 2) {
        printf("[pending] active=%llu/%llu stale_evicted=%llu forced=%llu\n",
            (unsigned long long)pending_count,
            (unsigned long long)max_pending,
            (unsigned long long)stale_evicted,
            (unsigned long long)forced_evicted);
    }

    fflush(stdout);

    // Reset interval histogram for next period
    memset(interval_histogram, 0, sizeof(interval_histogram));
    interval_sum_ns = 0;
    matched_count = 0;
    mismatch_count = 0;
}

static void usage(const char *p){
    fprintf(stderr,
        "fixlat v%s - eBPF FIX Protocol Latency Monitor\n\n"
        "Usage: %s -i <iface> [-p port] [-r seconds] [-m max] [-t timeout]\n"
        "  -i  Network interface to monitor (required)\n"
        "  -p  TCP port to watch (0 = any, default: 0)\n"
        "  -r  Report interval in seconds (default: 5)\n"
        "  -m  Maximum concurrent pending requests (default: 65536)\n"
        "  -t  Request timeout in seconds (default: 0.5)\n"
        "  -v  Show version and exit\n", VERSION, p);
}

int main(int argc, char **argv)
{
    const char *iface=NULL; uint16_t port=0; int opt;
    while ((opt=getopt(argc, argv, "i:p:r:m:t:v")) != -1) {
        switch (opt) {
            case 'i': iface=optarg; break;
            case 'p': port=(uint16_t)atoi(optarg); break;
            case 'r': report_every_sec=atoi(optarg); break;
            case 'm': max_pending=(uint64_t)atoll(optarg); break;
            case 't': timeout_ns=(uint64_t)(atof(optarg) * 1e9); break;
            case 'v': printf("fixlat v%s\n", VERSION); return 0;
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

    printf("fixlat v%s: attached to %s (port=%u), reporting every %ds\n",
           VERSION, iface, port, report_every_sec);
    printf("Interval stats: MIN/AVG/MAX | Press '?' for keyboard commands\n");

    // Enable raw mode for keyboard input
    enable_raw_mode();
    atexit(disable_raw_mode);

    // Single-threaded main loop: busy-wait poll ringbuffers + periodic stats + keyboard
    struct timespec last_report_time;
    struct timespec last_cleanup_time;
    clock_gettime(CLOCK_MONOTONIC, &last_report_time);
    last_cleanup_time = last_report_time;

    int cleanup_interval_ms = 500;  // Run cleanup every 500ms

    while (running) {
        // Non-blocking poll of both ringbuffers (timeout=0 for immediate processing)
        ring_buffer__poll(ingress_rb, 0);
        ring_buffer__poll(egress_rb, 0);

        // Handle keyboard input
        handle_keyboard();

        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);

        // Periodic cleanup of stale entries (separate from stats reporting)
        int64_t cleanup_elapsed_ms = (now.tv_sec - last_cleanup_time.tv_sec) * 1000 +
                                      (now.tv_nsec - last_cleanup_time.tv_nsec) / 1000000;

        if (cleanup_elapsed_ms >= cleanup_interval_ms) {
            cleanup_stale_entries(&now);
            last_cleanup_time = now;
        }

        // Check if it's time to print stats
        int64_t elapsed_sec = now.tv_sec - last_report_time.tv_sec;

        if (elapsed_sec >= report_every_sec) {
            double precise_elapsed = (now.tv_sec - last_report_time.tv_sec) +
                                     (now.tv_nsec - last_report_time.tv_nsec) / 1e9;
            snapshot(fd_stats, precise_elapsed);
            last_report_time = now;
        }
    }

    // Clean up
    disable_raw_mode();
    ring_buffer__free(ingress_rb);
    ring_buffer__free(egress_rb);

    bpf_tc_detach(&ing, &ing_o);
    bpf_tc_detach(&egr, &egr_o);
    bpf_tc_hook_destroy(&ing);
    bpf_tc_hook_destroy(&egr);
    fixlat_bpf__destroy(skel);
    return 0;
}
