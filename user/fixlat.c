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
#include <sched.h>

#ifdef __x86_64__
#include <immintrin.h>
#endif

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "fixlat.skel.h"
#include "fixlat.h"

static volatile bool running = true;
static int report_every_sec = 5;

// VERSION is now passed by compiler via -DVERSION flag from Makefile

// Time conversion constants
#define NANOS_IN_SECOND 1000000000ULL
#define NANOS_IN_MS     1000000ULL
#define NANOS_IN_US     1000ULL

// Pending inbound tag 11 map entry
struct pending_tag11 {
    char ord_id[FIXLAT_MAX_TAGVAL_LEN]; // tag 11 value as string key
    uint8_t ord_id_len;                 // actual length of tag 11 value
    uint64_t timestamp_ns;
    uint32_t hash; // precomputed bucket index

    struct pending_tag11 *next; // hash table chaining

    // Global age-ordered list (oldest=head). Used for O(1) eviction.
    struct pending_tag11 *age_prev;
    struct pending_tag11 *age_next;
};

// Simple hash table for pending inbound tag 11s
// Size is dynamically calculated based on max_pending with 0.5 load factor
static uint32_t pending_map_size = 0;
static struct pending_tag11 **pending_map = NULL;

// Age-ordered list of pending entries for O(1) eviction/cleanup
static struct pending_tag11 *pending_age_head = NULL; // oldest
static struct pending_tag11 *pending_age_tail = NULL; // newest

// Userspace stats
static uint64_t matched_count = 0;
static uint64_t mismatch_count = 0;
static uint64_t negative_latency_count = 0;
static uint64_t duplicate_ingress_ids = 0;
static uint64_t ingress_events_received = 0;
static uint64_t egress_events_received = 0;

// Ring buffer processing limits
static int events_this_poll = 0;
static const int max_events_per_poll = 128;

// Pending map tracking and eviction
static uint64_t pending_count = 0;
static uint64_t max_pending = 16384;
static uint64_t timeout_ns = 500000000ULL;  // 500ms default
static uint64_t stale_evicted = 0;
static uint64_t forced_evicted = 0;

static void on_sig(int s){ (void)s; running=false; }

// Idle strategy function pointer type
typedef void (*idle_strategy_fn)(uint64_t idle_count);

// Busy-spin idle strategy with x86 PAUSE instruction
static void idle_strategy_busy_spin(uint64_t idle_count) {
    (void)idle_count;
#ifdef __x86_64__
    _mm_pause();
#else
    __asm__ __volatile__("" ::: "memory");
#endif
}

// Default idle strategy with progressive backoff
static void idle_strategy_backoff(uint64_t idle_count) {
    if (idle_count < 100) {
#ifdef __x86_64__
        _mm_pause();
#else
        __asm__ __volatile__("" ::: "memory");
#endif
    } else if (idle_count < 200) {
        sched_yield();
    } else {
        sched_yield();
    }
}

static idle_strategy_fn idle_strategy = idle_strategy_backoff;
static const char *idle_strategy_name = "backoff";

static struct termios orig_termios;
static bool termios_saved = false;

// Forward declarations
static void dump_cumulative_histogram(void);
static void reset_cumulative_histogram(void);
static void show_keyboard_help(void);

// Helper: convert timespec to nanoseconds (monotonic epoch time)
static inline uint64_t timespec_to_ns(const struct timespec *ts) {
    return ts->tv_sec * NANOS_IN_SECOND + ts->tv_nsec;
}

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

// HDR histogram: 3 significant figures precision
// Maintains relative precision across wide range with compact memory footprint
// For 3 sig figs: 0-999 (width=1, 1000 buckets), 1000-9999 (width=10, 900 buckets), etc.
static uint64_t max_latency_ns = 100000000;  // 100ms default, configurable via -x
static uint64_t num_buckets = 0;  // Calculated at runtime based on max_latency_ns

// Calculate number of buckets needed for given max value with 3 sig figs
// First decade (0-999) uses 1000 buckets, subsequent decades use 900 buckets each
static uint64_t hdr_calculate_num_buckets(uint64_t max_value) {
    if (max_value == 0) return 1;

    uint64_t buckets = 0;
    uint64_t range_start = 0;
    uint64_t magnitude = 1;

    while (range_start <= max_value) {
        uint64_t range_end = (magnitude * 1000) - 1;
        if (range_end >= max_value) {
            // Partial or exact range at the end
            uint64_t values_in_range = max_value - range_start + 1;
            buckets += (values_in_range + magnitude - 1) / magnitude; // Ceiling division
            break;
        }
        // First range (0-999) has 1000 buckets, others have 900
        buckets += (magnitude == 1) ? 1000 : 900;
        range_start = magnitude * 1000;
        magnitude *= 10;
    }

    return buckets;
}

// Map value to bucket index (3 sig figs)
// Ranges: 0-999 (width=1), 1000-9999 (width=10), 10000-99999 (width=100), etc.
static uint64_t hdr_value_to_index(uint64_t value) {
    if (value == 0) return 0;
    if (value >= max_latency_ns) {
        return num_buckets > 0 ? num_buckets - 1 : 0;
    }

    uint64_t magnitude = 1;
    uint64_t base_index = 0;
    uint64_t range_start = 0;

    // Find which magnitude range this value falls into
    while (value >= magnitude * 1000) {
        base_index += (magnitude == 1) ? 1000 : 900;
        range_start = magnitude * 1000;
        magnitude *= 10;
    }

    // Within this range, bucket width = magnitude
    return base_index + (value - range_start) / magnitude;
}

// Map bucket index to representative value (upper bound of bucket)
static uint64_t hdr_index_to_value(uint64_t index) {
    if (index == 0) return 0;
    if (index >= num_buckets) return max_latency_ns;

    uint64_t magnitude = 1;
    uint64_t base_index = 0;
    uint64_t range_start = 0;

    // Find which magnitude range this index falls into
    while (index >= base_index + ((magnitude == 1) ? 1000 : 900) &&
           base_index + ((magnitude == 1) ? 1000 : 900) < num_buckets) {
        base_index += (magnitude == 1) ? 1000 : 900;
        range_start = magnitude * 1000;
        magnitude *= 10;
    }

    uint64_t offset = index - base_index;
    uint64_t bucket_min = range_start + (offset * magnitude);
    uint64_t bucket_max = bucket_min + magnitude - 1;

    // Clamp bucket_max to max_latency_ns (for partial buckets at the end)
    if (bucket_max > max_latency_ns) {
        bucket_max = max_latency_ns;
    }

    return bucket_max; // Upper bound - conservative for latency reporting
}

// Interval stats: simple tracking (reset each report)
static uint64_t interval_sum_ns = 0;
static uint64_t interval_min_ns = UINT64_MAX;
static uint64_t interval_max_ns = 0;

// Cumulative histogram: all-time percentile analysis (never reset)
static uint64_t *cumulative_histogram = NULL;

// Forward declarations for pending map functions
static void pending_map_add(const uint8_t *ord_id, uint8_t len, uint64_t ts_ns);
static bool pending_map_remove(const uint8_t *ord_id, uint8_t len, uint64_t *out_ts_ns);
static void record_latency(uint64_t latency_ns);


static int handle_ingress_tag11(void *ctx, void *data, size_t len) {
    (void)ctx; (void)len;
    struct tag11_with_timestamp *req = data;
    ingress_events_received++;
    pending_map_add(req->ord_id, req->ord_id_len, req->timestamp_ns);
    return (++events_this_poll >= max_events_per_poll) ? 1 : 0;
}

static int handle_egress_tag11(void *ctx, void *data, size_t len) {
    (void)ctx; (void)len;
    struct tag11_with_timestamp *req = data;
    egress_events_received++;

    uint64_t inbound_ts_ns;
    if (pending_map_remove(req->ord_id, req->ord_id_len, &inbound_ts_ns)) {
        if (req->timestamp_ns < inbound_ts_ns) {
            // Clock going backwards (egress timestamp < ingress timestamp)
            negative_latency_count++;
        } else {
            uint64_t latency_ns = req->timestamp_ns - inbound_ts_ns;
            record_latency(latency_ns);
        }
    } else {
        mismatch_count++;
    }
    return (++events_this_poll >= max_events_per_poll) ? 1 : 0;
}


// Round up to next power of 2 for hash table sizing
static uint32_t next_power_of_2(uint32_t n) {
    if (n == 0) return 1;
    n--;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    return n + 1;
}

// Initialize pending map with size based on max_pending (0.5 load factor)
static bool pending_map_init(uint64_t max_entries) {
    // Load factor 0.5: table size = max_entries / 0.5 = max_entries * 2
    uint32_t target_size = (uint32_t)(max_entries * 2);
    pending_map_size = next_power_of_2(target_size);

    pending_map = calloc(pending_map_size, sizeof(struct pending_tag11 *));
    if (!pending_map) {
        fprintf(stderr, "Failed to allocate pending map (%u buckets)\n", pending_map_size);
        return false;
    }

    // Initialize age list pointers
    pending_age_head = NULL;
    pending_age_tail = NULL;
    pending_count = 0;

    return true;
}

// Free pending map and all entries
static void pending_map_cleanup(void) {
    if (!pending_map) return;

    // Free all entries via age list
    while (pending_age_head) {
        struct pending_tag11 *next = pending_age_head->age_next;
        free(pending_age_head);
        pending_age_head = next;
    }
    pending_age_tail = NULL;
    pending_count = 0;

    // Free the bucket array
    free(pending_map);
    pending_map = NULL;
    pending_map_size = 0;
}

// Simple hash function for tag 11 strings
static uint32_t hash_tag11(const char *key, uint8_t len) {
    uint32_t hash = 5381;
    for (uint8_t i = 0; i < len; i++)
        hash = ((hash << 5) + hash) + key[i];
    return hash % pending_map_size;
}

// Age-list helpers
static inline void pending_age_append(struct pending_tag11 *e) {
    e->age_next = NULL;
    e->age_prev = pending_age_tail;
    if (pending_age_tail)
        pending_age_tail->age_next = e;
    else
        pending_age_head = e;
    pending_age_tail = e;
}

static inline void pending_age_remove(struct pending_tag11 *e) {
    if (e->age_prev)
        e->age_prev->age_next = e->age_next;
    else
        pending_age_head = e->age_next;

    if (e->age_next)
        e->age_next->age_prev = e->age_prev;
    else
        pending_age_tail = e->age_prev;

    e->age_prev = NULL;
    e->age_next = NULL;
}

// Remove a specific entry from both the hash table and age list.
static void pending_remove_entry(struct pending_tag11 *victim) {
    struct pending_tag11 **curr = &pending_map[victim->hash];
    while (*curr) {
        if (*curr == victim) {
            *curr = victim->next;
            pending_age_remove(victim);
            free(victim);
            pending_count--;
            return;
        }
        curr = &(*curr)->next;
    }
}

// Evict stale entries from the head of the age list.
static uint64_t pending_evict_stale(uint64_t timestamp_threshold_ns) {
    if (timeout_ns == 0)
        return 0;

    uint64_t cutoff_ns = timestamp_threshold_ns - timeout_ns;
    uint64_t evicted = 0;

    while (pending_age_head && pending_age_head->timestamp_ns < cutoff_ns) {
        pending_remove_entry(pending_age_head);
        evicted++;
    }

    if (evicted)
        stale_evicted += evicted;
    return evicted;
}

// Add inbound tag 11 to pending map
static void pending_map_add(const uint8_t *ord_id, uint8_t ord_id_len, uint64_t timestamp_ns) {
    // First evict anything stale (O(#stale) using age list)
    pending_evict_stale(timestamp_ns);

    // If still at limit, evict oldest unclaimed entries (FIFO) until we have space.
    while (pending_count >= max_pending && pending_age_head) {
        pending_remove_entry(pending_age_head);
        forced_evicted++;
    }

    if (pending_count >= max_pending) {
        // No space and nothing to evict (should only happen if max_pending==0)
        return;
    }

    // Traverse to tail, checking for duplicates along the way (FIFO: oldest first, newest last)
    uint32_t hash = hash_tag11((const char *)ord_id, ord_id_len);
    struct pending_tag11 **curr = &pending_map[hash];

    while (*curr) {
        if ((*curr)->ord_id_len == ord_id_len && memcmp((*curr)->ord_id, ord_id, ord_id_len) == 0) {
            // Duplicate found - do not add
            duplicate_ingress_ids++;
            return;
        }
        curr = &(*curr)->next;
    }
    // Now *curr points to the tail (NULL) - this is where we'll insert

    struct pending_tag11 *entry = malloc(sizeof(*entry));
    if (!entry) return;

    memcpy(entry->ord_id, ord_id, ord_id_len);
    entry->ord_id_len = ord_id_len;
    entry->timestamp_ns = timestamp_ns;
    entry->hash = hash;
    entry->next = NULL;

    // Insert at tail (FIFO ordering)
    *curr = entry;

    pending_age_append(entry);
    pending_count++;
}

// Lookup and remove outbound tag 11 from pending map
static bool pending_map_remove(const uint8_t *ord_id, uint8_t ord_id_len, uint64_t *out_ts_ns) {
    uint32_t hash = hash_tag11((const char *)ord_id, ord_id_len);

    struct pending_tag11 **curr = &pending_map[hash];
    while (*curr) {
        // Match requires: same length AND same key value
        if ((*curr)->ord_id_len == ord_id_len && memcmp((*curr)->ord_id, ord_id, ord_id_len) == 0) {
            *out_ts_ns = (*curr)->timestamp_ns;
            struct pending_tag11 *to_free = *curr;
            *curr = (*curr)->next;
            pending_age_remove(to_free);
            free(to_free);
            pending_count--;
            return true;
        }
        curr = &(*curr)->next;
    }
    return false;
}

// Record latency into cumulative histogram and update interval stats
static void record_latency(uint64_t latency_ns) {
    // Calculate HDR bucket index (3 significant figures)
    uint64_t bucket = hdr_value_to_index(latency_ns);

    // Update cumulative histogram only (interval doesn't need histogram)
    cumulative_histogram[bucket]++;

    // Update interval sum (with overflow detection, UINT64_MAX = overflow sentinel)
    if (interval_sum_ns != UINT64_MAX) {
        uint64_t new_interval_sum = interval_sum_ns + latency_ns;
        if (new_interval_sum < interval_sum_ns) {
            // Overflow detected - set to MAX and stop updating
            interval_sum_ns = UINT64_MAX;
        } else {
            interval_sum_ns = new_interval_sum;
        }
    }

    // Track actual interval min/max (not clamped to histogram range)
    if (latency_ns < interval_min_ns) interval_min_ns = latency_ns;
    if (latency_ns > interval_max_ns) interval_max_ns = latency_ns;

    matched_count++;
}

static uint64_t percentile_from_buckets(const uint64_t *hist, double p) {
    uint64_t total = 0;
    for (uint64_t i = 0; i < num_buckets; i++)
        total += hist[i];

    if (total == 0) return 0;

    // Special cases for MIN (p=0.0) and MAX (p=100.0)
    if (p <= 0.0) {
        // Find first non-empty bucket
        for (uint64_t i = 0; i < num_buckets; i++) {
            if (hist[i] > 0)
                return hdr_index_to_value(i);
        }
        return 0;
    }

    if (p >= 100.0) {
        // Find last non-empty bucket
        for (uint64_t i = num_buckets; i > 0; i--) {
            if (hist[i - 1] > 0)
                return hdr_index_to_value(i - 1);
        }
        return 0;
    }

    // Normal percentile calculation
    uint64_t rank = (uint64_t)((p / 100.0) * (double)(total - 1)) + 1;
    uint64_t acc = 0;

    for (uint64_t i = 0; i < num_buckets; i++) {
        acc += hist[i];
        if (acc >= rank) {
            // Return the representative value for this bucket
            return hdr_index_to_value(i);
        }
    }

    return max_latency_ns;
}

// Format and print a latency value
static void print_latency(uint64_t ns) {
    if (ns >= 1000)
        printf("%.3fus", ns / 1000.0);
    else
        printf("%lluns", (unsigned long long)ns);
}

// Print ASCII bar for histogram visualization
static void print_histogram_bar(uint64_t count, uint64_t max_count, int bar_width) {
    int filled = 0;
    if (max_count > 0) {
        filled = (int)((count * bar_width) / max_count);
        if (filled > bar_width) filled = bar_width;
    }

    for (int i = 0; i < filled; i++) {
        printf("#");
    }
}

// Format latency value for histogram display (compact format)
static void format_latency_compact(uint64_t ns, char *buf, size_t len) {
    if (ns < 1000)
        snprintf(buf, len, "%lluns", (unsigned long long)ns);
    else if (ns < NANOS_IN_MS)
        snprintf(buf, len, "%.1fus", ns / (double)NANOS_IN_US);
    else if (ns < NANOS_IN_SECOND)
        snprintf(buf, len, "%.2fms", ns / (double)NANOS_IN_MS);
    else
        snprintf(buf, len, "%.2fs", ns / (double)NANOS_IN_SECOND);
}

// Dump detailed cumulative histogram with ASCII visualization
static void dump_cumulative_histogram(void) {
    if (num_buckets == 0 || cumulative_histogram == NULL) return;
    uint64_t total = 0;
    for (uint64_t i = 0; i < num_buckets; i++)
        total += cumulative_histogram[i];

    if (total == 0) {
        printf("\n[cumulative] No latency samples recorded yet\n\n");
        return;
    }

    printf("\n========== CUMULATIVE HISTOGRAM (all-time, n=%llu) ==========\n", (unsigned long long)total);
    printf("MIN:      "); print_latency(percentile_from_buckets(cumulative_histogram, 0.0)); printf("\n");
    printf("P50:      "); print_latency(percentile_from_buckets(cumulative_histogram, 50.0)); printf("\n");
    printf("P90:      "); print_latency(percentile_from_buckets(cumulative_histogram, 90.0)); printf("\n");
    printf("P99:      "); print_latency(percentile_from_buckets(cumulative_histogram, 99.0)); printf("\n");
    printf("P99.9:    "); print_latency(percentile_from_buckets(cumulative_histogram, 99.9)); printf("\n");
    printf("P99.99:   "); print_latency(percentile_from_buckets(cumulative_histogram, 99.99)); printf("\n");
    printf("P99.999:  "); print_latency(percentile_from_buckets(cumulative_histogram, 99.999)); printf("\n");
    printf("MAX:      "); print_latency(percentile_from_buckets(cumulative_histogram, 100.0)); printf("\n");

    // ASCII art visualization - intelligently aggregate buckets
    printf("\nDistribution:\n");

    // Find range of data (first and last non-empty bucket)
    uint64_t first_bucket = 0, last_bucket = 0;
    for (uint64_t i = 0; i < num_buckets; i++) {
        if (cumulative_histogram[i] > 0) {
            first_bucket = i;
            break;
        }
    }
    for (uint64_t i = num_buckets; i > 0; i--) {
        if (cumulative_histogram[i - 1] > 0) {
            last_bucket = i - 1;
            break;
        }
    }

    if (first_bucket == last_bucket) {
        // All data in single bucket
        uint64_t val = hdr_index_to_value(first_bucket);
        char buf[32];
        format_latency_compact(val, buf, sizeof(buf));
        printf("%10s | %llu (100.0%%)\n", buf, (unsigned long long)total);
    } else {
        // Aggregate into ~25 display buckets
        const int num_display_buckets = 25;
        uint64_t buckets_per_display = (last_bucket - first_bucket + 1) / num_display_buckets;
        if (buckets_per_display < 1) buckets_per_display = 1;

        uint64_t display_counts[30] = {0};  // Up to 30 display rows
        uint64_t display_min[30] = {0};
        uint64_t display_max[30] = {0};
        int num_displays = 0;
        uint64_t max_count = 0;

        for (uint64_t i = first_bucket; i <= last_bucket; i += buckets_per_display) {
            if (num_displays >= 30) break;

            uint64_t end = i + buckets_per_display;
            if (end > last_bucket + 1) end = last_bucket + 1;

            uint64_t count = 0;
            for (uint64_t j = i; j < end; j++) {
                count += cumulative_histogram[j];
            }

            if (count > 0) {
                display_min[num_displays] = hdr_index_to_value(i);
                display_max[num_displays] = hdr_index_to_value(end - 1);
                display_counts[num_displays] = count;
                if (count > max_count) max_count = count;
                num_displays++;
            }
        }

        // Format all range strings and find max width for alignment
        char range_strs[30][32];
        int max_label_width = 0;

        for (int d = 0; d < num_displays; d++) {
            char min_buf[16], max_buf[16];
            format_latency_compact(display_min[d], min_buf, sizeof(min_buf));
            format_latency_compact(display_max[d], max_buf, sizeof(max_buf));

            if (display_min[d] == display_max[d]) {
                snprintf(range_strs[d], sizeof(range_strs[d]), "%s", min_buf);
            } else {
                snprintf(range_strs[d], sizeof(range_strs[d]), "%s-%s", min_buf, max_buf);
            }

            int len = strlen(range_strs[d]);
            if (len > max_label_width) max_label_width = len;
        }

        // Print bars with aligned labels
        const int bar_width = 50;
        for (int d = 0; d < num_displays; d++) {
            double pct = (100.0 * display_counts[d]) / total;

            printf("%*s |", max_label_width, range_strs[d]);
            print_histogram_bar(display_counts[d], max_count, bar_width);
            printf(" %llu (%.1f%%)\n", (unsigned long long)display_counts[d], pct);
        }
    }

    printf("==============================================================\n\n");
    fflush(stdout);
}

// Reset cumulative histogram
static void reset_cumulative_histogram(void) {
    memset(cumulative_histogram, 0, num_buckets * sizeof(uint64_t));
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
        interval_min = interval_min_ns;
        if (interval_sum_ns != UINT64_MAX) {
            interval_avg = interval_sum_ns / interval_count;
        }
        interval_max = interval_max_ns;
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
            st.ingress_fragmented += percpu_stats[i].ingress_fragmented;
            st.egress_fragmented += percpu_stats[i].egress_fragmented;
            st.cb_clobbered += percpu_stats[i].cb_clobbered;
            st.tag11_too_long += percpu_stats[i].tag11_too_long;
            st.parser_stuck += percpu_stats[i].parser_stuck;
        }
    }

    // Traffic stats with filters on same line
    printf("[traffic] hooks: ingress=%llu egress=%llu | scanned: ingress=%llu egress=%llu",
        (unsigned long long)st.ingress_hook_called,
        (unsigned long long)st.egress_hook_called,
        (unsigned long long)st.ingress_scan_started,
        (unsigned long long)st.egress_scan_started);

    // Append filters if any non-zero
    if (st.payload_zero || st.payload_too_small) {
        printf(" | filters: payload_zero=%llu payload_small=%llu",
            (unsigned long long)st.payload_zero,
            (unsigned long long)st.payload_too_small);
    }

    // Append fragmentation stats if any non-zero
    if (st.ingress_fragmented || st.egress_fragmented) {
        printf(" | fragmented: ingress=%llu egress=%llu",
            (unsigned long long)st.ingress_fragmented,
            (unsigned long long)st.egress_fragmented);
    }
    printf("\n");

    // Main stats line with interval latency (simple: MIN/AVG/MAX)
    printf("[fixlat] matched=%llu inbound=%llu outbound=%llu mismatch=%llu dup_ingress=%llu negative=%llu | rate: %.0f match/sec | latency: min=",
        (unsigned long long)interval_count,
        (unsigned long long)st.inbound_total,
        (unsigned long long)st.outbound_total,
        (unsigned long long)mismatch_count,
        (unsigned long long)duplicate_ingress_ids,
        (unsigned long long)negative_latency_count,
        rate);

    if (interval_count > 0) {
        print_latency(interval_min);
        printf(" avg=");
        if (interval_sum_ns == UINT64_MAX) {
            printf("OVERFLOW");
        } else {
            print_latency(interval_avg);
        }
        printf(" max=");
        print_latency(interval_max);
    } else {
        printf("- avg=- max=-");
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

    // Reset interval stats for next period
    interval_sum_ns = 0;
    interval_min_ns = UINT64_MAX;
    interval_max_ns = 0;
    matched_count = 0;
    mismatch_count = 0;
    duplicate_ingress_ids = 0;
    negative_latency_count = 0;
}

// Parse port range from string (e.g., "8080" or "12001-12010")
// Returns: 0 on success, -1 on error
static int parse_port_range(const char *str, uint16_t *min, uint16_t *max) {
    char *dash = strchr(str, '-');

    if (dash) {
        // Port range format: "12001-12010"
        *dash = '\0';  // Split string
        *min = (uint16_t)atoi(str);
        *max = (uint16_t)atoi(dash + 1);

        if (*min == 0 || *max == 0 || *min > *max) {
            fprintf(stderr, "Invalid port range: %s-%s (ports must be 1-65535)\n", str, dash + 1);
            return -1;
        }
    } else {
        // Single port format: "8080"
        uint16_t port = (uint16_t)atoi(str);
        if (port == 0) {
            fprintf(stderr, "Invalid port: %s (port must be 1-65535)\n", str);
            return -1;
        }
        *min = port;
        *max = port;
    }

    return 0;
}

static void usage(const char *p){
    fprintf(stderr,
        "ebpf-fix-latency-tool v%s - eBPF FIX Protocol Latency Monitor\n\n"
        "Usage: %s -i <iface> -p <port|range> [-r seconds] [-m max] [-t timeout] [-c cpu] [-x max_ms] [-s strategy]\n"
        "  -i  Network interface to monitor (required)\n"
        "  -p  TCP port or range to watch (e.g., 8080 or 12001-12010) (required)\n"
        "  -r  Report interval in seconds (default: 5)\n"
        "  -m  Maximum concurrent pending requests (default: 16384)\n"
        "  -t  Request timeout in seconds (default: 0.5)\n"
        "  -c  Pin userspace thread to CPU core (optional)\n"
        "  -x  Maximum latency to track in milliseconds (default: 100)\n"
        "  -s  Idle strategy: 'spin' (busy-spin) or 'backoff' (default, progressive backoff)\n"
        "  -v  Show version and exit\n", VERSION, p);
}

int main(int argc, char **argv)
{
    const char *iface=NULL;
    uint16_t port_min=0, port_max=0;
    int cpu_core = -1;
    int opt;

    while ((opt=getopt(argc, argv, "i:p:r:m:t:c:x:s:v")) != -1) {
        switch (opt) {
            case 'i': iface=optarg; break;
            case 'p':
                if (parse_port_range(optarg, &port_min, &port_max) != 0) {
                    usage(argv[0]);
                    return 1;
                }
                break;
            case 'r': report_every_sec=atoi(optarg); break;
            case 'm': max_pending=(uint64_t)atoll(optarg); break;
            case 't': timeout_ns=(uint64_t)(atof(optarg) * (double)NANOS_IN_SECOND); break;
            case 'c': cpu_core=atoi(optarg); break;
            case 'x': max_latency_ns=(uint64_t)(atof(optarg) * (double)NANOS_IN_MS); break;
            case 's':
                if (strcmp(optarg, "spin") == 0) {
                    idle_strategy = idle_strategy_busy_spin;
                    idle_strategy_name = "spin";
                } else if (strcmp(optarg, "backoff") == 0) {
                    idle_strategy = idle_strategy_backoff;
                    idle_strategy_name = "backoff";
                } else {
                    fprintf(stderr, "Invalid idle strategy: %s (use 'spin' or 'backoff')\n", optarg);
                    usage(argv[0]);
                    return 1;
                }
                break;
            case 'v': printf("ebpf-fix-latency-tool v%s\n", VERSION); return 0;
            default: usage(argv[0]); return 1;
        }
    }
    if (!iface){ usage(argv[0]); return 1; }
    if (port_min == 0 || port_max == 0) {
        fprintf(stderr, "Error: -p <port|range> is required\n\n");
        usage(argv[0]);
        return 1;
    }

    // Pin to CPU core if requested
    if (cpu_core >= 0) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(cpu_core, &cpuset);

        if (sched_setaffinity(0, sizeof(cpuset), &cpuset) != 0) {
            fprintf(stderr, "Failed to set CPU affinity to core %d: %s\n",
                    cpu_core, strerror(errno));
            return 1;
        }
    }

    // Initialize cumulative HDR histogram (3 significant figures)
    num_buckets = hdr_calculate_num_buckets(max_latency_ns);
    cumulative_histogram = calloc(num_buckets, sizeof(uint64_t));
    if (!cumulative_histogram) {
        fprintf(stderr, "Failed to allocate histogram memory (%llu buckets, ~%llu KB)\n",
                (unsigned long long)num_buckets,
                (unsigned long long)(num_buckets * sizeof(uint64_t) / 1024));
        return 1;
    }
    // Store histogram and pending map stats for startup message
    uint64_t histo_kb = (num_buckets * sizeof(uint64_t)) / 1024;

    // Initialize pending map (0.5 load factor)
    if (!pending_map_init(max_pending)) {
        free(cumulative_histogram);
        return 1;
    }
    uint64_t pending_kb = (pending_map_size * sizeof(struct pending_tag11 *)) / 1024;

    struct rlimit rl={RLIM_INFINITY, RLIM_INFINITY}; setrlimit(RLIMIT_MEMLOCK, &rl);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    struct fixlat_bpf *skel = fixlat_bpf__open();
    if (!skel){ fprintf(stderr,"open skel failed\n"); return 1; }
    if (fixlat_bpf__load(skel)){ fprintf(stderr,"load skel failed\n"); return 1; }

    __u32 z=0;
    struct config cfg = {0};
    cfg.watch_port_min = port_min;
    cfg.watch_port_max = port_max;
    if (bpf_map_update_elem(bpf_map__fd(skel->maps.cfg_map), &z, &cfg, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to update config map\n");
        return 1;
    }

    // Populate ingress jump table with tail call programs (indices 1-7 for payload scanning)
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

    idx = 6; prog_fd = bpf_program__fd(skel->progs.handle_ingress_payload_6);
    bpf_map_update_elem(ingress_jump_table_fd, &idx, &prog_fd, BPF_ANY);

    idx = 7; prog_fd = bpf_program__fd(skel->progs.handle_ingress_payload_7);
    bpf_map_update_elem(ingress_jump_table_fd, &idx, &prog_fd, BPF_ANY);

    // Populate egress jump table with tail call programs (indices 1-7 for payload scanning)
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

    idx = 6; prog_fd = bpf_program__fd(skel->progs.handle_egress_payload_6);
    bpf_map_update_elem(egress_jump_table_fd, &idx, &prog_fd, BPF_ANY);

    idx = 7; prog_fd = bpf_program__fd(skel->progs.handle_egress_payload_7);
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

    // Print startup message
    if (port_min == port_max) {
        printf("ebpf-fix-latency-tool v%s | %s:%u | tracking up to %lluk pending tags (%lluK RAM) | histogram 0-%.0fms (%lluK RAM)\n",
               VERSION, iface, port_min, (unsigned long long)(max_pending / 1000),
               (unsigned long long)pending_kb, max_latency_ns / (double)NANOS_IN_MS, (unsigned long long)histo_kb);
    } else {
        printf("ebpf-fix-latency-tool v%s | %s:%u-%u | tracking up to %lluk pending tags (%lluK RAM) | histogram 0-%.0fms (%lluK RAM)\n",
               VERSION, iface, port_min, port_max, (unsigned long long)(max_pending / 1000),
               (unsigned long long)pending_kb, max_latency_ns / (double)NANOS_IN_MS, (unsigned long long)histo_kb);
    }

    // Display CPU affinity and/or idle strategy info
    bool has_cpu_affinity = (cpu_core >= 0);
    bool has_spin_strategy = (strcmp(idle_strategy_name, "spin") == 0);

    if (has_cpu_affinity && has_spin_strategy) {
        printf("Userspace thread pinned to CPU core %d | CPU spinning idle strategy selected\n", cpu_core);
    } else if (has_cpu_affinity) {
        printf("Userspace thread pinned to CPU core %d\n", cpu_core);
    } else if (has_spin_strategy) {
        printf("CPU spinning idle strategy selected\n");
    }

    printf("Interval stats: MIN/AVG/MAX (%ds intervals) | Press '?' for keyboard commands\n", report_every_sec);

    // Enable raw mode for keyboard input
    enable_raw_mode();
    atexit(disable_raw_mode);

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t last_report_ns = timespec_to_ns(&ts);
    uint64_t last_cleanup_ns = last_report_ns;

    double cleanup_interval_sec = 0.5;

    uint64_t iterations_since_housekeeping = 0;
    const uint64_t max_iterations_between_housekeeping = 10000;
    uint64_t idle_iterations = 0;

    while (running) {
        events_this_poll = 0;
        int ingress_work = ring_buffer__poll(ingress_rb, 0);
        events_this_poll = 0;
        int egress_work = ring_buffer__poll(egress_rb, 0);
        int total_work = ingress_work + egress_work;

        iterations_since_housekeeping++;

        if (total_work > 0) {
            idle_iterations = 0;
        } else {
            idle_strategy(idle_iterations++);
        }

        bool should_do_housekeeping = (total_work == 0) ||
                                      (iterations_since_housekeeping >= max_iterations_between_housekeeping);

        if (!should_do_housekeeping) {
            continue;
        }

        iterations_since_housekeeping = 0;

        handle_keyboard();

        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        uint64_t now_ns = timespec_to_ns(&now);

        double cleanup_elapsed_sec = (now_ns - last_cleanup_ns) / (double)NANOS_IN_SECOND;
        if (cleanup_elapsed_sec >= cleanup_interval_sec) {
            pending_evict_stale(now_ns);
            last_cleanup_ns = now_ns;
        }

        double report_elapsed_sec = (now_ns - last_report_ns) / (double)NANOS_IN_SECOND;
        if (report_elapsed_sec >= report_every_sec) {
            snapshot(fd_stats, report_elapsed_sec);
            last_report_ns = now_ns;
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

    // Free pending map and histogram
    pending_map_cleanup();
    free(cumulative_histogram);

    return 0;
}
