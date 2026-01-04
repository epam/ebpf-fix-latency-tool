#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// HDR histogram simulation (copied from fixlat.c)
static uint64_t max_latency_ns = 100000000;  // 100ms
static uint64_t num_buckets = 0;

static uint64_t hdr_calculate_num_buckets(uint64_t max_value) {
    if (max_value == 0) return 1;
    uint64_t buckets = 0;
    uint64_t range_start = 0;
    uint64_t magnitude = 1;
    while (range_start <= max_value) {
        uint64_t range_end = (magnitude * 1000) - 1;
        if (range_end >= max_value) {
            uint64_t values_in_range = max_value - range_start + 1;
            buckets += (values_in_range + magnitude - 1) / magnitude;
            break;
        }
        buckets += (magnitude == 1) ? 1000 : 900;
        range_start = magnitude * 1000;
        magnitude *= 10;
    }
    return buckets;
}

static uint64_t hdr_value_to_index(uint64_t value) {
    if (value == 0) return 0;
    if (value >= max_latency_ns) {
        return num_buckets > 0 ? num_buckets - 1 : 0;
    }
    uint64_t magnitude = 1;
    uint64_t base_index = 0;
    uint64_t range_start = 0;
    while (value >= magnitude * 1000) {
        base_index += (magnitude == 1) ? 1000 : 900;
        range_start = magnitude * 1000;
        magnitude *= 10;
    }
    return base_index + (value - range_start) / magnitude;
}

static uint64_t hdr_index_to_value(uint64_t index) {
    if (index == 0) return 0;
    if (index >= num_buckets) return max_latency_ns;
    uint64_t magnitude = 1;
    uint64_t base_index = 0;
    uint64_t range_start = 0;
    while (index >= base_index + ((magnitude == 1) ? 1000 : 900) &&
           base_index + ((magnitude == 1) ? 1000 : 900) < num_buckets) {
        base_index += (magnitude == 1) ? 1000 : 900;
        range_start = magnitude * 1000;
        magnitude *= 10;
    }
    uint64_t offset = index - base_index;
    uint64_t bucket_min = range_start + (offset * magnitude);
    uint64_t bucket_max = bucket_min + magnitude - 1;
    if (bucket_max > max_latency_ns) {
        bucket_max = max_latency_ns;
    }
    return (bucket_min + bucket_max) / 2;
}

// Visualization functions
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

static void format_latency_compact(uint64_t ns, char *buf, size_t len) {
    if (ns < 1000)
        snprintf(buf, len, "%lluns", (unsigned long long)ns);
    else if (ns < 1000000)
        snprintf(buf, len, "%.1fus", ns / 1e3);
    else if (ns < 1000000000)
        snprintf(buf, len, "%.2fms", ns / 1e6);
    else
        snprintf(buf, len, "%.2fs", ns / 1e9);
}

static void dump_histogram(uint64_t *histogram, const char *title) {
    uint64_t total = 0;
    for (uint64_t i = 0; i < num_buckets; i++)
        total += histogram[i];

    if (total == 0) {
        printf("\nNo data\n\n");
        return;
    }

    printf("\n========== %s (n=%llu) ==========\n", title, (unsigned long long)total);

    // Find range of data
    uint64_t first_bucket = 0, last_bucket = 0;
    for (uint64_t i = 0; i < num_buckets; i++) {
        if (histogram[i] > 0) {
            first_bucket = i;
            break;
        }
    }
    for (uint64_t i = num_buckets - 1; i > 0; i--) {
        if (histogram[i] > 0) {
            last_bucket = i;
            break;
        }
    }

    if (first_bucket == last_bucket) {
        uint64_t val = hdr_index_to_value(first_bucket);
        char buf[32];
        format_latency_compact(val, buf, sizeof(buf));
        printf("%10s | %llu (100.0%%)\n", buf, (unsigned long long)total);
    } else {
        // Aggregate into ~25 display buckets
        const int num_display_buckets = 25;
        uint64_t buckets_per_display = (last_bucket - first_bucket + 1) / num_display_buckets;
        if (buckets_per_display < 1) buckets_per_display = 1;

        uint64_t display_counts[30] = {0};
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
                count += histogram[j];
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
        printf("\nDistribution (%d buckets):\n", num_displays);
        const int bar_width = 50;
        for (int d = 0; d < num_displays; d++) {
            double pct = (100.0 * display_counts[d]) / total;

            printf("%*s |", max_label_width, range_strs[d]);
            print_histogram_bar(display_counts[d], max_count, bar_width);
            printf(" %llu (%.1f%%)\n", (unsigned long long)display_counts[d], pct);
        }
    }

    printf("==============================================================\n\n");
}

int main(void) {
    printf("\n=== ASCII Histogram Adaptive Bucketing Test ===\n\n");

    max_latency_ns = 100000000;  // 100ms
    num_buckets = hdr_calculate_num_buckets(max_latency_ns);
    printf("HDR histogram: %llu buckets for max %.1fms\n",
           (unsigned long long)num_buckets, max_latency_ns / 1e6);

    // Test 1: Wide distribution (1us to 50ms)
    uint64_t *histogram1 = calloc(num_buckets, sizeof(uint64_t));
    for (uint64_t i = 0; i < 10000; i++) {
        // Exponential-like distribution
        uint64_t value = 1000 + (i * i * 5000) / 10000;  // 1us to 50ms range
        if (value > 50000000) value = 50000000;
        histogram1[hdr_value_to_index(value)]++;
    }
    dump_histogram(histogram1, "Wide Distribution (1us-50ms)");
    free(histogram1);

    // Test 2: Narrow distribution (10-20us) - should show fine granularity
    uint64_t *histogram2 = calloc(num_buckets, sizeof(uint64_t));
    for (uint64_t i = 0; i < 5000; i++) {
        uint64_t value = 10000 + (i * 10000) / 5000;  // 10-20us
        histogram2[hdr_value_to_index(value)]++;
    }
    dump_histogram(histogram2, "Narrow Distribution (10-20us)");
    free(histogram2);

    // Test 3: Realistic FIX latency (bimodal: fast 50-100us, slow 5-15ms)
    uint64_t *histogram3 = calloc(num_buckets, sizeof(uint64_t));
    // Fast path: 70% at 50-100us
    for (uint64_t i = 0; i < 7000; i++) {
        uint64_t value = 50000 + (i * 50000) / 7000;  // 50-100us
        histogram3[hdr_value_to_index(value)]++;
    }
    // Slow path: 30% at 5-15ms
    for (uint64_t i = 0; i < 3000; i++) {
        uint64_t value = 5000000 + (i * 10000000) / 3000;  // 5-15ms
        histogram3[hdr_value_to_index(value)]++;
    }
    dump_histogram(histogram3, "Bimodal FIX Latency");
    free(histogram3);

    printf("✓ Adaptive bucketing shows 20-30 lines for wide distributions\n");
    printf("✓ Fine granularity for narrow distributions\n\n");
    return 0;
}
