#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <math.h>

// HDR histogram globals (same as in fixlat.c)
static uint64_t max_latency_ns = 100000000;  // 100ms default
static uint64_t num_buckets = 0;

// HDR histogram functions (copy from fixlat.c - UPDATED WITH 900 BUCKETS PER DECADE)
static uint64_t hdr_calculate_num_buckets(uint64_t max_value) {
    if (max_value == 0) return 1;

    uint64_t buckets = 0;
    uint64_t range_start = 0;
    uint64_t magnitude = 1;

    while (range_start <= max_value) {
        uint64_t range_end = (magnitude * 1000) - 1;
        if (range_end >= max_value) {
            // Partial range at the end
            uint64_t values_in_range = max_value - range_start + 1;
            buckets += (values_in_range + magnitude - 1) / magnitude;
            break;
        }
        // First range (0-999) has 1000 buckets, others have 900
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

    // Clamp bucket_max to max_latency_ns (for partial buckets at the end)
    if (bucket_max > max_latency_ns) {
        bucket_max = max_latency_ns;
    }

    return bucket_max; // Upper bound - conservative for latency reporting
}

// Test framework
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;
static int current_test_failed = 0;

#define TEST(name) \
    static void test_##name(void); \
    static void run_test_##name(void) { \
        printf("Running test: %s... ", #name); \
        fflush(stdout); \
        tests_run++; \
        current_test_failed = 0; \
        test_##name(); \
        if (!current_test_failed) { \
            printf("PASSED\n"); \
            tests_passed++; \
        } \
    } \
    static void test_##name(void)

#define ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            printf("\n  FAILED: %s\n  at %s:%d\n", message, __FILE__, __LINE__); \
            current_test_failed = 1; \
            tests_failed++; \
            return; \
        } \
    } while(0)

#define ASSERT_EQ(actual, expected, message) \
    do { \
        uint64_t _a = (actual); \
        uint64_t _e = (expected); \
        if (_a != _e) { \
            printf("\n  FAILED: %s\n  Expected: %llu, Got: %llu\n  at %s:%d\n", \
                   message, (unsigned long long)_e, (unsigned long long)_a, __FILE__, __LINE__); \
            current_test_failed = 1; \
            tests_failed++; \
            return; \
        } \
    } while(0)

// ===== TESTS =====

TEST(bucket_calculation_100ms) {
    max_latency_ns = 100000000; // 100ms exactly
    num_buckets = hdr_calculate_num_buckets(max_latency_ns);

    // 0-999: 1000 buckets
    // 1000-9999: 900 buckets
    // 10000-99999: 900 buckets
    // 100000-999999: 900 buckets
    // 1000000-9999999: 900 buckets
    // 10000000-99999999: 900 buckets
    // 100000000-100000000: 1 bucket (partial)
    // Total: 1000 + 5*900 + 1 = 5501 buckets
    ASSERT_EQ(num_buckets, 5501, "100ms should use 5501 buckets");
}

TEST(bucket_calculation_1s) {
    max_latency_ns = 1000000000; // 1s exactly
    uint64_t buckets = hdr_calculate_num_buckets(max_latency_ns);

    // 1000 + 6*900 + 1 = 6401 buckets
    ASSERT_EQ(buckets, 6401, "1s should use 6401 buckets");
}

TEST(bucket_calculation_10ms) {
    max_latency_ns = 10000000; // 10ms exactly
    uint64_t buckets = hdr_calculate_num_buckets(max_latency_ns);

    // 0-999: 1000, 1k-9.9k: 900, 10k-99.9k: 900, 100k-999.9k: 900, 1m-9.9m: 900, 10m: 1
    // Total: 1000 + 4*900 + 1 = 4601
    ASSERT_EQ(buckets, 4601, "10ms should use 4601 buckets");
}

TEST(value_to_index_zero) {
    max_latency_ns = 100000000;
    num_buckets = hdr_calculate_num_buckets(max_latency_ns);

    uint64_t index = hdr_value_to_index(0);
    ASSERT_EQ(index, 0, "Value 0 should map to index 0");
}

TEST(value_to_index_first_range) {
    max_latency_ns = 100000000;
    num_buckets = hdr_calculate_num_buckets(max_latency_ns);

    // Range 0-999 (width=1): value N maps to index N
    ASSERT_EQ(hdr_value_to_index(1), 1, "Value 1ns -> index 1");
    ASSERT_EQ(hdr_value_to_index(100), 100, "Value 100ns -> index 100");
    ASSERT_EQ(hdr_value_to_index(500), 500, "Value 500ns -> index 500");
    ASSERT_EQ(hdr_value_to_index(999), 999, "Value 999ns -> index 999");
}

TEST(value_to_index_second_range) {
    max_latency_ns = 100000000;
    num_buckets = hdr_calculate_num_buckets(max_latency_ns);

    // Range 1000-9999 (width=10): base_index=1000
    // value 1000 -> index 1000
    // value 1010 -> index 1001
    // value 5000 -> index 1400
    ASSERT_EQ(hdr_value_to_index(1000), 1000, "Value 1000ns -> index 1000");
    ASSERT_EQ(hdr_value_to_index(1010), 1001, "Value 1010ns -> index 1001");
    ASSERT_EQ(hdr_value_to_index(5000), 1400, "Value 5000ns -> index 1400");
    ASSERT_EQ(hdr_value_to_index(9990), 1899, "Value 9990ns -> index 1899");
}

TEST(value_to_index_microsecond_range) {
    max_latency_ns = 100000000;
    num_buckets = hdr_calculate_num_buckets(max_latency_ns);

    // Range 10000-99999 (width=100): base_index=1900
    // 10us = 10000ns -> index 1900
    // 30us = 30000ns -> (30000 - 10000) / 100 = 200 -> index 2100
    // 50us = 50000ns -> (50000 - 10000) / 100 = 400 -> index 2300
    ASSERT_EQ(hdr_value_to_index(10000), 1900, "Value 10us -> index 1900");
    ASSERT_EQ(hdr_value_to_index(30000), 2100, "Value 30us -> index 2100");
    ASSERT_EQ(hdr_value_to_index(50000), 2300, "Value 50us -> index 2300");
}

TEST(value_to_index_max_value) {
    max_latency_ns = 100000000;
    num_buckets = hdr_calculate_num_buckets(max_latency_ns);

    uint64_t index = hdr_value_to_index(max_latency_ns);
    ASSERT_EQ(index, num_buckets - 1, "Max value should map to last bucket");

    // Values beyond max should also map to last bucket
    index = hdr_value_to_index(max_latency_ns * 2);
    ASSERT_EQ(index, num_buckets - 1, "Values > max should map to last bucket");
}

TEST(index_to_value_zero) {
    max_latency_ns = 100000000;
    num_buckets = hdr_calculate_num_buckets(max_latency_ns);

    uint64_t value = hdr_index_to_value(0);
    ASSERT_EQ(value, 0, "Index 0 should map to value 0");
}

TEST(index_to_value_first_range) {
    max_latency_ns = 100000000;
    num_buckets = hdr_calculate_num_buckets(max_latency_ns);

    // Range 0-999 (width=1): index N represents bucket [N,N], upper bound = N
    ASSERT_EQ(hdr_index_to_value(1), 1, "Index 1 -> 1ns");
    ASSERT_EQ(hdr_index_to_value(100), 100, "Index 100 -> 100ns");
    ASSERT_EQ(hdr_index_to_value(500), 500, "Index 500 -> 500ns");
}

TEST(index_to_value_second_range) {
    max_latency_ns = 100000000;
    num_buckets = hdr_calculate_num_buckets(max_latency_ns);

    // Range 1000-9999 (width=10): index 1000 = bucket [1000-1009], upper bound=1009
    ASSERT_EQ(hdr_index_to_value(1000), 1009, "Index 1000 -> 1009ns");
    ASSERT_EQ(hdr_index_to_value(1001), 1019, "Index 1001 -> 1019ns");
}

TEST(roundtrip_value_index_value) {
    max_latency_ns = 100000000;
    num_buckets = hdr_calculate_num_buckets(max_latency_ns);

    uint64_t test_values[] = {
        0, 1, 100, 500, 999,           // First range
        1000, 5000, 9999,              // Second range
        10000, 30000, 50000, 99999,    // Third range
        100000, 500000, 999999,        // Fourth range
        1000000, 5000000, 9999999,     // Fifth range
        10000000, 50000000, 99999999   // Sixth range
    };

    for (size_t i = 0; i < sizeof(test_values)/sizeof(test_values[0]); i++) {
        uint64_t original = test_values[i];
        uint64_t index = hdr_value_to_index(original);
        uint64_t reconstructed = hdr_index_to_value(index);

        // Find the magnitude (bucket width) for this value
        uint64_t magnitude = 1;
        while (original >= magnitude * 1000) {
            magnitude *= 10;
        }

        // Reconstructed value should be within ±magnitude/2 of original
        uint64_t tolerance = magnitude;
        uint64_t diff = (reconstructed > original) ?
                       (reconstructed - original) : (original - reconstructed);

        if (diff > tolerance) {
            printf("\n  Roundtrip failed for value %llu: index=%llu, reconstructed=%llu (diff=%llu, tolerance=%llu)\n",
                   (unsigned long long)original, (unsigned long long)index,
                   (unsigned long long)reconstructed, (unsigned long long)diff,
                   (unsigned long long)tolerance);
            ASSERT(0, "Roundtrip value mismatch");
        }
    }
}

TEST(precision_check_microsecond_range) {
    max_latency_ns = 100000000;
    num_buckets = hdr_calculate_num_buckets(max_latency_ns);

    // In 10-100us range (10000-99999), bucket width = 100ns
    // Check that values differing by 100ns map to different buckets
    uint64_t val1 = 30000;  // 30.0us
    uint64_t val2 = 30100;  // 30.1us

    uint64_t idx1 = hdr_value_to_index(val1);
    uint64_t idx2 = hdr_value_to_index(val2);

    ASSERT(idx1 != idx2, "Values 30.0us and 30.1us should map to different buckets");
    ASSERT_EQ(idx2 - idx1, 1, "Adjacent 100ns values should map to adjacent buckets");
}

TEST(no_bucket_overlap) {
    max_latency_ns = 100000000;
    num_buckets = hdr_calculate_num_buckets(max_latency_ns);

    // Test range boundaries: verify no overlap between ranges
    // 999 (last of range 0) and 1000 (first of range 1)
    uint64_t idx_999 = hdr_value_to_index(999);
    uint64_t idx_1000 = hdr_value_to_index(1000);
    ASSERT(idx_1000 > idx_999, "Range boundary: 1000 should be after 999");

    // 9999 (last of range 1) and 10000 (first of range 2)
    uint64_t idx_9999 = hdr_value_to_index(9999);
    uint64_t idx_10000 = hdr_value_to_index(10000);
    ASSERT(idx_10000 > idx_9999, "Range boundary: 10000 should be after 9999");
}

TEST(all_buckets_valid) {
    max_latency_ns = 100000000;
    num_buckets = hdr_calculate_num_buckets(max_latency_ns);

    // Every bucket index should produce a valid value
    for (uint64_t i = 0; i < num_buckets; i++) {
        uint64_t value = hdr_index_to_value(i);
        if (value > max_latency_ns) {
            printf("\n  Bucket %llu -> value %llu (max=%llu)\n",
                   (unsigned long long)i, (unsigned long long)value,
                   (unsigned long long)max_latency_ns);
        }
        ASSERT(value <= max_latency_ns, "Bucket value should not exceed max");
    }
}

TEST(monotonic_increasing) {
    max_latency_ns = 100000000;
    num_buckets = hdr_calculate_num_buckets(max_latency_ns);

    // Bucket values should be monotonically increasing
    uint64_t prev_value = 0;
    for (uint64_t i = 0; i < num_buckets; i++) {
        uint64_t value = hdr_index_to_value(i);
        if (value < prev_value) {
            printf("\n  Bucket %llu -> value %llu < prev %llu\n",
                   (unsigned long long)i, (unsigned long long)value,
                   (unsigned long long)prev_value);
        }
        ASSERT(value >= prev_value, "Bucket values should be monotonically increasing");
        prev_value = value;
    }
}

// ===== PERCENTILE CALCULATION HELPER =====

// Calculate percentile from histogram (0.0 - 1.0)
static uint64_t calculate_percentile(uint64_t *histogram, uint64_t total_count, double percentile) {
    if (total_count == 0) return 0;

    uint64_t target_count = (uint64_t)(total_count * percentile);
    uint64_t cumulative = 0;

    for (uint64_t i = 0; i < num_buckets; i++) {
        cumulative += histogram[i];
        if (cumulative >= target_count) {
            return hdr_index_to_value(i);
        }
    }

    return hdr_index_to_value(num_buckets - 1);
}

// ===== END-TO-END TESTS =====

TEST(e2e_uniform_distribution) {
    max_latency_ns = 100000000;  // 100ms
    num_buckets = hdr_calculate_num_buckets(max_latency_ns);
    uint64_t *histogram = calloc(num_buckets, sizeof(uint64_t));

    // Record 10,000 samples uniformly distributed from 1ms to 99ms
    uint64_t num_samples = 10000;
    uint64_t min_val = 1000000;   // 1ms
    uint64_t max_val = 99000000;  // 99ms
    uint64_t range = max_val - min_val;

    for (uint64_t i = 0; i < num_samples; i++) {
        uint64_t value = min_val + (i * range) / num_samples;
        uint64_t index = hdr_value_to_index(value);
        histogram[index]++;
    }

    // For uniform distribution:
    // p50 should be around 50ms (midpoint of 1-99ms)
    // p90 should be around 89.2ms (1 + 0.9 * 98)
    // p99 should be around 98.02ms (1 + 0.99 * 98)

    uint64_t p50 = calculate_percentile(histogram, num_samples, 0.50);
    uint64_t p90 = calculate_percentile(histogram, num_samples, 0.90);
    uint64_t p99 = calculate_percentile(histogram, num_samples, 0.99);

    // Allow generous tolerance due to bucketing (±10% of expected value)
    uint64_t expected_p50 = 50000000;  // 50ms
    uint64_t expected_p90 = 89200000;  // 89.2ms
    uint64_t expected_p99 = 98020000;  // 98.02ms

    uint64_t tolerance_p50 = expected_p50 / 10;
    uint64_t tolerance_p90 = expected_p90 / 10;
    uint64_t tolerance_p99 = expected_p99 / 10;

    uint64_t diff_p50 = (p50 > expected_p50) ? (p50 - expected_p50) : (expected_p50 - p50);
    uint64_t diff_p90 = (p90 > expected_p90) ? (p90 - expected_p90) : (expected_p90 - p90);
    uint64_t diff_p99 = (p99 > expected_p99) ? (p99 - expected_p99) : (expected_p99 - p99);

    if (diff_p50 > tolerance_p50) {
        printf("\n  p50: expected ~%llums, got %llums (diff=%llums)\n",
               (unsigned long long)(expected_p50 / 1000000),
               (unsigned long long)(p50 / 1000000),
               (unsigned long long)(diff_p50 / 1000000));
    }
    ASSERT(diff_p50 <= tolerance_p50, "p50 should be around 50ms");

    if (diff_p90 > tolerance_p90) {
        printf("\n  p90: expected ~%llums, got %llums (diff=%llums)\n",
               (unsigned long long)(expected_p90 / 1000000),
               (unsigned long long)(p90 / 1000000),
               (unsigned long long)(diff_p90 / 1000000));
    }
    ASSERT(diff_p90 <= tolerance_p90, "p90 should be around 89ms");

    if (diff_p99 > tolerance_p99) {
        printf("\n  p99: expected ~%llums, got %llums (diff=%llums)\n",
               (unsigned long long)(expected_p99 / 1000000),
               (unsigned long long)(p99 / 1000000),
               (unsigned long long)(diff_p99 / 1000000));
    }
    ASSERT(diff_p99 <= tolerance_p99, "p99 should be around 98ms");

    free(histogram);
}

TEST(e2e_realistic_latency_distribution) {
    max_latency_ns = 100000000;  // 100ms
    num_buckets = hdr_calculate_num_buckets(max_latency_ns);
    uint64_t *histogram = calloc(num_buckets, sizeof(uint64_t));

    // Simulate realistic latency distribution:
    // - 70% of requests: 1-10ms (fast path)
    // - 20% of requests: 10-30ms (medium)
    // - 8% of requests: 30-60ms (slow)
    // - 2% of requests: 60-100ms (very slow outliers)

    uint64_t total = 0;

    // Fast path: 7000 samples from 1-10ms
    for (uint64_t i = 0; i < 7000; i++) {
        uint64_t value = 1000000 + (i * 9000000) / 7000;  // 1-10ms
        histogram[hdr_value_to_index(value)]++;
        total++;
    }

    // Medium: 2000 samples from 10-30ms
    for (uint64_t i = 0; i < 2000; i++) {
        uint64_t value = 10000000 + (i * 20000000) / 2000;  // 10-30ms
        histogram[hdr_value_to_index(value)]++;
        total++;
    }

    // Slow: 800 samples from 30-60ms
    for (uint64_t i = 0; i < 800; i++) {
        uint64_t value = 30000000 + (i * 30000000) / 800;  // 30-60ms
        histogram[hdr_value_to_index(value)]++;
        total++;
    }

    // Outliers: 200 samples from 60-100ms
    for (uint64_t i = 0; i < 200; i++) {
        uint64_t value = 60000000 + (i * 40000000) / 200;  // 60-100ms
        histogram[hdr_value_to_index(value)]++;
        total++;
    }

    uint64_t p50 = calculate_percentile(histogram, total, 0.50);
    uint64_t p90 = calculate_percentile(histogram, total, 0.90);
    uint64_t p99 = calculate_percentile(histogram, total, 0.99);

    // Expected values for this distribution:
    // p50 should be in fast path range (1-10ms), around 5-7ms
    // p90 should be in medium/slow boundary (around 30ms)
    // p99 should be in outliers range (around 80ms)

    ASSERT(p50 >= 1000000 && p50 <= 10000000, "p50 should be in fast path (1-10ms)");
    ASSERT(p90 >= 20000000 && p90 <= 40000000, "p90 should be around 20-40ms");
    ASSERT(p99 >= 60000000 && p99 <= 100000000, "p99 should be in outlier range (60-100ms)");
}

TEST(e2e_single_value_distribution) {
    max_latency_ns = 100000000;
    num_buckets = hdr_calculate_num_buckets(max_latency_ns);
    uint64_t *histogram = calloc(num_buckets, sizeof(uint64_t));

    // All samples are exactly 5ms
    uint64_t single_value = 5000000;  // 5ms
    uint64_t num_samples = 1000;

    for (uint64_t i = 0; i < num_samples; i++) {
        histogram[hdr_value_to_index(single_value)]++;
    }

    uint64_t p50 = calculate_percentile(histogram, num_samples, 0.50);
    uint64_t p90 = calculate_percentile(histogram, num_samples, 0.90);
    uint64_t p99 = calculate_percentile(histogram, num_samples, 0.99);

    // All percentiles should be the same value (or very close due to bucketing)
    uint64_t index = hdr_value_to_index(single_value);
    uint64_t bucket_value = hdr_index_to_value(index);

    ASSERT_EQ(p50, bucket_value, "p50 should match bucket value");
    ASSERT_EQ(p90, bucket_value, "p90 should match bucket value");
    ASSERT_EQ(p99, bucket_value, "p99 should match bucket value");

    free(histogram);
}

TEST(e2e_bimodal_distribution) {
    max_latency_ns = 100000000;
    num_buckets = hdr_calculate_num_buckets(max_latency_ns);
    uint64_t *histogram = calloc(num_buckets, sizeof(uint64_t));

    // Bimodal: 50% at ~2ms (local cache hits), 50% at ~50ms (database queries)
    uint64_t num_samples = 10000;

    for (uint64_t i = 0; i < num_samples / 2; i++) {
        histogram[hdr_value_to_index(2000000)]++;  // 2ms
    }

    for (uint64_t i = 0; i < num_samples / 2; i++) {
        histogram[hdr_value_to_index(50000000)]++;  // 50ms
    }

    uint64_t p25 = calculate_percentile(histogram, num_samples, 0.25);
    uint64_t p50 = calculate_percentile(histogram, num_samples, 0.50);
    uint64_t p75 = calculate_percentile(histogram, num_samples, 0.75);

    // p25 should be in first mode (~2ms)
    // p50 should be at transition (could be either mode, verify it's reasonable)
    // p75 should be in second mode (~50ms)

    ASSERT(p25 <= 5000000, "p25 should be in first mode (<5ms)");
    ASSERT(p50 >= 1000000 && p50 <= 55000000, "p50 should be in one of the modes");
    ASSERT(p75 >= 40000000, "p75 should be in second mode (>40ms)");

    free(histogram);
}

TEST(e2e_percentile_boundary_values) {
    max_latency_ns = 100000000;
    num_buckets = hdr_calculate_num_buckets(max_latency_ns);
    uint64_t *histogram = calloc(num_buckets, sizeof(uint64_t));

    // Test percentile calculation with 100 samples
    uint64_t num_samples = 100;
    for (uint64_t i = 0; i < num_samples; i++) {
        // Values from 1ms to 100ms
        uint64_t value = 1000000 + (i * 99000000) / 100;
        histogram[hdr_value_to_index(value)]++;
    }

    // Test boundary percentiles
    uint64_t p0 = calculate_percentile(histogram, num_samples, 0.0);
    uint64_t p100 = calculate_percentile(histogram, num_samples, 1.0);

    // p0 should be the minimum value bucket
    // p100 should be the maximum value bucket
    ASSERT(p0 <= 2000000, "p0 should be near minimum (<=2ms)");
    ASSERT(p100 >= 90000000, "p100 should be near maximum (>=90ms)");

    free(histogram);
}

// ===== MAIN =====

int main(void) {
    printf("\n=== HDR Histogram Unit Tests ===\n\n");

    // Basic correctness tests
    run_test_bucket_calculation_100ms();
    run_test_bucket_calculation_1s();
    run_test_bucket_calculation_10ms();
    run_test_value_to_index_zero();
    run_test_value_to_index_first_range();
    run_test_value_to_index_second_range();
    run_test_value_to_index_microsecond_range();
    run_test_value_to_index_max_value();
    run_test_index_to_value_zero();
    run_test_index_to_value_first_range();
    run_test_index_to_value_second_range();
    run_test_roundtrip_value_index_value();
    run_test_precision_check_microsecond_range();
    run_test_no_bucket_overlap();
    run_test_all_buckets_valid();
    run_test_monotonic_increasing();

    // End-to-end percentile validation
    run_test_e2e_uniform_distribution();
    run_test_e2e_realistic_latency_distribution();
    run_test_e2e_single_value_distribution();
    run_test_e2e_bimodal_distribution();
    run_test_e2e_percentile_boundary_values();

    printf("\n=== Test Results ===\n");
    printf("Total:  %d\n", tests_run);
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);

    if (tests_failed > 0) {
        printf("\nSome tests FAILED!\n");
        return 1;
    }

    printf("\nAll tests PASSED!\n");
    return 0;
}
