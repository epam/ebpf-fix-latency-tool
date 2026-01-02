/*
 * Unit tests for pending_map implementation
 * Tests dynamic hash table, age-ordered list, and eviction logic
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include "fixlat.h"

// Test framework
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;
static bool current_test_failed = false;

#define TEST(name) \
    static void test_##name(void); \
    static void run_test_##name(void) { \
        current_test_failed = false; \
        printf("Running test: %s... ", #name); \
        test_##name(); \
        tests_run++; \
        if (!current_test_failed) { \
            printf("PASSED\n"); \
            tests_passed++; \
        } else { \
            printf("FAILED\n"); \
            tests_failed++; \
        } \
    } \
    static void test_##name(void)

#define ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            printf("\n  Assertion failed: %s\n  %s\n", #condition, message); \
            current_test_failed = true; \
            return; \
        } \
    } while(0)

#define ASSERT_EQ(actual, expected, message) \
    do { \
        if ((actual) != (expected)) { \
            printf("\n  Expected %lld, got %lld: %s\n", (long long)(expected), (long long)(actual), message); \
            current_test_failed = true; \
            return; \
        } \
    } while(0)

// ============================================================================
// Pending map implementation (extracted from fixlat.c)
// ============================================================================

struct pending_tag11 {
    char key[FIXLAT_MAX_TAGVAL_LEN + 1];
    uint64_t timestamp_ns;
    uint32_t hash;
    struct pending_tag11 *next;
    struct pending_tag11 *age_prev;
    struct pending_tag11 *age_next;
};

static uint32_t pending_map_size = 0;
static struct pending_tag11 **pending_map = NULL;
static struct pending_tag11 *pending_age_head = NULL;
static struct pending_tag11 *pending_age_tail = NULL;
static uint64_t pending_count = 0;
static uint64_t max_pending = 0;
static uint64_t timeout_ns = 0;
static uint64_t stale_evicted = 0;
static uint64_t forced_evicted = 0;

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

static bool pending_map_init(uint64_t max_entries) {
    uint32_t target_size = (uint32_t)(max_entries * 2);
    pending_map_size = next_power_of_2(target_size);
    pending_map = calloc(pending_map_size, sizeof(struct pending_tag11 *));
    if (!pending_map) return false;
    max_pending = max_entries;
    pending_count = 0;
    pending_age_head = NULL;
    pending_age_tail = NULL;
    stale_evicted = 0;
    forced_evicted = 0;
    return true;
}

static void pending_map_cleanup(void) {
    if (!pending_map) return;
    while (pending_age_head) {
        struct pending_tag11 *next = pending_age_head->age_next;
        free(pending_age_head);
        pending_age_head = next;
    }
    pending_age_tail = NULL;
    pending_count = 0;
    free(pending_map);
    pending_map = NULL;
    pending_map_size = 0;
    max_pending = 0;
    timeout_ns = 0;
    stale_evicted = 0;
    forced_evicted = 0;
}

static uint32_t hash_tag11(const char *key, uint8_t len) {
    uint32_t hash = 5381;
    for (uint8_t i = 0; i < len; i++)
        hash = ((hash << 5) + hash) + key[i];
    return hash % pending_map_size;
}

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

static uint64_t pending_evict_stale(uint64_t now_ns) {
    if (timeout_ns == 0)
        return 0;

    uint64_t cutoff_ns = now_ns - timeout_ns;
    uint64_t evicted = 0;

    while (pending_age_head && pending_age_head->timestamp_ns < cutoff_ns) {
        pending_remove_entry(pending_age_head);
        evicted++;
    }

    if (evicted)
        stale_evicted += evicted;
    return evicted;
}

static void pending_map_add(const uint8_t *ord_id, uint8_t len, uint64_t ts_ns) {
    pending_evict_stale(ts_ns);

    while (pending_count >= max_pending && pending_age_head) {
        pending_remove_entry(pending_age_head);
        forced_evicted++;
    }

    if (pending_count >= max_pending) {
        return;
    }

    struct pending_tag11 *entry = malloc(sizeof(*entry));
    if (!entry) return;

    memset(entry, 0, sizeof(*entry));
    memcpy(entry->key, ord_id, len);
    entry->key[len] = '\0';

    entry->timestamp_ns = ts_ns;
    entry->hash = hash_tag11(entry->key, len);

    entry->next = pending_map[entry->hash];
    pending_map[entry->hash] = entry;

    pending_age_append(entry);
    pending_count++;
}

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
            pending_age_remove(to_free);
            free(to_free);
            pending_count--;
            return true;
        }
        curr = &(*curr)->next;
    }
    return false;
}

// ============================================================================
// Test cases
// ============================================================================

TEST(init_and_cleanup) {
    ASSERT(pending_map_init(100), "Failed to initialize map");
    ASSERT_EQ(pending_map_size, 256, "Map size should be 256 (100*2 rounded up to power of 2)");
    ASSERT(pending_map != NULL, "Map should be allocated");
    ASSERT_EQ(pending_count, 0, "Initial count should be 0");
    pending_map_cleanup();
    ASSERT(pending_map == NULL, "Map should be NULL after cleanup");
    ASSERT_EQ(pending_map_size, 0, "Map size should be 0 after cleanup");
}

TEST(init_power_of_2_sizes) {
    pending_map_init(4096);
    ASSERT_EQ(pending_map_size, 8192, "4096*2 = 8192 (already power of 2)");
    pending_map_cleanup();

    pending_map_init(1000);
    ASSERT_EQ(pending_map_size, 2048, "1000*2 = 2000, rounded to 2048");
    pending_map_cleanup();

    pending_map_init(16384);
    ASSERT_EQ(pending_map_size, 32768, "16384*2 = 32768 (already power of 2)");
    pending_map_cleanup();
}

TEST(add_single_entry) {
    pending_map_init(100);
    const char *tag11 = "ORDER123";
    pending_map_add((uint8_t*)tag11, strlen(tag11), 1000000);
    ASSERT_EQ(pending_count, 1, "Should have 1 entry");
    ASSERT(pending_age_head != NULL, "Age head should not be NULL");
    ASSERT(pending_age_tail != NULL, "Age tail should not be NULL");
    ASSERT(pending_age_head == pending_age_tail, "Head and tail should be same for single entry");
    pending_map_cleanup();
}

TEST(add_and_remove_entry) {
    pending_map_init(100);
    const char *tag11 = "ORDER456";
    uint64_t ts_in = 2000000;
    pending_map_add((uint8_t*)tag11, strlen(tag11), ts_in);
    ASSERT_EQ(pending_count, 1, "Should have 1 entry after add");

    uint64_t ts_out = 0;
    bool found = pending_map_remove((uint8_t*)tag11, strlen(tag11), &ts_out);
    ASSERT(found, "Should find the entry");
    ASSERT_EQ(ts_out, ts_in, "Timestamp should match");
    ASSERT_EQ(pending_count, 0, "Should have 0 entries after remove");
    ASSERT(pending_age_head == NULL, "Age head should be NULL after removing last entry");
    ASSERT(pending_age_tail == NULL, "Age tail should be NULL after removing last entry");
    pending_map_cleanup();
}

TEST(add_multiple_entries) {
    pending_map_init(100);
    pending_map_add((uint8_t*)"ORDER1", 6, 1000);
    pending_map_add((uint8_t*)"ORDER2", 6, 2000);
    pending_map_add((uint8_t*)"ORDER3", 6, 3000);
    ASSERT_EQ(pending_count, 3, "Should have 3 entries");

    // Verify age list order (oldest first)
    ASSERT(pending_age_head != NULL, "Head should exist");
    ASSERT_EQ(strcmp(pending_age_head->key, "ORDER1"), 0, "Head should be ORDER1 (oldest)");
    ASSERT(pending_age_tail != NULL, "Tail should exist");
    ASSERT_EQ(strcmp(pending_age_tail->key, "ORDER3"), 0, "Tail should be ORDER3 (newest)");
    pending_map_cleanup();
}

TEST(remove_middle_entry) {
    pending_map_init(100);
    pending_map_add((uint8_t*)"ORDER1", 6, 1000);
    pending_map_add((uint8_t*)"ORDER2", 6, 2000);
    pending_map_add((uint8_t*)"ORDER3", 6, 3000);

    uint64_t ts_out = 0;
    bool found = pending_map_remove((uint8_t*)"ORDER2", 6, &ts_out);
    ASSERT(found, "Should find ORDER2");
    ASSERT_EQ(ts_out, 2000, "Timestamp should match");
    ASSERT_EQ(pending_count, 2, "Should have 2 entries left");

    // Verify age list integrity
    ASSERT_EQ(strcmp(pending_age_head->key, "ORDER1"), 0, "Head should still be ORDER1");
    ASSERT_EQ(strcmp(pending_age_tail->key, "ORDER3"), 0, "Tail should still be ORDER3");
    ASSERT(pending_age_head->age_next == pending_age_tail, "ORDER1 next should be ORDER3");
    ASSERT(pending_age_tail->age_prev == pending_age_head, "ORDER3 prev should be ORDER1");
    pending_map_cleanup();
}

TEST(stale_eviction) {
    pending_map_init(100);
    timeout_ns = 500000000; // 500ms

    uint64_t base_time = 1000000000; // 1 second
    pending_map_add((uint8_t*)"OLD1", 4, base_time);
    pending_map_add((uint8_t*)"OLD2", 4, base_time + 100000000); // +100ms

    ASSERT_EQ(pending_count, 2, "Should have 2 entries");
    ASSERT_EQ(stale_evicted, 0, "No stale evictions yet");

    // Add entry at +700ms, should trigger eviction of OLD1 and OLD2
    // Cutoff = 700ms - 500ms = 200ms, so OLD1 (0ms) and OLD2 (100ms) are both stale
    pending_map_add((uint8_t*)"NEW1", 4, base_time + 700000000);

    ASSERT_EQ(pending_count, 1, "Should have 1 entry after stale eviction");
    ASSERT_EQ(stale_evicted, 2, "Should have evicted 2 stale entries");
    ASSERT_EQ(strcmp(pending_age_head->key, "NEW1"), 0, "Head should be NEW1 after eviction");
    ASSERT(pending_age_head == pending_age_tail, "Should only have one entry");

    // Add another entry that doesn't trigger eviction
    pending_map_add((uint8_t*)"NEW2", 4, base_time + 800000000);
    ASSERT_EQ(pending_count, 2, "Should have 2 entries");
    ASSERT_EQ(stale_evicted, 2, "No additional evictions");

    pending_map_cleanup();
}

TEST(fifo_eviction_at_capacity) {
    pending_map_init(5); // Small capacity
    timeout_ns = 0; // No timeout-based eviction

    for (int i = 0; i < 5; i++) {
        char buf[10];
        snprintf(buf, sizeof(buf), "ORD%d", i);
        pending_map_add((uint8_t*)buf, strlen(buf), 1000 + i);
    }
    ASSERT_EQ(pending_count, 5, "Should be at capacity");
    ASSERT_EQ(forced_evicted, 0, "No forced evictions yet");

    // Add one more, should evict oldest (ORD0)
    pending_map_add((uint8_t*)"ORD5", 4, 1005);
    ASSERT_EQ(pending_count, 5, "Should still be at capacity");
    ASSERT_EQ(forced_evicted, 1, "Should have 1 forced eviction");
    ASSERT_EQ(strcmp(pending_age_head->key, "ORD1"), 0, "Head should be ORD1 (ORD0 evicted)");
    ASSERT_EQ(strcmp(pending_age_tail->key, "ORD5"), 0, "Tail should be ORD5");

    pending_map_cleanup();
}

TEST(hash_collision_handling) {
    pending_map_init(100);

    // Add entries that will likely collide (small map, many entries)
    for (int i = 0; i < 20; i++) {
        char buf[10];
        snprintf(buf, sizeof(buf), "COL%d", i);
        pending_map_add((uint8_t*)buf, strlen(buf), 1000 + i);
    }
    ASSERT_EQ(pending_count, 20, "Should have all 20 entries");

    // Verify all can be found
    for (int i = 0; i < 20; i++) {
        char buf[10];
        snprintf(buf, sizeof(buf), "COL%d", i);
        uint64_t ts_out = 0;
        bool found = pending_map_remove((uint8_t*)buf, strlen(buf), &ts_out);
        ASSERT(found, "Should find all entries despite collisions");
        ASSERT_EQ(ts_out, 1000 + i, "Timestamp should match");
    }
    ASSERT_EQ(pending_count, 0, "All entries should be removed");

    pending_map_cleanup();
}

TEST(remove_nonexistent_entry) {
    pending_map_init(100);
    pending_map_add((uint8_t*)"EXISTS", 6, 1000);

    uint64_t ts_out = 0;
    bool found = pending_map_remove((uint8_t*)"NOTHERE", 7, &ts_out);
    ASSERT(!found, "Should not find nonexistent entry");
    ASSERT_EQ(pending_count, 1, "Count should not change");

    pending_map_cleanup();
}

TEST(age_list_order_maintained) {
    pending_map_init(100);

    // Add in order
    for (int i = 0; i < 10; i++) {
        char buf[10];
        snprintf(buf, sizeof(buf), "SEQ%d", i);
        pending_map_add((uint8_t*)buf, strlen(buf), 1000 + i * 100);
    }

    // Walk age list and verify order
    struct pending_tag11 *curr = pending_age_head;
    for (int i = 0; i < 10; i++) {
        ASSERT(curr != NULL, "List should have 10 entries");
        char expected[10];
        snprintf(expected, sizeof(expected), "SEQ%d", i);
        ASSERT_EQ(strcmp(curr->key, expected), 0, "Age list order should match insertion order");
        ASSERT_EQ(curr->timestamp_ns, 1000 + i * 100, "Timestamp should match");
        curr = curr->age_next;
    }
    ASSERT(curr == NULL, "List should end after 10 entries");

    pending_map_cleanup();
}

TEST(load_factor_check) {
    pending_map_init(4096);
    ASSERT_EQ(pending_map_size, 8192, "Map size should be 2x max_pending");

    // Fill to capacity
    for (int i = 0; i < 4096; i++) {
        char buf[20];
        snprintf(buf, sizeof(buf), "LOAD%d", i);
        pending_map_add((uint8_t*)buf, strlen(buf), 1000 + i);
    }
    ASSERT_EQ(pending_count, 4096, "Should have max entries");

    // Verify load factor is 0.5
    double load_factor = (double)pending_count / (double)pending_map_size;
    ASSERT(load_factor >= 0.49 && load_factor <= 0.51, "Load factor should be ~0.5");

    pending_map_cleanup();
}

// ============================================================================
// Main test runner
// ============================================================================

int main(void) {
    printf("\n=== Pending Map Unit Tests ===\n\n");

    run_test_init_and_cleanup();
    run_test_init_power_of_2_sizes();
    run_test_add_single_entry();
    run_test_add_and_remove_entry();
    run_test_add_multiple_entries();
    run_test_remove_middle_entry();
    run_test_stale_eviction();
    run_test_fifo_eviction_at_capacity();
    run_test_hash_collision_handling();
    run_test_remove_nonexistent_entry();
    run_test_age_list_order_maintained();
    run_test_load_factor_check();

    printf("\n=== Test Results ===\n");
    printf("Total:  %d\n", tests_run);
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);

    if (tests_failed == 0) {
        printf("\nAll tests PASSED!\n");
        return 0;
    } else {
        printf("\nSome tests FAILED!\n");
        return 1;
    }
}
