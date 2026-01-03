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

TEST(combined_stale_and_fifo_eviction) {
    pending_map_init(5); // Small capacity
    timeout_ns = 500000000; // 500ms

    uint64_t base_time = 1000000000;

    // Add 5 entries to fill capacity
    for (int i = 0; i < 5; i++) {
        char buf[10];
        snprintf(buf, sizeof(buf), "ENT%d", i);
        pending_map_add((uint8_t*)buf, strlen(buf), base_time + i * 100000000);
    }
    ASSERT_EQ(pending_count, 5, "Should be at capacity");

    // Add new entry at +1000ms
    // Cutoff = 1000ms - 500ms = 500ms
    // ENT0 (0ms), ENT1 (100ms), ENT2 (200ms), ENT3 (300ms), ENT4 (400ms) are all stale
    // Should evict all 5, then add new one
    pending_map_add((uint8_t*)"NEW", 3, base_time + 1000000000);

    ASSERT_EQ(pending_count, 1, "Should have only new entry");
    ASSERT_EQ(stale_evicted, 5, "Should have evicted 5 stale entries");
    ASSERT_EQ(forced_evicted, 0, "No forced evictions needed - stale cleanup made room");
    ASSERT_EQ(strcmp(pending_age_head->key, "NEW"), 0, "Head should be NEW");

    pending_map_cleanup();
}

TEST(partial_stale_eviction) {
    pending_map_init(100);
    timeout_ns = 0; // Disable timeout during setup

    uint64_t base_time = 1000000000;

    // Add 5 entries all at once (no stale eviction during add since timeout disabled)
    pending_map_add((uint8_t*)"OLD1", 4, base_time);
    pending_map_add((uint8_t*)"OLD2", 4, base_time + 100000000);
    pending_map_add((uint8_t*)"FRESH1", 6, base_time + 500000000);
    pending_map_add((uint8_t*)"FRESH2", 6, base_time + 600000000);
    pending_map_add((uint8_t*)"FRESH3", 6, base_time + 700000000);

    ASSERT_EQ(pending_count, 5, "Should have 5 entries");

    // Now enable timeout and add final entry
    timeout_ns = 300000000; // 300ms timeout
    // Add at +900ms, cutoff = 900ms - 300ms = 600ms
    // OLD1 (0ms) and OLD2 (100ms) are stale, FRESH1 (500ms) is stale
    // FRESH2 (600ms) is exactly at cutoff - NOT stale
    pending_map_add((uint8_t*)"NEW", 3, base_time + 900000000);

    ASSERT_EQ(pending_count, 3, "Should have 3 entries (evicted 3 stale)");
    ASSERT_EQ(stale_evicted, 3, "Should have evicted exactly 3 stale entries");
    ASSERT_EQ(strcmp(pending_age_head->key, "FRESH2"), 0, "Head should be FRESH2");
    ASSERT_EQ(strcmp(pending_age_tail->key, "NEW"), 0, "Tail should be NEW");

    pending_map_cleanup();
}

TEST(evict_all_entries_empty_list) {
    pending_map_init(100);
    timeout_ns = 500000000; // 500ms

    uint64_t base_time = 1000000000;

    // Add 3 entries
    pending_map_add((uint8_t*)"A", 1, base_time);
    pending_map_add((uint8_t*)"B", 1, base_time + 100000000);
    pending_map_add((uint8_t*)"C", 1, base_time + 200000000);
    ASSERT_EQ(pending_count, 3, "Should have 3 entries");

    // Add new entry far in future - all existing should be stale
    pending_map_add((uint8_t*)"NEW", 3, base_time + 2000000000);

    ASSERT_EQ(pending_count, 1, "Should have only new entry");
    ASSERT_EQ(stale_evicted, 3, "All 3 old entries evicted");
    ASSERT(pending_age_head != NULL, "Head should not be NULL");
    ASSERT(pending_age_tail != NULL, "Tail should not be NULL");
    ASSERT(pending_age_head == pending_age_tail, "Head and tail should be same (single entry)");
    ASSERT_EQ(strcmp(pending_age_head->key, "NEW"), 0, "Only entry should be NEW");

    // Now remove the last entry
    uint64_t ts_out;
    bool found = pending_map_remove((uint8_t*)"NEW", 3, &ts_out);
    ASSERT(found, "Should find NEW");
    ASSERT_EQ(pending_count, 0, "List should be empty");
    ASSERT(pending_age_head == NULL, "Head should be NULL after emptying");
    ASSERT(pending_age_tail == NULL, "Tail should be NULL after emptying");

    pending_map_cleanup();
}

TEST(boundary_timestamp_exactly_at_cutoff) {
    pending_map_init(100);
    timeout_ns = 500000000; // 500ms

    uint64_t base_time = 1000000000;
    uint64_t cutoff_time = base_time + 500000000; // Exactly cutoff

    // Add entries around the boundary
    pending_map_add((uint8_t*)"BEFORE", 6, cutoff_time - 1);  // Just before cutoff - stale
    pending_map_add((uint8_t*)"EXACT", 5, cutoff_time);        // Exactly at cutoff - NOT stale
    pending_map_add((uint8_t*)"AFTER", 5, cutoff_time + 1);    // After cutoff - NOT stale

    ASSERT_EQ(pending_count, 3, "Should have 3 entries");

    // Trigger stale eviction at +1000ms
    // Cutoff = 1000ms - 500ms = 500ms
    pending_map_add((uint8_t*)"NEW", 3, base_time + 1000000000);

    // Only BEFORE should be evicted (timestamp < cutoff)
    ASSERT_EQ(pending_count, 3, "Should have 3 entries (EXACT, AFTER, NEW)");
    ASSERT_EQ(stale_evicted, 1, "Only BEFORE should be evicted");
    ASSERT_EQ(strcmp(pending_age_head->key, "EXACT"), 0, "EXACT should not be evicted");

    pending_map_cleanup();
}

TEST(timeout_disabled_no_stale_eviction) {
    pending_map_init(5);
    timeout_ns = 0; // Timeout disabled

    uint64_t base_time = 1000000000;

    // Add 5 old entries
    for (int i = 0; i < 5; i++) {
        char buf[10];
        snprintf(buf, sizeof(buf), "OLD%d", i);
        pending_map_add((uint8_t*)buf, strlen(buf), base_time);
    }
    ASSERT_EQ(pending_count, 5, "Should be at capacity");
    ASSERT_EQ(stale_evicted, 0, "No stale evictions with timeout=0");

    // Add new entry far in future - should NOT evict as stale, should use FIFO
    pending_map_add((uint8_t*)"NEW", 3, base_time + 10000000000);

    ASSERT_EQ(pending_count, 5, "Still at capacity");
    ASSERT_EQ(stale_evicted, 0, "Still no stale evictions");
    ASSERT_EQ(forced_evicted, 1, "Should use FIFO eviction instead");
    ASSERT_EQ(strcmp(pending_age_head->key, "OLD1"), 0, "OLD0 evicted, OLD1 is now head");

    pending_map_cleanup();
}

TEST(remove_head_entry_only) {
    pending_map_init(100);

    pending_map_add((uint8_t*)"FIRST", 5, 1000);
    pending_map_add((uint8_t*)"SECOND", 6, 2000);
    pending_map_add((uint8_t*)"THIRD", 5, 3000);

    ASSERT_EQ(pending_count, 3, "Should have 3 entries");
    ASSERT_EQ(strcmp(pending_age_head->key, "FIRST"), 0, "Head is FIRST");

    // Remove head
    uint64_t ts_out;
    bool found = pending_map_remove((uint8_t*)"FIRST", 5, &ts_out);
    ASSERT(found, "Should find FIRST");
    ASSERT_EQ(ts_out, 1000, "Timestamp matches");
    ASSERT_EQ(pending_count, 2, "Should have 2 entries");

    // Verify head updated
    ASSERT_EQ(strcmp(pending_age_head->key, "SECOND"), 0, "SECOND is new head");
    ASSERT(pending_age_head->age_prev == NULL, "New head has no prev");
    ASSERT_EQ(strcmp(pending_age_tail->key, "THIRD"), 0, "Tail unchanged");

    pending_map_cleanup();
}

TEST(remove_tail_entry_only) {
    pending_map_init(100);

    pending_map_add((uint8_t*)"FIRST", 5, 1000);
    pending_map_add((uint8_t*)"SECOND", 6, 2000);
    pending_map_add((uint8_t*)"THIRD", 5, 3000);

    ASSERT_EQ(pending_count, 3, "Should have 3 entries");
    ASSERT_EQ(strcmp(pending_age_tail->key, "THIRD"), 0, "Tail is THIRD");

    // Remove tail
    uint64_t ts_out;
    bool found = pending_map_remove((uint8_t*)"THIRD", 5, &ts_out);
    ASSERT(found, "Should find THIRD");
    ASSERT_EQ(ts_out, 3000, "Timestamp matches");
    ASSERT_EQ(pending_count, 2, "Should have 2 entries");

    // Verify tail updated
    ASSERT_EQ(strcmp(pending_age_tail->key, "SECOND"), 0, "SECOND is new tail");
    ASSERT(pending_age_tail->age_next == NULL, "New tail has no next");
    ASSERT_EQ(strcmp(pending_age_head->key, "FIRST"), 0, "Head unchanged");

    pending_map_cleanup();
}

TEST(interleaved_operations_stress) {
    pending_map_init(100);
    timeout_ns = 0; // Disable timeout during setup

    uint64_t base_time = 5000000000ULL;

    // Add 10 entries with varying timestamps
    for (int i = 0; i < 10; i++) {
        char buf[10];
        snprintf(buf, sizeof(buf), "A%d", i);
        pending_map_add((uint8_t*)buf, strlen(buf), base_time + i * 100000000);
    }
    ASSERT_EQ(pending_count, 10, "Should have 10 entries");

    // Remove middle 5 (A3, A4, A5, A6, A7)
    uint64_t ts_out;
    for (int i = 3; i <= 7; i++) {
        char buf[10];
        snprintf(buf, sizeof(buf), "A%d", i);
        pending_map_remove((uint8_t*)buf, strlen(buf), &ts_out);
    }
    ASSERT_EQ(pending_count, 5, "Should have 5 entries");

    // Add 5 more entries (still no timeout)
    pending_map_add((uint8_t*)"B0", 2, base_time + 1000000000);
    pending_map_add((uint8_t*)"B1", 2, base_time + 1500000000);
    pending_map_add((uint8_t*)"B2", 2, base_time + 2000000000);
    pending_map_add((uint8_t*)"B3", 2, base_time + 2500000000);
    pending_map_add((uint8_t*)"B4", 2, base_time + 3000000000);

    ASSERT_EQ(pending_count, 10, "Should have 10 entries again");

    // Now enable timeout and trigger stale eviction
    timeout_ns = 1000000000; // 1 second

    // Trigger stale eviction at +5000ms from base
    // Cutoff = 5000ms - 1000ms = 4000ms from base
    pending_map_add((uint8_t*)"TRIGGER", 7, base_time + 5000000000);

    // Should have evicted old entries (A0-A2, A8-A9) but kept newer ones
    ASSERT(pending_count <= 11, "Some entries should have been evicted");
    ASSERT(stale_evicted > 0, "Should have evicted some stale entries");

    // Verify age list still valid by walking it
    int walked = 0;
    struct pending_tag11 *curr = pending_age_head;
    uint64_t prev_ts = 0;
    while (curr) {
        ASSERT(curr->timestamp_ns >= prev_ts, "Age list should be time-ordered");
        prev_ts = curr->timestamp_ns;
        walked++;
        curr = curr->age_next;
    }
    ASSERT_EQ((uint64_t)walked, pending_count, "Age list walk should count all entries");

    pending_map_cleanup();
}

TEST(age_list_consistency_after_many_removals) {
    pending_map_init(100);
    timeout_ns = 0; // No timeout-based eviction

    // Add 20 entries
    for (int i = 0; i < 20; i++) {
        char buf[10];
        snprintf(buf, sizeof(buf), "ITEM%d", i);
        pending_map_add((uint8_t*)buf, strlen(buf), 1000 + i);
    }
    ASSERT_EQ(pending_count, 20, "Should have 20 entries");

    // Remove every other entry (ITEM0, ITEM2, ITEM4, ...)
    uint64_t ts_out;
    for (int i = 0; i < 20; i += 2) {
        char buf[10];
        snprintf(buf, sizeof(buf), "ITEM%d", i);
        bool found = pending_map_remove((uint8_t*)buf, strlen(buf), &ts_out);
        ASSERT(found, "Should find entry to remove");
    }
    ASSERT_EQ(pending_count, 10, "Should have 10 entries left");

    // Walk age list and verify consistency
    int count = 0;
    struct pending_tag11 *curr = pending_age_head;
    struct pending_tag11 *prev = NULL;

    while (curr) {
        // Verify bidirectional linkage
        ASSERT(curr->age_prev == prev, "Prev pointer should match");
        if (prev) {
            ASSERT(prev->age_next == curr, "Next pointer should match");
        }

        // Verify timestamps are ascending
        if (prev) {
            ASSERT(curr->timestamp_ns > prev->timestamp_ns, "Timestamps should be ascending");
        }

        prev = curr;
        curr = curr->age_next;
        count++;
    }

    ASSERT_EQ(count, 10, "Should walk exactly 10 entries");
    ASSERT(prev == pending_age_tail, "Last walked entry should be tail");

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

    // Age-based eviction edge cases
    run_test_combined_stale_and_fifo_eviction();
    run_test_partial_stale_eviction();
    run_test_evict_all_entries_empty_list();
    run_test_boundary_timestamp_exactly_at_cutoff();
    run_test_timeout_disabled_no_stale_eviction();
    run_test_remove_head_entry_only();
    run_test_remove_tail_entry_only();
    run_test_interleaved_operations_stress();
    run_test_age_list_consistency_after_many_removals();

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
