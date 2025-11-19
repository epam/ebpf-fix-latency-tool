#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "fixlat.h"

#define SOH 0x01
#define COLOR_GREEN "\033[32m"
#define COLOR_RED "\033[31m"
#define COLOR_RESET "\033[0m"

static const uint32_t TAG11 = ((uint32_t)SOH << 24) | ((uint32_t)'1' << 16) | ((uint32_t)'1' << 8) | ((uint32_t)'=');

static int test_count = 0;
static int test_passed = 0;
static int test_failed = 0;

/* Userspace version of the tag 11 parser logic */
static int parse_tag11(const unsigned char *data, size_t len,
                       struct pending_req *results, int max_results) {
    uint32_t win = 0;
    bool copy_state = false;
    uint8_t ord_id_len = 0;
    int found = 0;

    struct pending_req req = {0};

    for (size_t i = 0; i < len && found < max_results; i++) {
        unsigned char c = data[i];

        if (copy_state) {
            if (c == SOH) {
                /* Found end of tag value */
                if (ord_id_len > 0) {
                    req.len = ord_id_len;
                    results[found++] = req;
                }

                /* Reset for next tag */
                copy_state = false;
                ord_id_len = 0;
                win = SOH;
                memset(&req, 0, sizeof(req));
            } else if (ord_id_len < FIXLAT_MAX_TAGVAL_LEN) {
                /* Copy character to req.ord_id as we scan */
                req.ord_id[ord_id_len++] = c;
            }
        } else {
            /* Scan for TAG11 pattern */
            win = (win << 8) | c;
            if (win == TAG11) {
                copy_state = true;
                ord_id_len = 0;
            }
        }
    }

    return found;
}

static void run_test(const char *name,
                     const char *fix_msg,
                     const char **expected_tags,
                     int expected_count) {
    test_count++;
    printf("[TEST %d] %s... ", test_count, name);
    fflush(stdout);

    struct pending_req results[10];
    int found = parse_tag11((const unsigned char *)fix_msg, strlen(fix_msg), results, 10);

    /* Check count matches */
    if (found != expected_count) {
        printf(COLOR_RED "FAILED" COLOR_RESET " - expected %d tags, found %d\n",
               expected_count, found);
        test_failed++;
        return;
    }

    /* Check each tag value */
    bool all_match = true;
    for (int i = 0; i < found; i++) {
        size_t expected_len = strlen(expected_tags[i]);
        if (results[i].len != expected_len ||
            memcmp(results[i].ord_id, expected_tags[i], expected_len) != 0) {
            printf(COLOR_RED "FAILED" COLOR_RESET " - tag[%d] mismatch\n", i);
            printf("  Expected: '%.*s' (len=%zu)\n", (int)expected_len, expected_tags[i], expected_len);
            printf("  Got:      '%.*s' (len=%u)\n", results[i].len, results[i].ord_id, results[i].len);
            all_match = false;
        }
    }

    if (all_match) {
        printf(COLOR_GREEN "PASSED" COLOR_RESET "\n");
        test_passed++;
    } else {
        test_failed++;
    }
}

int main(void) {
    printf("=== Tag 11 Parser Logic Tests (Userspace) ===\n\n");

    /* TEST 1: Simple FIX message with one tag 11 */
    {
        const char *fix = "8=FIX.4.2\x01" "11=ORDER123\x01" "35=D\x01";
        const char *expected[] = {"ORDER123"};
        run_test("Single tag 11", fix, expected, 1);
    }

    /* TEST 2: Multiple tag 11 in same message */
    {
        const char *fix = "8=FIX.4.2\x01" "11=ABC\x01" "35=D\x01" "11=XYZ\x01";
        const char *expected[] = {"ABC", "XYZ"};
        run_test("Multiple tag 11", fix, expected, 2);
    }

    /* TEST 3: Tag 11 with numeric value */
    {
        const char *fix = "8=FIX.4.2\x01" "11=123456789\x01" "35=D\x01";
        const char *expected[] = {"123456789"};
        run_test("Numeric tag 11", fix, expected, 1);
    }

    /* TEST 4: Empty tag 11 (should be ignored) */
    {
        const char *fix = "8=FIX.4.2\x01" "11=\x01" "35=D\x01";
        const char *expected[] = {};
        run_test("Empty tag 11", fix, expected, 0);
    }

    /* TEST 5: Tag 11 at max length */
    {
        char fix[256];
        char long_id[FIXLAT_MAX_TAGVAL_LEN + 1];
        memset(long_id, 'A', FIXLAT_MAX_TAGVAL_LEN);
        long_id[FIXLAT_MAX_TAGVAL_LEN] = '\0';
        snprintf(fix, sizeof(fix), "8=FIX.4.2\x01" "11=%s\x01" "35=D\x01", long_id);
        const char *expected[] = {long_id};
        run_test("Max length tag 11", fix, expected, 1);
    }

    /* TEST 6: Tag 11 exceeding max length (should truncate) */
    {
        char fix[256];
        char very_long_id[FIXLAT_MAX_TAGVAL_LEN + 10];
        memset(very_long_id, 'B', FIXLAT_MAX_TAGVAL_LEN + 5);
        very_long_id[FIXLAT_MAX_TAGVAL_LEN + 5] = '\0';
        snprintf(fix, sizeof(fix), "8=FIX.4.2\x01" "11=%s\x01" "35=D\x01", very_long_id);

        char expected_truncated[FIXLAT_MAX_TAGVAL_LEN + 1];
        memset(expected_truncated, 'B', FIXLAT_MAX_TAGVAL_LEN);
        expected_truncated[FIXLAT_MAX_TAGVAL_LEN] = '\0';
        const char *expected[] = {expected_truncated};

        run_test("Truncated tag 11", fix, expected, 1);
    }

    /* TEST 7: FIX message without tag 11 */
    {
        const char *fix = "8=FIX.4.2\x01" "35=D\x01" "49=SENDER\x01";
        const char *expected[] = {};
        run_test("FIX without tag 11", fix, expected, 0);
    }

    /* TEST 8: Tag 11 with special characters */
    {
        const char *fix = "8=FIX.4.2\x01" "11=ORD-2024.01\x01" "35=D\x01";
        const char *expected[] = {"ORD-2024.01"};
        run_test("Tag 11 with special chars", fix, expected, 1);
    }

    /* TEST 9: Tag 110 and 111 (should not match tag 11) */
    {
        const char *fix = "8=FIX.4.2\x01" "110=100\x01" "111=200\x01" "35=D\x01";
        const char *expected[] = {};
        run_test("Tag 110/111 not matching", fix, expected, 0);
    }

    /* TEST 10: Tag 11 at start of message */
    {
        const char *fix = "\x01" "11=FIRST\x01" "8=FIX.4.2\x01";
        const char *expected[] = {"FIRST"};
        run_test("Tag 11 at start", fix, expected, 1);
    }

    /* TEST 11: Consecutive tag 11 */
    {
        const char *fix = "\x01" "11=A\x01" "11=B\x01" "11=C\x01";
        const char *expected[] = {"A", "B", "C"};
        run_test("Consecutive tag 11", fix, expected, 3);
    }

    /* TEST 12: Tag 11 with embedded numbers */
    {
        const char *fix = "8=FIX.4.2\x01" "11=ORD11ABC11\x01" "35=D\x01";
        const char *expected[] = {"ORD11ABC11"};
        run_test("Tag 11 value with '11'", fix, expected, 1);
    }

    /* Summary */
    printf("\n=== Test Summary ===\n");
    printf("Total:  %d\n", test_count);
    printf(COLOR_GREEN "Passed: %d" COLOR_RESET "\n", test_passed);
    if (test_failed > 0) {
        printf(COLOR_RED "Failed: %d" COLOR_RESET "\n", test_failed);
    } else {
        printf("Failed: 0\n");
    }

    return (test_failed == 0) ? 0 : 1;
}
