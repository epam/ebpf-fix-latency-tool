#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include "../include/fixlat.h"

#define SOH 0x01
#define TAG11 ((uint32_t)(SOH << 24) | ((uint32_t)'1' << 16) | ((uint32_t)'1' << 8) | ((uint32_t)'='))

// Simplified parser logic extracted from eBPF code for testing
bool parse_tag11(const uint8_t *data, size_t len, uint8_t *out_value, uint8_t *out_len) {
    if (len < 4) return false;

    // Scan for TAG11 pattern
    bool found_tag11_start = false;
    uint32_t window = 0;
    size_t offset = 0;

    for (size_t i = 0; i < len; i++, offset++) {
        uint8_t c = data[offset];
        window = (window << 8) | c;

        if (window == TAG11) {
            found_tag11_start = true;
            offset++; // Move past '='
            break;
        }
    }

    if (!found_tag11_start)
        return false;

    // Extract tag 11 value until SOH
    bool found_tag11_end = false;
    uint8_t value_len = 0;

    for (size_t i = 0; i < FIXLAT_MAX_TAGVAL_LEN && offset < len; i++) {
        uint8_t c = data[offset++];

        if (c == SOH) {
            value_len = i;
            found_tag11_end = true;
            break;
        }

        out_value[i] = c;
    }

    if (!found_tag11_end || value_len == 0)
        return false;

    *out_len = value_len;
    return true;
}

void test_basic_tag11_parsing() {
    printf("Test: Basic tag 11 parsing...\n");

    // FIX message with tag 11
    uint8_t msg[] = {
        '8', '=', 'F', 'I', 'X', '.', '4', '.', '2', SOH,
        '9', '=', '1', '0', '0', SOH,
        SOH, '1', '1', '=', 'O', 'R', 'D', 'E', 'R', '1', '2', '3', SOH,
        '3', '5', '=', 'D', SOH
    };

    uint8_t value[FIXLAT_MAX_TAGVAL_LEN] = {0};
    uint8_t len = 0;

    bool result = parse_tag11(msg, sizeof(msg), value, &len);

    assert(result == true);
    assert(len == 8);
    assert(memcmp(value, "ORDER123", 8) == 0);

    printf("  ✓ Successfully parsed tag 11 value: %.*s (len=%d)\n", len, value, len);
}

void test_tag11_at_start() {
    printf("Test: Tag 11 at message start...\n");

    uint8_t msg[] = {
        SOH, '1', '1', '=', 'A', 'B', 'C', SOH,
        '3', '5', '=', 'D', SOH
    };

    uint8_t value[FIXLAT_MAX_TAGVAL_LEN] = {0};
    uint8_t len = 0;

    bool result = parse_tag11(msg, sizeof(msg), value, &len);

    assert(result == true);
    assert(len == 3);
    assert(memcmp(value, "ABC", 3) == 0);

    printf("  ✓ Successfully parsed tag 11 at start: %.*s (len=%d)\n", len, value, len);
}

void test_tag11_missing() {
    printf("Test: No tag 11 present...\n");

    uint8_t msg[] = {
        '8', '=', 'F', 'I', 'X', '.', '4', '.', '2', SOH,
        '3', '5', '=', 'D', SOH
    };

    uint8_t value[FIXLAT_MAX_TAGVAL_LEN] = {0};
    uint8_t len = 0;

    bool result = parse_tag11(msg, sizeof(msg), value, &len);

    assert(result == false);

    printf("  ✓ Correctly returned false for missing tag 11\n");
}

void test_tag11_numeric() {
    printf("Test: Numeric tag 11 value...\n");

    uint8_t msg[] = {
        SOH, '1', '1', '=', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', SOH
    };

    uint8_t value[FIXLAT_MAX_TAGVAL_LEN] = {0};
    uint8_t len = 0;

    bool result = parse_tag11(msg, sizeof(msg), value, &len);

    assert(result == true);
    assert(len == 10);
    assert(memcmp(value, "1234567890", 10) == 0);

    printf("  ✓ Successfully parsed numeric tag 11: %.*s (len=%d)\n", len, value, len);
}

int main(void) {
    printf("=== Tag 11 Parser Unit Tests ===\n\n");

    test_basic_tag11_parsing();
    test_tag11_at_start();
    test_tag11_missing();
    test_tag11_numeric();

    printf("\n✓ All tests passed!\n");
    return 0;
}
