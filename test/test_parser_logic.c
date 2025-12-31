#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

// Parse port range from string (e.g., "8080" or "12001-12010")
// Returns: 0 on success, -1 on error
static int parse_port_range(const char *str, uint16_t *min, uint16_t *max) {
    char buffer[128];
    strncpy(buffer, str, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    char *dash = strchr(buffer, '-');

    if (dash) {
        // Port range format: "12001-12010"
        *dash = '\0';  // Split string
        *min = (uint16_t)atoi(buffer);
        *max = (uint16_t)atoi(dash + 1);

        if (*min == 0 || *max == 0 || *min > *max) {
            fprintf(stderr, "Invalid port range: %s-%s\n", buffer, dash + 1);
            return -1;
        }
    } else {
        // Single port format: "8080" or "0"
        uint16_t port = (uint16_t)atoi(buffer);
        *min = port;
        *max = port;
    }

    return 0;
}

int main() {
    uint16_t min, max;
    int result;

    printf("Testing parse_port_range function...\n\n");

    // Test 1: Single port
    printf("Test 1: Single port '8080'\n");
    result = parse_port_range("8080", &min, &max);
    assert(result == 0);
    assert(min == 8080);
    assert(max == 8080);
    printf("  ✓ min=%u, max=%u\n\n", min, max);

    // Test 2: Port range
    printf("Test 2: Port range '12001-12010'\n");
    result = parse_port_range("12001-12010", &min, &max);
    assert(result == 0);
    assert(min == 12001);
    assert(max == 12010);
    printf("  ✓ min=%u, max=%u\n\n", min, max);

    // Test 3: Port 0 (all ports)
    printf("Test 3: Port 0 (all ports)\n");
    result = parse_port_range("0", &min, &max);
    assert(result == 0);
    assert(min == 0);
    assert(max == 0);
    printf("  ✓ min=%u, max=%u\n\n", min, max);

    // Test 4: Large port range
    printf("Test 4: Large port range '1024-65535'\n");
    result = parse_port_range("1024-65535", &min, &max);
    assert(result == 0);
    assert(min == 1024);
    assert(max == 65535);
    printf("  ✓ min=%u, max=%u\n\n", min, max);

    // Test 5: Invalid range (min > max)
    printf("Test 5: Invalid range '8080-8070' (min > max)\n");
    result = parse_port_range("8080-8070", &min, &max);
    assert(result == -1);
    printf("  ✓ Correctly rejected\n\n");

    // Test 6: Invalid range (zero in range)
    printf("Test 6: Invalid range '0-100' (zero in range)\n");
    result = parse_port_range("0-100", &min, &max);
    assert(result == -1);
    printf("  ✓ Correctly rejected\n\n");

    // Test 7: Single port at edge
    printf("Test 7: Single port '65535' (max port)\n");
    result = parse_port_range("65535", &min, &max);
    assert(result == 0);
    assert(min == 65535);
    assert(max == 65535);
    printf("  ✓ min=%u, max=%u\n\n", min, max);

    printf("All tests passed! ✓\n");
    return 0;
}
