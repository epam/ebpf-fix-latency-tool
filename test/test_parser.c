#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "fixlat.skel.h"
#include "fixlat.h"

#define SOH 0x01
#define TEST_BUFFER_SIZE 4096
#define MAX_TAG11_PER_PKT 4

/* Color codes for test output */
#define COLOR_GREEN "\033[32m"
#define COLOR_RED "\033[31m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_RESET "\033[0m"

static int test_count = 0;
static int test_passed = 0;
static int test_failed = 0;

/* Simple packet builder */
struct packet_builder {
    unsigned char buf[TEST_BUFFER_SIZE];
    size_t offset;
};

static void pb_init(struct packet_builder *pb) {
    memset(pb->buf, 0, sizeof(pb->buf));
    pb->offset = 0;
}

static void pb_add_eth_header(struct packet_builder *pb) {
    struct ethhdr *eth = (struct ethhdr *)(pb->buf + pb->offset);
    memset(eth->h_dest, 0xff, ETH_ALEN);    // broadcast
    memset(eth->h_source, 0x00, ETH_ALEN);  // fake source
    eth->h_proto = htons(ETH_P_IP);
    pb->offset += sizeof(struct ethhdr);
}

static void pb_add_ip_header(struct packet_builder *pb, uint16_t payload_len) {
    struct iphdr *ip = (struct iphdr *)(pb->buf + pb->offset);
    ip->ihl = 5;  // 20 bytes
    ip->version = 4;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len);
    ip->protocol = IPPROTO_TCP;
    ip->saddr = inet_addr("192.168.1.1");
    ip->daddr = inet_addr("192.168.1.2");
    pb->offset += sizeof(struct iphdr);
}

static void pb_add_tcp_header(struct packet_builder *pb, uint16_t sport, uint16_t dport) {
    struct tcphdr *tcp = (struct tcphdr *)(pb->buf + pb->offset);
    tcp->source = htons(sport);
    tcp->dest = htons(dport);
    tcp->doff = 5;  // 20 bytes
    tcp->psh = 1;   // Push flag
    pb->offset += sizeof(struct tcphdr);
}

static void pb_add_payload(struct packet_builder *pb, const char *data, size_t len) {
    memcpy(pb->buf + pb->offset, data, len);
    pb->offset += len;
}

/* Build a complete packet with FIX message */
static size_t build_fix_packet(unsigned char *buf, const char *fix_msg) {
    struct packet_builder pb;
    pb_init(&pb);

    size_t fix_len = strlen(fix_msg);
    pb_add_eth_header(&pb);
    pb_add_ip_header(&pb, fix_len);
    pb_add_tcp_header(&pb, 12345, 9999);
    pb_add_payload(&pb, fix_msg, fix_len);

    memcpy(buf, pb.buf, pb.offset);
    return pb.offset;
}

/* Test harness */
static void run_test(const char *name,
                     struct fixlat_bpf *skel,
                     const unsigned char *pkt,
                     size_t pkt_len,
                     const char **expected_tags,
                     int expected_count) {
    test_count++;
    printf("[TEST %d] %s... ", test_count, name);
    fflush(stdout);

    /* Clear the queue before test */
    int queue_fd = bpf_map__fd(skel->maps.pending_q);
    struct pending_req dummy;
    while (bpf_map_lookup_and_delete_elem(queue_fd, NULL, &dummy) == 0) {
        // drain queue
    }

    /* Run the BPF program - test tag parser directly instead of filter
     * since tail calls may not work with bpf_prog_test_run */
    LIBBPF_OPTS(bpf_test_run_opts, opts,
        .data_in = pkt,
        .data_size_in = pkt_len,
        .repeat = 1,
    );

    /* Set up ctx->cb for tag parser (simulate what filter would do) */
    /* Calculate payload offset: eth + ip + tcp headers */
    __u32 payload_offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);

    /* For test_run, we need to pass cb values in ctx_in */
    struct {
        __u32 cb[5];
    } ctx_cb = {0};
    ctx_cb.cb[0] = payload_offset;
    ctx_cb.cb[1] = 32;  // MAX_TAIL_CALLS

    opts.ctx_in = &ctx_cb;
    opts.ctx_size_in = sizeof(ctx_cb);

    int prog_fd = bpf_program__fd(skel->progs.tc_tag_parser);
    int err = bpf_prog_test_run_opts(prog_fd, &opts);

    if (err != 0) {
        printf(COLOR_RED "FAILED" COLOR_RESET " - bpf_prog_test_run failed: %s\n", strerror(errno));
        test_failed++;
        return;
    }

    /* Verify results by reading from pending_q */
    struct pending_req results[MAX_TAG11_PER_PKT];
    int found = 0;

    for (int i = 0; i < MAX_TAG11_PER_PKT; i++) {
        if (bpf_map_lookup_and_delete_elem(queue_fd, NULL, &results[found]) == 0) {
            found++;
        } else {
            break;
        }
    }

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
    struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &rl);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    printf("=== eBPF FIX Parser Unit Tests ===\n\n");

    /* Load BPF program */
    struct fixlat_bpf *skel = fixlat_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    if (fixlat_bpf__load(skel)) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        fixlat_bpf__destroy(skel);
        return 1;
    }

    /* Set up prog_array for tail calls */
    int prog_array_fd = bpf_map__fd(skel->maps.prog_array);
    int tag_parser_fd = bpf_program__fd(skel->progs.tc_tag_parser);
    __u32 prog_idx = 0;
    if (bpf_map_update_elem(prog_array_fd, &prog_idx, &tag_parser_fd, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to setup prog_array\n");
        fixlat_bpf__destroy(skel);
        return 1;
    }

    unsigned char pkt_buf[TEST_BUFFER_SIZE];
    size_t pkt_len;

    /* TEST 1: Simple FIX message with one tag 11 */
    {
        const char *fix = "8=FIX.4.2\x01" "11=ORDER123\x01" "35=D\x01";
        const char *expected[] = {"ORDER123"};
        pkt_len = build_fix_packet(pkt_buf, fix);
        run_test("Single tag 11", skel, pkt_buf, pkt_len, expected, 1);
    }

    /* TEST 2: Multiple tag 11 in same packet */
    {
        const char *fix = "8=FIX.4.2\x01" "11=ABC\x01" "35=D\x01" "11=XYZ\x01";
        const char *expected[] = {"ABC", "XYZ"};
        pkt_len = build_fix_packet(pkt_buf, fix);
        run_test("Multiple tag 11", skel, pkt_buf, pkt_len, expected, 2);
    }

    /* TEST 3: Tag 11 with numeric value */
    {
        const char *fix = "8=FIX.4.2\x01" "11=123456789\x01" "35=D\x01";
        const char *expected[] = {"123456789"};
        pkt_len = build_fix_packet(pkt_buf, fix);
        run_test("Numeric tag 11", skel, pkt_buf, pkt_len, expected, 1);
    }

    /* TEST 4: Empty tag 11 (should be ignored) */
    {
        const char *fix = "8=FIX.4.2\x01" "11=\x01" "35=D\x01";
        const char *expected[] = {};
        pkt_len = build_fix_packet(pkt_buf, fix);
        run_test("Empty tag 11", skel, pkt_buf, pkt_len, expected, 0);
    }

    /* TEST 5: Tag 11 at max length */
    {
        char fix[256];
        char long_id[FIXLAT_MAX_TAGVAL_LEN + 1];
        memset(long_id, 'A', FIXLAT_MAX_TAGVAL_LEN);
        long_id[FIXLAT_MAX_TAGVAL_LEN] = '\0';
        snprintf(fix, sizeof(fix), "8=FIX.4.2\x01" "11=%s\x01" "35=D\x01", long_id);
        const char *expected[] = {long_id};
        pkt_len = build_fix_packet(pkt_buf, fix);
        run_test("Max length tag 11", skel, pkt_buf, pkt_len, expected, 1);
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

        pkt_len = build_fix_packet(pkt_buf, fix);
        run_test("Truncated tag 11", skel, pkt_buf, pkt_len, expected, 1);
    }

    /* TEST 7: Non-FIX packet (should skip) */
    {
        const char *http = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        const char *expected[] = {};
        pkt_len = build_fix_packet(pkt_buf, http);
        run_test("Non-FIX packet", skel, pkt_buf, pkt_len, expected, 0);
    }

    /* TEST 8: FIX message without tag 11 */
    {
        const char *fix = "8=FIX.4.2\x01" "35=D\x01" "49=SENDER\x01";
        const char *expected[] = {};
        pkt_len = build_fix_packet(pkt_buf, fix);
        run_test("FIX without tag 11", skel, pkt_buf, pkt_len, expected, 0);
    }

    /* TEST 9: Tag 11 with special characters */
    {
        const char *fix = "8=FIX.4.2\x01" "11=ORD-2024.01\x01" "35=D\x01";
        const char *expected[] = {"ORD-2024.01"};
        pkt_len = build_fix_packet(pkt_buf, fix);
        run_test("Tag 11 with special chars", skel, pkt_buf, pkt_len, expected, 1);
    }

    /* TEST 10: Tag 110 and 111 (should not match tag 11) */
    {
        const char *fix = "8=FIX.4.2\x01" "110=100\x01" "111=200\x01" "35=D\x01";
        const char *expected[] = {};
        pkt_len = build_fix_packet(pkt_buf, fix);
        run_test("Tag 110/111 not matching", skel, pkt_buf, pkt_len, expected, 0);
    }

    fixlat_bpf__destroy(skel);

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
