/*
 * test_mmr.c — Unit tests for CKB MMR implementation
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../components/ckb_core/include/ckb_mmr.h"
#include "../components/ckb_core/include/ckb_types.h"

static int tests_run = 0;
static int tests_failed = 0;

static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("  %s: ", label);
    size_t i;
    for (i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

#define ASSERT_EQ_INT(label, got, expected) \
    do { \
        tests_run++; \
        if ((got) != (expected)) { \
            printf("FAIL: %s (got %llu, expected %llu)\n", \
                   label, (unsigned long long)(got), (unsigned long long)(expected)); \
            tests_failed++; \
        } else { printf("PASS: %s\n", label); } \
    } while(0)

#define ASSERT_EQ_BYTES(label, got, expected, len) \
    do { \
        tests_run++; \
        if (memcmp(got, expected, len) != 0) { \
            printf("FAIL: %s\n", label); \
            print_hex("  got     ", (const uint8_t*)(got), len); \
            print_hex("  expected", (const uint8_t*)(expected), len); \
            tests_failed++; \
        } else { printf("PASS: %s\n", label); } \
    } while(0)

static void test_leaf_pos(void) {
    /* Leaf 0 → pos 0, leaf 1 → pos 1, leaf 2 → pos 3, leaf 3 → pos 4 */
    ASSERT_EQ_INT("leaf 0 → pos 0", ckb_mmr_leaf_index_to_pos(0), 0);
    ASSERT_EQ_INT("leaf 1 → pos 1", ckb_mmr_leaf_index_to_pos(1), 1);
    ASSERT_EQ_INT("leaf 2 → pos 3", ckb_mmr_leaf_index_to_pos(2), 3);
    ASSERT_EQ_INT("leaf 3 → pos 4", ckb_mmr_leaf_index_to_pos(3), 4);
    ASSERT_EQ_INT("leaf 4 → pos 7", ckb_mmr_leaf_index_to_pos(4), 7);
}

static void test_peak_count(void) {
    ASSERT_EQ_INT("peak_count(1)  = 1", ckb_mmr_peak_count(1),  1);
    ASSERT_EQ_INT("peak_count(2)  = 1", ckb_mmr_peak_count(2),  1);
    ASSERT_EQ_INT("peak_count(3)  = 2", ckb_mmr_peak_count(3),  2);
    ASSERT_EQ_INT("peak_count(4)  = 1", ckb_mmr_peak_count(4),  1);
    ASSERT_EQ_INT("peak_count(11) = 3", ckb_mmr_peak_count(11), 3);
    ASSERT_EQ_INT("peak_count(8)  = 1", ckb_mmr_peak_count(8),  1);
}

static void test_mmr_merge_deterministic(void) {
    /* Merging two identical nodes should produce a deterministic result */
    ckb_header_digest_t left, right, merged;
    memset(&left,  0, sizeof(left));
    memset(&right, 0, sizeof(right));

    /* Set left hash to all-1 */
    memset(left.children_hash,  0x01, 32);
    memset(right.children_hash, 0x02, 32);
    left.start_number  = 0;  left.end_number  = 0;
    right.start_number = 1;  right.end_number = 1;
    left.start_compact_target  = 0x1a000000;
    right.start_compact_target = 0x1a000000;
    left.end_compact_target    = 0x1a000000;
    right.end_compact_target   = 0x1a000000;

    int ret = ckb_mmr_merge(&left, &right, &merged);
    ASSERT_EQ_INT("ckb_mmr_merge returns 0", ret, 0);

    /* merged.start_number should be left.start_number = 0 */
    ASSERT_EQ_INT("merged.start_number = 0", merged.start_number, 0);
    /* merged.end_number should be right.end_number = 1 */
    ASSERT_EQ_INT("merged.end_number = 1",   merged.end_number,   1);

    /* merged.children_hash should be Blake2b(left.hash || right.hash) */
    uint8_t expected_hash[32];
    ckb_blake2b_256_2(left.children_hash, 32, right.children_hash, 32, expected_hash);
    ASSERT_EQ_BYTES("merged.children_hash = Blake2b(l||r)",
                    merged.children_hash, expected_hash, 32);

    printf("  merged hash: ");
    size_t i;
    for (i = 0; i < 32; i++) printf("%02x", merged.children_hash[i]);
    printf("\n");
}

static void test_bag_peaks_single(void) {
    ckb_hash_t peak;
    memset(peak, 0xAB, 32);
    ckb_hash_t root;
    int ret = ckb_mmr_bag_peaks(&peak, 1, root);
    ASSERT_EQ_INT("bag_peaks single returns 0", ret, 0);
    ASSERT_EQ_BYTES("bag_peaks single = peak", root, peak, 32);
}

static void test_bag_peaks_two(void) {
    /* bag(left, right) = Blake2b(left || right) */
    ckb_hash_t peaks[2];
    memset(peaks[0], 0x11, 32);
    memset(peaks[1], 0x22, 32);

    uint8_t expected[32];
    /* Bag right-to-left: acc = right, then merge(left, acc) */
    ckb_blake2b_256_2(peaks[0], 32, peaks[1], 32, expected);

    ckb_hash_t root;
    int ret = ckb_mmr_bag_peaks(peaks, 2, root);
    ASSERT_EQ_INT("bag_peaks two returns 0", ret, 0);
    ASSERT_EQ_BYTES("bag_peaks two = Blake2b(l||r)", root, expected, 32);
}

static void test_u256_add(void) {
    uint8_t a[32] = {0}; a[0] = 0xFF;
    uint8_t b[32] = {0}; b[0] = 0x01;
    int carry = ckb_u256_add(a, b);
    ASSERT_EQ_INT("u256 0xFF + 0x01 carry=0, a[0]=0", a[0], 0);
    ASSERT_EQ_INT("u256 0xFF + 0x01 a[1]=1",           a[1], 1);
    ASSERT_EQ_INT("u256 0xFF + 0x01 carry=0",          carry, 0);
}

static void test_compact_target(void) {
    /* 0x1a01d4ae is a common mainnet compact target */
    uint8_t target[32];
    ckb_compact_to_target(0x1a01d4ae, target);
    printf("  compact 0x1a01d4ae → ");
    size_t i;
    for (i = 31; i >= 1; i--) if (target[i]) break;
    for (; i < 32; i++) printf("%02x", target[31 - i]);
    printf("\n");
    tests_run++;
    printf("PASS: compact_to_target executes\n");
}

static void test_flyclient_sample_count(void) {
    ckb_flyclient_params_t p;
    p.adversary_ratio = 0.5;
    p.security_bits   = 40.0;
    p.leaf_count      = 18000000;
    uint32_t m = ckb_flyclient_sample_count(&p);
    printf("  FlyClient samples needed (c=0.5, λ=40, n=18M): %u\n", m);
    tests_run++;
    if (m >= 10 && m <= 128)
        printf("PASS: flyclient_sample_count in range\n");
    else {
        printf("FAIL: flyclient_sample_count out of range (%u)\n", m);
        tests_failed++;
    }
}

static void test_header_serialise_roundtrip(void) {
    ckb_header_t h;
    memset(&h, 0, sizeof(h));
    h.version        = 0;
    h.compact_target = 0x1a01d4ae;
    h.timestamp      = 1614000000000ULL;
    h.number         = 12345678;
    h.epoch          = 0x000400280002eaULL;
    memset(h.parent_hash, 0xAA, 32);
    memset(h.transactions_root, 0xBB, 32);
    memset(h.dao, 0xCC, 32);
    memset(h.nonce, 0x42, 16);

    uint8_t buf[CKB_HEADER_SIZE];
    ckb_header_t h2;

    int r1 = ckb_header_serialize(&h, buf);
    int r2 = ckb_header_deserialize(buf, &h2);

    ASSERT_EQ_INT("header_serialize returns 0",   r1, 0);
    ASSERT_EQ_INT("header_deserialize returns 0", r2, 0);
    ASSERT_EQ_INT("roundtrip: version",         h2.version,        h.version);
    ASSERT_EQ_INT("roundtrip: compact_target",  h2.compact_target, h.compact_target);
    ASSERT_EQ_INT("roundtrip: number",          h2.number,         h.number);
    ASSERT_EQ_BYTES("roundtrip: parent_hash",   h2.parent_hash, h.parent_hash, 32);
    ASSERT_EQ_BYTES("roundtrip: dao",           h2.dao, h.dao, 32);
}

int main(void) {
    printf("=== CKB MMR & Types Unit Tests ===\n\n");

    test_leaf_pos();
    test_peak_count();
    test_mmr_merge_deterministic();
    test_bag_peaks_single();
    test_bag_peaks_two();
    test_u256_add();
    test_compact_target();
    test_flyclient_sample_count();
    test_header_serialise_roundtrip();

    printf("\n=== Results: %d/%d passed ===\n",
           tests_run - tests_failed, tests_run);
    return tests_failed > 0 ? 1 : 0;
}
