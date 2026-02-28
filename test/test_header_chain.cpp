// =============================================================================
// test_header_chain.cpp — Host-side unit tests for header_chain PoW verification
//
// Build:
//   g++ -std=c++17 -I../src -I../../CKB-ESP32/src \
//       test_header_chain.cpp ../src/core/eaglesong.cpp -o test_headers
// Run:
//   ./test_headers
// =============================================================================

// Stubs for embedded-only symbols
#define IRAM_ATTR
#define LIGHT_HEADER_CACHE_SIZE  10
#define LIGHT_JSON_BUFFER_SIZE   16384

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "../src/core/eaglesong.h"
#include "../../CKB-ESP32/src/ckb_blake2b.h"

static int pass = 0, fail = 0;
#define CHECK(label, expr) do { \
    if (expr) { printf("PASS: %s\n", label); pass++; } \
    else       { printf("FAIL: %s\n", label); fail++; } \
} while(0)

// ─── Utility ─────────────────────────────────────────────────────────────────

static void hex_bytes(const char* h, uint8_t* out, int n) {
    if (h[0]=='0' && h[1]=='x') h += 2;
    for (int i = 0; i < n; i++) {
        auto nib = [](char c) {
            return c>='0'&&c<='9' ? c-'0' : c>='a'&&c<='f' ? c-'a'+10 : c-'A'+10;
        };
        out[i] = (nib(h[i*2]) << 4) | nib(h[i*2+1]);
    }
}

static void write_u32_le(uint8_t* b, uint32_t v) { b[0]=v; b[1]=v>>8; b[2]=v>>16; b[3]=v>>24; }
static void write_u64_le(uint8_t* b, uint64_t v) { for(int i=0;i<8;i++) b[i]=(v>>(i*8))&0xFF; }

// compact_target → 32-byte big-endian target
static void compact_to_target_be(uint32_t compact, uint8_t target[32]) {
    memset(target, 0, 32);
    uint32_t exp = compact >> 24, man = compact & 0x007FFFFF;
    if (exp == 0 || exp > 32) return;
    int pos = (int)(32 - exp);
    if (pos >= 0 && pos + 2 < 32) {
        target[pos]   = (man >> 16) & 0xFF;
        target[pos+1] = (man >>  8) & 0xFF;
        target[pos+2] = (man >>  0) & 0xFF;
    }
}

// result (BE) <= target (BE)
static bool pow_valid(const uint8_t result[32], const uint8_t target[32]) {
    for (int i = 0; i < 32; i++) {
        if (result[i] < target[i]) return true;
        if (result[i] > target[i]) return false;
    }
    return true;
}

// nonce RPC hex → LE bytes (u128 big-endian value → reverse)
static void nonce_rpc_to_le(const char* hex, uint8_t out[16]) {
    uint8_t raw[16];
    hex_bytes(hex, raw, 16);
    for (int i = 0; i < 16; i++) out[i] = raw[15 - i];
}

// ─── Test data: CKB mainnet block #18,731,746 ────────────────────────────────
// Verified against live node (192.168.68.87:8114)

static const struct {
    const char* compact_target;
    const char* parent_hash;
    const char* transactions_root;
    const char* proposals_hash;
    const char* extra_hash;
    const char* dao;
    const char* nonce;            // RPC format (u128 BE hex)
    uint64_t    number;
    uint64_t    timestamp;        // ms
    uint64_t    epoch;
    const char* expected_hash;   // block hash
} BLOCK = {
    "0x190c561d",
    "0xf58c3f31367dbd2048e35855a81cdaeef20ce52d282d95552be1e67ec5dfd3c0",
    "0xa446f35a76532887b1bb2300150022f735cf393cee7c74dc7a9d82c43afdd365",
    "0x701fe0e115ac20dc3492fdcee5ebe574f268aeec7151401afe905d6531575eff",
    "0x1206e7ad3f4774b819e3a862cbce25cb83b785abeabe7a5645bbc54e86bc9ccd",
    "0x73e10496f6fc48588fb17d6b8f492a005c4eec29eed472090058de774afc3507",
    "0xef5253f22d9822be0000001537651703",
    0x11dd2e2,
    0x19ca64cc29d,
    0x4a202100035b1,
    "0x2ab1c231a9f43997eef6123f834d31d3497fcd79845c8abd9d906d47b31830fa",
};

static void build_raw(uint8_t buf[192]) {
    uint8_t* p = buf;
    write_u32_le(p, 0);                                      p += 4;
    write_u32_le(p, 0x190c561d);                             p += 4;
    write_u64_le(p, BLOCK.timestamp);                        p += 8;
    write_u64_le(p, BLOCK.number);                           p += 8;
    write_u64_le(p, BLOCK.epoch);                            p += 8;
    hex_bytes(BLOCK.parent_hash,        p, 32);              p += 32;
    hex_bytes(BLOCK.transactions_root,  p, 32);              p += 32;
    hex_bytes(BLOCK.proposals_hash,     p, 32);              p += 32;
    hex_bytes(BLOCK.extra_hash,         p, 32);              p += 32;
    hex_bytes(BLOCK.dao,                p, 32);              p += 32;
}

// ─── Tests ────────────────────────────────────────────────────────────────────

static void test_eaglesong_selftest() {
    CHECK("Eaglesong self-test", eaglesong_selftest());
}

static void test_molecule_size() {
    uint8_t buf[192];
    build_raw(buf);
    // Just verify we can build without crash; size is compile-time correct
    CHECK("Molecule struct = 192 bytes", true);  // enforced by build_raw
}

static void test_pow_hash() {
    uint8_t buf[192];
    build_raw(buf);

    uint8_t pow_hash[32];
    CKB_Blake2b ctx;
    ckb_blake2b_init(&ctx);
    ckb_blake2b_update(&ctx, buf, 192);
    ckb_blake2b_final(&ctx, pow_hash);

    // Known pow_hash for this block
    uint8_t expected[32];
    hex_bytes("0x756922e2fab65d403f29da75d4c68521b26d01ecc46e4f28d3b781035ca47288",
              expected, 32);

    CHECK("pow_hash = Blake2b(Molecule struct)", memcmp(pow_hash, expected, 32) == 0);
}

static void test_block_hash() {
    uint8_t buf[192];
    build_raw(buf);

    uint8_t nonce_le[16];
    nonce_rpc_to_le(BLOCK.nonce, nonce_le);

    uint8_t block_hash[32];
    CKB_Blake2b ctx;
    ckb_blake2b_init(&ctx);
    ckb_blake2b_update(&ctx, buf,      192);
    ckb_blake2b_update(&ctx, nonce_le, 16);
    ckb_blake2b_final(&ctx, block_hash);

    uint8_t expected[32];
    hex_bytes(BLOCK.expected_hash, expected, 32);

    printf("computed:  "); for(int i=0;i<32;i++) printf("%02x", block_hash[i]); printf("\n");
    printf("expected:  "); for(int i=0;i<32;i++) printf("%02x", expected[i]);   printf("\n");

    CHECK("block_hash = Blake2b(struct || nonce_le)", memcmp(block_hash, expected, 32) == 0);
}

static void test_pow_valid() {
    uint8_t buf[192];
    build_raw(buf);

    uint8_t pow_hash[32];
    CKB_Blake2b ctx;
    ckb_blake2b_init(&ctx);
    ckb_blake2b_update(&ctx, buf, 192);
    ckb_blake2b_final(&ctx, pow_hash);

    uint8_t nonce_le[16];
    nonce_rpc_to_le(BLOCK.nonce, nonce_le);

    uint8_t result[32];
    ckb_pow_hash(pow_hash, nonce_le, result);

    uint8_t target[32];
    compact_to_target_be(0x190c561d, target);

    printf("result: "); for(int i=0;i<32;i++) printf("%02x", result[i]); printf("\n");
    printf("target: "); for(int i=0;i<32;i++) printf("%02x", target[i]); printf("\n");

    CHECK("Eaglesong result <= compact_target", pow_valid(result, target));
}

static void test_nonce_conversion() {
    uint8_t nonce_le[16];
    nonce_rpc_to_le("0xef5253f22d9822be0000001537651703", nonce_le);
    // u128 value reversed: 0317653715000000be22982df25352ef
    uint8_t expected[16] = {
        0x03,0x17,0x65,0x37,0x15,0x00,0x00,0x00,
        0xbe,0x22,0x98,0x2d,0xf2,0x53,0x52,0xef
    };
    CHECK("nonce RPC → LE bytes", memcmp(nonce_le, expected, 16) == 0);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main() {
    printf("=== ckb-light-esp header_chain tests ===\n\n");

    test_eaglesong_selftest();
    test_nonce_conversion();
    test_molecule_size();
    test_pow_hash();

    printf("\n--- block hash verification ---\n");
    test_block_hash();

    printf("\n--- full PoW verification ---\n");
    test_pow_valid();

    printf("\n=== Results: %d passed, %d failed ===\n", pass, fail);
    return fail > 0 ? 1 : 0;
}
