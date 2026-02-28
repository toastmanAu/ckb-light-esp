// =============================================================================
// test_merkle.cpp — Host-side tests for CBMT proof verification
//
// Test vector: CKB mainnet block #18,731,830 (4 txs)
// Verified against live node (192.168.68.87:8114)
//
// Build:
//   g++ -std=c++17 -I../src -I../../CKB-ESP32/src \
//       test_merkle.cpp ../src/core/merkle.cpp -o test_merkle
// Run:
//   ./test_merkle
// =============================================================================

#define IRAM_ATTR
#define LIGHT_HEADER_CACHE_SIZE  10
#define LIGHT_JSON_BUFFER_SIZE   4096

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "../../CKB-ESP32/src/ckb_blake2b.h"
#include "../src/core/merkle.h"

static int pass = 0, fail = 0;
#define CHECK(label, expr) do { \
    if (expr) { printf("PASS: %s\n", label); pass++; } \
    else       { printf("FAIL: %s\n", label); fail++; } \
} while(0)

static void hex_bytes(const char* h, uint8_t* out, int n) {
    if (h[0]=='0'&&h[1]=='x') h+=2;
    for (int i=0;i<n;i++){
        auto nib=[](char c){return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:c-'A'+10;};
        out[i]=(nib(h[i*2])<<4)|nib(h[i*2+1]);
    }
}

// ─── Test data from block #18,731,830 ────────────────────────────────────────
// get_transaction_proof for tx[2] in this 4-tx block

static const char* TX2_HASH       = "0x863420cbcdd1bd762d606c802e630a6fd15f8783c33e4487030af37e3c7eaae7";
static const char* TRANSACTIONS_ROOT = "0xfe14d9706c2a163a4d979d8898a77c48d98f9d6f5126859d81365f7e08c75396";
static const char* WITNESSES_ROOT = "0x782fb419b467929297cf2ed3af49eb6888a7dc21a29a2623bd9760fef9a1fdc6";

// Proof from RPC: indices=[0x5], lemmas=[T3, B1]
static const char* PROOF_JSON =
    "{"
    "\"indices\": [\"0x5\"],"
    "\"lemmas\": ["
    "  \"0xf48fd97880998d1a45763bddd466d2e7478c2eaebfcd85ee197cb816f5c323bc\","
    "  \"0x2876164697e46635bf9e0a8f39b517201e8c0c8e6ef52eefd4fbe4770cb947db\""
    "]"
    "}";

// ─── Tests ───────────────────────────────────────────────────────────────────

static void test_parse_proof() {
    MerkleProof proof;
    bool ok = Merkle::parseProof(PROOF_JSON, proof);
    CHECK("parseProof succeeds",           ok);
    CHECK("parseProof depth = 2",          proof.depth == 2);
    CHECK("parseProof indices[0] = 5",     proof.indices[0] == 5);

    uint8_t expected_lemma0[32], expected_lemma1[32];
    hex_bytes("0xf48fd97880998d1a45763bddd466d2e7478c2eaebfcd85ee197cb816f5c323bc", expected_lemma0, 32);
    hex_bytes("0x2876164697e46635bf9e0a8f39b517201e8c0c8e6ef52eefd4fbe4770cb947db", expected_lemma1, 32);
    CHECK("parseProof lemma[0] = T3",      memcmp(proof.lemmas[0], expected_lemma0, 32) == 0);
    CHECK("parseProof lemma[1] = B1",      memcmp(proof.lemmas[1], expected_lemma1, 32) == 0);
}

static void test_cbmt_verify() {
    MerkleProof proof;
    Merkle::parseProof(PROOF_JSON, proof);

    uint8_t txHash[32], txsCBMTRoot[32];
    hex_bytes(TX2_HASH, txHash, 32);

    bool ok = Merkle::verify(txHash, proof, txsCBMTRoot);
    CHECK("CBMT verify succeeds", ok);

    // Expected txs CBMT root (computed manually / confirmed in Python)
    uint8_t expected_cbmt_root[32];
    hex_bytes("0xc7826378f877ef27f3f21b3558afdc8bca8ad93fa2e2cdb7f0837daab18387c1", expected_cbmt_root, 32);
    CHECK("CBMT root correct", memcmp(txsCBMTRoot, expected_cbmt_root, 32) == 0);
}

static void test_transactions_root() {
    MerkleProof proof;
    Merkle::parseProof(PROOF_JSON, proof);

    uint8_t txHash[32], txsCBMTRoot[32];
    hex_bytes(TX2_HASH, txHash, 32);
    Merkle::verify(txHash, proof, txsCBMTRoot);

    uint8_t witnessesRoot[32], expectedRoot[32];
    hex_bytes(WITNESSES_ROOT,     witnessesRoot, 32);
    hex_bytes(TRANSACTIONS_ROOT,  expectedRoot,  32);

    bool ok = Merkle::verifyTransactionsRoot(txsCBMTRoot, witnessesRoot, expectedRoot);
    CHECK("transactions_root = merge(txsCBMTRoot, witnessesRoot)", ok);
}

static void test_full_inclusion() {
    MerkleProof proof;
    Merkle::parseProof(PROOF_JSON, proof);

    uint8_t txHash[32], witnessesRoot[32], expectedRoot[32];
    hex_bytes(TX2_HASH,          txHash,       32);
    hex_bytes(WITNESSES_ROOT,    witnessesRoot, 32);
    hex_bytes(TRANSACTIONS_ROOT, expectedRoot,  32);

    bool ok = Merkle::verifyInclusion(txHash, proof, witnessesRoot, expectedRoot);
    CHECK("verifyInclusion (end-to-end)", ok);
}

static void test_wrong_txhash_fails() {
    MerkleProof proof;
    Merkle::parseProof(PROOF_JSON, proof);

    // Use a different tx hash — should fail
    uint8_t wrongHash[32] = {0xDE,0xAD,0};
    uint8_t witnessesRoot[32], expectedRoot[32];
    hex_bytes(WITNESSES_ROOT,    witnessesRoot, 32);
    hex_bytes(TRANSACTIONS_ROOT, expectedRoot,  32);

    bool ok = Merkle::verifyInclusion(wrongHash, proof, witnessesRoot, expectedRoot);
    CHECK("wrong txHash correctly rejected", !ok);
}

static void test_single_tx_block() {
    // Single-tx block: CBMT root = tx hash, witnesses_root = witness_hash of that tx
    // transactions_root = merge(tx_hash, witness_hash)
    // Simulate with known values:
    uint8_t txHash[32]       = {0x01,0x02,0x03};
    uint8_t witnessHash[32]  = {0x04,0x05,0x06};

    // Compute expected transactions_root
    CKB_Blake2b ctx;
    uint8_t expectedRoot[32];
    ckb_blake2b_init(&ctx);
    ckb_blake2b_update(&ctx, txHash,      32);
    ckb_blake2b_update(&ctx, witnessHash, 32);
    ckb_blake2b_final(&ctx, expectedRoot);

    // Single-tx proof: depth=0, indices[0] doesn't matter
    MerkleProof proof;
    proof.depth = 0;
    proof.indices[0] = 0;  // only item, tree index = 0

    bool ok = Merkle::verifyInclusion(txHash, proof, witnessHash, expectedRoot);
    CHECK("single-tx block inclusion", ok);
}

int main() {
    printf("=== ckb-light-esp merkle tests ===\n\n");

    printf("--- parseProof ---\n");
    test_parse_proof();

    printf("\n--- CBMT verify ---\n");
    test_cbmt_verify();

    printf("\n--- transactions_root ---\n");
    test_transactions_root();

    printf("\n--- full inclusion ---\n");
    test_full_inclusion();
    test_wrong_txhash_fails();
    test_single_tx_block();

    printf("\n=== Results: %d passed, %d failed ===\n", pass, fail);
    return fail > 0 ? 1 : 0;
}
