#pragma once
#include <stdint.h>
#include <stdbool.h>

// =============================================================================
// merkle.h — CKB Complete Binary Merkle Tree (CBMT) proof verification
//
// RFC 0006 — Merkle Tree for Static Data
// https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0006-merkle-tree
//
// CKB uses CBMT (not a standard binary Merkle tree). Key differences:
//
//   Indexing: top-to-bottom, left-to-right, root = 0
//             n items → 2n-1 nodes, item i at index (i + n - 1)
//   Parent:   (i - 1) / 2
//   Sibling:  ((i + 1) ^ 1) - 1
//   Is left:  (i & 1) == 1  (odd index = left child)
//
//   Merge:    Blake2b-256(left[32] || right[32], "ckb-default-hash")
//
// RPC: get_transaction_proof returns:
//   proof.indices:  uint32[] — tree node index of tx (ascending by item hash)
//   proof.lemmas:   H256[]   — sibling hashes (descending by index)
//                  (NOTE: called "lemmas" in CKB RPC, not "siblings")
//   witnesses_root: H256     — separate witness tree root
//
// IMPORTANT: header.transactions_root ≠ CBMT root of tx hashes!
//   transactions_root = merge(txs_CBMT_root, witnesses_root)
//
// So full verification is:
//   1. verify CBMT proof → txs_CBMT_root
//   2. merge(txs_CBMT_root, witnesses_root) == header.transactions_root
//
// Disabled at compile time if LIGHT_NO_MERKLE is defined.
// =============================================================================

#ifndef LIGHT_NO_MERKLE

// Max depth = max proof siblings needed for 2^32 leaf tree
#define MERKLE_MAX_PROOF_DEPTH  32

typedef struct {
    uint32_t indices[MERKLE_MAX_PROOF_DEPTH];    // tree node indices (ascending by hash)
    uint8_t  lemmas[MERKLE_MAX_PROOF_DEPTH][32];  // sibling hashes, "lemmas" in CKB RPC
    uint8_t  depth;                               // number of lemmas
} MerkleProof;

class Merkle {
public:
    // Verify a transaction's inclusion in a block's CBMT.
    //
    // txHash:        32-byte transaction hash (the leaf value)
    // proof:         parsed CBMT proof (indices + lemmas)
    // txsCBMTRoot:   OUT — computed txs CBMT root (pass to verifyTransactionsRoot)
    //
    // Returns true if proof is valid; txsCBMTRoot is set to the computed root.
    static bool verify(
        const uint8_t*     txHash,
        const MerkleProof& proof,
        uint8_t*           txsCBMTRoot   // [32] out
    );

    // Full verification: txsCBMTRoot + witnesses_root must equal header.transactions_root
    // Call after verify() with the witnesses_root from get_transaction_proof RPC response.
    static bool verifyTransactionsRoot(
        const uint8_t* txsCBMTRoot,       // [32] from verify()
        const uint8_t* witnessesRoot,     // [32] from RPC
        const uint8_t* expectedRoot       // [32] from verified block header
    );

    // Combined convenience: verify CBMT proof then check against header root.
    // witnessesRoot: from get_transaction_proof RPC "witnesses_root" field
    // expectedRoot:  header.transactions_root from a verified block header
    static bool verifyInclusion(
        const uint8_t*     txHash,
        const MerkleProof& proof,
        const uint8_t*     witnessesRoot,
        const uint8_t*     expectedRoot
    );

    // Parse proof JSON from get_transaction_proof RPC.
    // Expected shape: { "indices": ["0x5"], "lemmas": ["0xabc...","0xdef..."] }
    // Returns false if malformed.
    static bool parseProof(const char* json, MerkleProof& out);
};

#endif // LIGHT_NO_MERKLE
