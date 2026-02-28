#pragma once
#include <stdint.h>
#include <stdbool.h>

// =============================================================================
// merkle.h — Transaction inclusion proof verification
//
// CKB uses a binary Merkle tree with Blake2b-256 leaves.
// A proof is a set of sibling hashes from leaf to root.
// We verify: hash(proof path) == transactions_root in header.
//
// Disabled at compile time if LIGHT_NO_MERKLE is defined.
// =============================================================================

#ifndef LIGHT_NO_MERKLE

#define MERKLE_MAX_PROOF_DEPTH  32   // supports trees up to 2^32 leaves

typedef struct {
  uint8_t  siblings[MERKLE_MAX_PROOF_DEPTH][32];  // sibling hashes
  uint8_t  indices[MERKLE_MAX_PROOF_DEPTH];        // 0=left, 1=right at each level
  uint8_t  depth;                                  // number of levels
} MerkleProof;

class Merkle {
public:
  // Verify a transaction is included in a block
  // txHash:   32-byte tx hash (leaf)
  // proof:    sibling path from leaf to root
  // root:     expected transactions_root from verified block header
  // Returns true if proof is valid
  static bool verify(
    const uint8_t* txHash,
    const MerkleProof& proof,
    const uint8_t* expectedRoot
  );

  // Parse a Merkle proof from JSON (as returned by light client RPC)
  static bool parseProof(const char* json, MerkleProof& out);

private:
  // Blake2b-256 of (left || right)
  static void hashPair(
    const uint8_t* left,
    const uint8_t* right,
    uint8_t* out
  );
};

#endif // LIGHT_NO_MERKLE
