/*
 * ckb_mmr.h — Merkle Mountain Range proof verifier for CKB
 *
 * Implements the MMR verification required by RFC 0044 (CKB Light Client).
 * The light client uses FlyClient-style probabilistic verification:
 * only a logarithmic number of headers need to be checked.
 *
 * Key operations:
 *   1. Verify an MMR proof: given a leaf (HeaderDigest) and a proof path,
 *      confirm the leaf is included in the MMR with a given root.
 *   2. Verify the chain root stored in a block's extra_hash.
 *   3. Compute a HeaderDigest for a leaf node.
 */

#ifndef CKB_MMR_H
#define CKB_MMR_H

#include "ckb_types.h"
#include "ckb_blake2b.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum MMR proof length.
 * For 18M blocks: ceil(log2(18M)) ≈ 25 peaks + proof siblings.
 * 64 is conservative headroom. */
#define CKB_MMR_MAX_PROOF_ITEMS  64

/* ── MMR leaf position helpers ── */

/**
 * Convert a block number (0-indexed leaf index) to MMR position.
 * MMR positions are 0-indexed in insertion order.
 */
uint64_t ckb_mmr_leaf_index_to_pos(uint64_t index);

/**
 * Count the number of peaks in an MMR with `leaf_count` leaves.
 */
uint32_t ckb_mmr_peak_count(uint64_t leaf_count);

/* ── HeaderDigest computation ── */

/**
 * Compute the children_hash of a leaf MMR node from a block header.
 * For a leaf: children_hash = header_hash
 * (i.e., the block header hash itself)
 */
void ckb_mmr_leaf_digest(const ckb_hash_t header_hash,
                          ckb_header_digest_t *out);

/**
 * Compute the parent HeaderDigest from two child digests.
 * parent.children_hash = Blake2b(left.children_hash || right.children_hash)
 * parent.total_difficulty = left.total_difficulty + right.total_difficulty
 * parent.start_* = left.start_*
 * parent.end_*   = right.end_*
 */
int ckb_mmr_merge(const ckb_header_digest_t *left,
                  const ckb_header_digest_t *right,
                  ckb_header_digest_t *out);

/* ── MMR Proof ── */

/**
 * A single MMR inclusion proof.
 *
 * To verify a leaf at position `leaf_pos` in an MMR with `leaf_count` leaves:
 *   - `proof_items` are the sibling/peak hashes needed to recompute the root
 *   - `proof_len` is the number of items
 *
 * The proof format follows the ckb-light-client reference implementation:
 * items are ordered from leaf sibling up to peak, then remaining peaks
 * are bagged right-to-left.
 */
typedef struct {
    uint64_t    leaf_count;                              /* total leaves in MMR */
    uint64_t    leaf_pos;                                /* position of the leaf */
    ckb_hash_t  proof_items[CKB_MMR_MAX_PROOF_ITEMS];   /* sibling hashes */
    uint32_t    proof_len;
} ckb_mmr_proof_t;

/**
 * Verify that `leaf` is included in the MMR with root `expected_root`.
 *
 * @param proof         The inclusion proof
 * @param leaf          The HeaderDigest of the leaf being proven
 * @param expected_root The MMR root hash to verify against
 *
 * @return 0 if valid, -1 if invalid or error
 */
int ckb_mmr_verify(const ckb_mmr_proof_t *proof,
                   const ckb_header_digest_t *leaf,
                   const ckb_hash_t expected_root);

/**
 * Compute the MMR root from a set of peak hashes (bagging).
 * Peaks must be in left-to-right order.
 * Result is written to `root_out`.
 */
int ckb_mmr_bag_peaks(const ckb_hash_t *peaks, uint32_t peak_count,
                      ckb_hash_t root_out);

/* ── Verifiable Header ── */

/**
 * A "verifiable header" as defined in RFC 0044:
 * Contains the header, uncles_hash, extension, and the parent chain root.
 */
typedef struct {
    ckb_header_t header;
    ckb_hash_t   uncles_hash;
    uint8_t     *extension;      /* nullable, variable length */
    uint32_t     extension_len;
    ckb_hash_t   parent_chain_root; /* MMR root of parent block */
} ckb_verifiable_header_t;

/**
 * Verify that a verifiable header's extra_hash field is consistent
 * with the uncles_hash, extension, and parent_chain_root.
 *
 * extra_hash = Blake2b(uncles_hash || extension_hash || chain_root_hash)
 * where extension_hash = Blake2b(extension) if extension present, else 0x00..
 *
 * @return 0 if valid, -1 if invalid
 */
int ckb_verify_extra_hash(const ckb_verifiable_header_t *vh);

/* ── FlyClient sampling ── */

/**
 * Parameters for FlyClient block sampling.
 * See RFC 0044 §"The FlyClient Sampling Protocol".
 */
typedef struct {
    double   adversary_ratio;   /* c: fraction of adversary's hashrate (e.g. 0.5) */
    double   security_bits;     /* lambda: desired security bits (e.g. 40) */
    uint64_t leaf_count;        /* total blocks to sample from */
} ckb_flyclient_params_t;

/**
 * Compute the minimum number of block samples needed for security.
 * Returns the sample count m.
 */
uint32_t ckb_flyclient_sample_count(const ckb_flyclient_params_t *params);

#ifdef __cplusplus
}
#endif

#endif /* CKB_MMR_H */
