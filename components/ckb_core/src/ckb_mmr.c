/*
 * ckb_mmr.c — Merkle Mountain Range proof verifier
 *
 * MMR position numbering follows the CKB reference implementation:
 * leaves and internal nodes are numbered in insertion order (0-indexed).
 *
 * Example MMR with 11 leaves (positions 0..17, nodes 18):
 *
 *          14
 *       /       \
 *     6          13
 *   /   \       /   \
 *  2     5     9     12     17
 * / \   /  \  / \   /  \   /  \
 * 0   1 3   4 7   8 10  11 15  16 18
 *
 * Peaks: {14, 17, 18}  →  bag right-to-left → root
 */

#include "ckb_mmr.h"
#include "ckb_blake2b.h"
#include <string.h>
#include <math.h>

/* ── Low-level MMR position math ── */

/* Count trailing zeros of a 64-bit integer */
static uint32_t ctz64(uint64_t x) {
    if (x == 0) return 64;
    uint32_t n = 0;
    if ((x & 0xFFFFFFFFULL) == 0) { n += 32; x >>= 32; }
    if ((x & 0x0000FFFFULL) == 0) { n += 16; x >>= 16; }
    if ((x & 0x000000FFULL) == 0) { n +=  8; x >>=  8; }
    if ((x & 0x0000000FULL) == 0) { n +=  4; x >>=  4; }
    if ((x & 0x00000003ULL) == 0) { n +=  2; x >>=  2; }
    if ((x & 0x00000001ULL) == 0) { n +=  1; }
    return n;
}

/* Count ones in a 64-bit integer (popcount) */
static uint32_t popcount64(uint64_t x) {
    x = x - ((x >> 1) & 0x5555555555555555ULL);
    x = (x & 0x3333333333333333ULL) + ((x >> 2) & 0x3333333333333333ULL);
    x = (x + (x >> 4)) & 0x0f0f0f0f0f0f0f0fULL;
    return (uint32_t)((x * 0x0101010101010101ULL) >> 56);
}

/* Height of the node at position `pos` in the MMR tree */
static uint32_t mmr_node_height(uint64_t pos) {
    /* pos is 0-indexed; height of a leaf is 0 */
    pos += 1; /* convert to 1-indexed for the bit trick */
    while (!((pos) & ~((pos) - 1))) {
        pos += 1;
    }
    return (uint32_t)ctz64(pos) ;
}

/* Number of MMR nodes (positions) for `leaf_count` leaves */
static uint64_t mmr_size(uint64_t leaf_count) {
    if (leaf_count == 0) return 0;
    uint64_t n = leaf_count;
    uint64_t size = 0;
    while (n > 0) {
        uint32_t h = 63 - __builtin_clzll(n); /* floor(log2(n)) */
        size += (1ULL << (h + 1)) - 1;
        n -= (1ULL << h);
    }
    return size;
}

/* Position of the leaf with given 0-indexed leaf number */
uint64_t ckb_mmr_leaf_index_to_pos(uint64_t index) {
    /* Each leaf insertion adds 1 + (number of right merges) nodes.
     * Simple formula: mmr_size(index) gives position of leaf `index`. */
    return mmr_size(index);
}

/* Count peaks in an MMR with leaf_count leaves */
uint32_t ckb_mmr_peak_count(uint64_t leaf_count) {
    return popcount64(leaf_count);
}

/* ── Hashing ── */

/* Hash two MMR node hashes together: Blake2b(left || right) */
static int mmr_merge_hashes(const ckb_hash_t left, const ckb_hash_t right,
                              ckb_hash_t out) {
    return ckb_blake2b_256_2(left, 32, right, 32, out);
}

/* ── HeaderDigest operations ── */

void ckb_mmr_leaf_digest(const ckb_hash_t header_hash,
                          ckb_header_digest_t *out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    memcpy(out->children_hash, header_hash, 32);
    /* Other fields (total_difficulty, number ranges, etc.) must be
     * populated from the actual block header by the caller. */
}

int ckb_mmr_merge(const ckb_header_digest_t *left,
                  const ckb_header_digest_t *right,
                  ckb_header_digest_t *out) {
    if (!left || !right || !out) return -1;

    /* children_hash = Blake2b(left.children_hash || right.children_hash) */
    if (mmr_merge_hashes(left->children_hash, right->children_hash,
                          out->children_hash) < 0) return -1;

    /* total_difficulty = left + right (256-bit LE addition) */
    memcpy(out->total_difficulty, left->total_difficulty, 32);
    ckb_u256_add(out->total_difficulty, right->total_difficulty);

    /* Range: take start from left, end from right */
    out->start_number        = left->start_number;
    out->end_number          = right->end_number;
    out->start_epoch         = left->start_epoch;
    out->end_epoch           = right->end_epoch;
    out->start_timestamp     = left->start_timestamp;
    out->end_timestamp       = right->end_timestamp;
    out->start_compact_target = left->start_compact_target;
    out->end_compact_target  = right->end_compact_target;

    return 0;
}

/* ── MMR Proof verification ── */

/*
 * Compute peaks from leaf_count.
 * Fills `peak_positions[]` with the MMR positions of each peak,
 * in left-to-right order. Returns peak count.
 */
static uint32_t compute_peaks(uint64_t leaf_count,
                               uint64_t peak_positions[64]) {
    uint32_t count = 0;
    uint64_t n = leaf_count;
    uint64_t pos = 0;

    while (n > 0) {
        uint32_t h = 63 - __builtin_clzll(n); /* highest bit */
        uint64_t subtree_size = (1ULL << (h + 1)) - 1;
        peak_positions[count++] = pos + subtree_size - 1;
        pos += subtree_size;
        n -= (1ULL << h);
    }
    return count;
}

int ckb_mmr_bag_peaks(const ckb_hash_t *peaks, uint32_t peak_count,
                      ckb_hash_t root_out) {
    if (!peaks || peak_count == 0 || !root_out) return -1;

    if (peak_count == 1) {
        memcpy(root_out, peaks[0], 32);
        return 0;
    }

    /* Bag right-to-left: start from rightmost, merge leftward */
    ckb_hash_t acc;
    memcpy(acc, peaks[peak_count - 1], 32);

    int i;
    for (i = (int)peak_count - 2; i >= 0; i--) {
        if (mmr_merge_hashes(peaks[i], acc, acc) < 0) return -1;
    }
    memcpy(root_out, acc, 32);
    return 0;
}

int ckb_mmr_verify(const ckb_mmr_proof_t *proof,
                   const ckb_header_digest_t *leaf,
                   const ckb_hash_t expected_root) {
    if (!proof || !leaf || !expected_root) return -1;
    if (proof->proof_len > CKB_MMR_MAX_PROOF_ITEMS) return -1;

    uint64_t leaf_count = proof->leaf_count;
    uint64_t pos        = proof->leaf_pos;

    if (leaf_count == 0) return -1;

    /* Compute peak positions */
    uint64_t peak_positions[64];
    uint32_t peak_count = compute_peaks(leaf_count, peak_positions);

    /* Find which peak subtree contains our leaf */
    uint32_t peak_idx = 0;
    uint64_t peak_pos = 0;
    {
        uint32_t i;
        for (i = 0; i < peak_count; i++) {
            if (pos <= peak_positions[i]) {
                peak_pos = peak_positions[i];
                peak_idx = i;
                break;
            }
            if (i == peak_count - 1) return -1; /* leaf outside MMR */
        }
    }

    /* Walk up the proof path from leaf to peak */
    ckb_hash_t current;
    memcpy(current, leaf->children_hash, 32);

    uint32_t proof_used = 0;
    uint64_t cur_pos = pos;

    /* Height of the peak subtree */
    uint32_t peak_height = mmr_node_height(peak_pos);

    uint32_t height = 0;
    while (height < peak_height && proof_used < proof->proof_len) {
        /* Is current node a left or right child? */
        uint64_t sibling_offset = (2ULL << height) - 1;

        if (proof_used >= proof->proof_len) return -1;
        const uint8_t *sibling = proof->proof_items[proof_used++];

        ckb_hash_t parent;
        /* Left child has even height-adjusted offset; determine order */
        /* Right sibling is at cur_pos + sibling_offset,
         * left sibling is at cur_pos - sibling_offset */
        uint64_t right_pos = cur_pos + sibling_offset;
        if (right_pos <= peak_pos) {
            /* cur_pos is the left child */
            if (mmr_merge_hashes(current, sibling, parent) < 0) return -1;
            cur_pos = right_pos + 1; /* parent position */
        } else {
            /* cur_pos is the right child */
            if (mmr_merge_hashes(sibling, current, parent) < 0) return -1;
            cur_pos = cur_pos + sibling_offset + 1;
        }
        memcpy(current, parent, 32);
        height++;
    }

    /* current should now be the peak hash */
    /* Reconstruct root by bagging peaks, replacing our peak with `current` */
    /* First gather all peak hashes from proof (remaining items) */
    ckb_hash_t peak_hashes[64];
    uint32_t i;
    for (i = 0; i < peak_count; i++) {
        if (i == peak_idx) {
            memcpy(peak_hashes[i], current, 32);
        } else {
            /* Take from proof */
            if (proof_used >= proof->proof_len) return -1;
            memcpy(peak_hashes[i], proof->proof_items[proof_used++], 32);
        }
    }

    /* Bag peaks to get root */
    ckb_hash_t computed_root;
    if (ckb_mmr_bag_peaks(peak_hashes, peak_count, computed_root) < 0) return -1;

    /* Compare with expected root */
    return (memcmp(computed_root, expected_root, 32) == 0) ? 0 : -1;
}

/* ── Verifiable header ── */

int ckb_verify_extra_hash(const ckb_verifiable_header_t *vh) {
    if (!vh) return -1;

    ckb_blake2b_state S;
    uint8_t computed[32];

    /* extension_hash: Blake2b of extension bytes, or all-zero if absent */
    uint8_t extension_hash[32];
    if (vh->extension && vh->extension_len > 0) {
        if (ckb_blake2b_256(vh->extension, vh->extension_len,
                             extension_hash) < 0) return -1;
    } else {
        memset(extension_hash, 0, 32);
    }

    /* extra_hash = Blake2b(uncles_hash || extension_hash) */
    /* Note: for light client, chain root is encoded in the first 32 bytes
     * of the block extension field (post-MMR activation), not directly
     * in extra_hash. The extra_hash = Blake2b(uncles_hash || ext_hash). */
    if (ckb_blake2b_init_default(&S) < 0) return -1;
    if (ckb_blake2b_update(&S, vh->uncles_hash, 32) < 0) return -1;
    if (ckb_blake2b_update(&S, extension_hash, 32) < 0) return -1;
    if (ckb_blake2b_final(&S, computed, 32) < 0) return -1;

    return (memcmp(computed, vh->header.extra_hash, 32) == 0) ? 0 : -1;
}

/* ── FlyClient sampling ── */

uint32_t ckb_flyclient_sample_count(const ckb_flyclient_params_t *params) {
    if (!params || params->leaf_count == 0) return 0;
    if (params->adversary_ratio <= 0.0 || params->adversary_ratio >= 1.0) return 0;

    double c = params->adversary_ratio;
    double lambda = params->security_bits;

    /* delta = c^k where k = 1/p, p = catch probability per sample
     * Using simplified: m >= lambda / log2(1/(1 - 1/k))
     * For practical embedded use, we use a conservative fixed formula:
     * m = ceil(lambda / log2(1/c)) + 1
     * This is a safe over-approximation. */
    double log_inv_c = -log2(c);
    if (log_inv_c <= 0) return 128; /* fallback */

    uint32_t m = (uint32_t)(lambda / log_inv_c) + 2;
    if (m < 10) m = 10;   /* minimum 10 samples */
    if (m > 128) m = 128; /* cap for embedded */
    return m;
}
