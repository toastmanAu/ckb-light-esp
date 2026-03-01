// =============================================================================
// merkle.cpp — CKB Complete Binary Merkle Tree (CBMT) proof verification
//
// RFC 0006: https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0006-merkle-tree
//
// CKB CBMT properties:
//   - Complete binary tree (all levels full except last, nodes left-packed)
//   - Full binary tree (every non-leaf has exactly two children)
//   - Array representation: 2n-1 nodes for n items
//   - Node indexing: top-to-bottom, left-to-right, starting at 0
//     Item i is at array index (i + n - 1) where n = number of items
//   - Parent of node i: (i-1)/2
//   - Sibling of node i: (i+1)^1 - 1  (XOR trick)
//   - Children of node i: 2i+1 (left), 2i+2 (right)
//
// Leaf hash: Blake2b-256(tx_hash, "ckb-default-hash") — but for tx inclusion,
//            the leaf IS the tx_hash (already hashed by the node)
//
// Merge rule: merge(left, right) = Blake2b-256(left || right)
//
// Proof structure (from RPC get_transaction with proof):
//   indices: array of uint32 — tree node indices (in ascending order by item hash)
//   siblings: array of H256 — sibling hashes (in descending order by index)
//
// Proof verification algorithm (from RFC 0006):
//   1. Build queue of (hash, index) pairs from (items, proof.indices)
//   2. Sort queue descending by index
//   3. Process queue:
//      a. Pop front (hash1, index1)
//      b. Check if sibling(index1) == index of queue.front()
//         - Yes: pop queue.front() as (hash2, index2), merge(hash2, hash1) → sibling consumed
//         - No: take next proof node as hash2, merge based on left/right position
//      c. Push (merged_hash, parent(index1)) back to queue
//   4. Final hash == root → valid
// =============================================================================

#include "merkle.h"
#include <ckb_blake2b.h>
#include <string.h>

#ifndef LIGHT_NO_MERKLE

// ─── CBMT index arithmetic ────────────────────────────────────────────────────

static inline uint32_t cbmt_parent(uint32_t i)   { return (i - 1) / 2; }
static inline uint32_t cbmt_sibling(uint32_t i)  { return ((i + 1) ^ 1) - 1; }
static inline bool     cbmt_is_left(uint32_t i)  { return (i & 1) == 1; }  // odd index = left child

// ─── Blake2b merge ────────────────────────────────────────────────────────────

static void cbmt_merge(const uint8_t* left, const uint8_t* right, uint8_t* out) {
    CKB_Blake2b ctx;
    ckb_blake2b_init(&ctx);
    ckb_blake2b_update(&ctx, left,  32);
    ckb_blake2b_update(&ctx, right, 32);
    ckb_blake2b_final(&ctx, out);
}

// ─── Simple queue for proof verification ─────────────────────────────────────
// Fixed-size queue of (hash, index) pairs — max depth bounded by MERKLE_MAX_PROOF_DEPTH

typedef struct {
    uint8_t  hash[32];
    uint32_t index;
} QueueEntry;

typedef struct {
    QueueEntry entries[MERKLE_MAX_PROOF_DEPTH + 2];
    int        head;
    int        tail;
} ProofQueue;

static void queue_init(ProofQueue* q)                  { q->head = q->tail = 0; }
static bool queue_empty(const ProofQueue* q)           { return q->head == q->tail; }
static int  queue_size(const ProofQueue* q)            { return q->tail - q->head; }

static void queue_push(ProofQueue* q, const uint8_t* hash, uint32_t index) {
    int slot = q->tail % (MERKLE_MAX_PROOF_DEPTH + 2);
    memcpy(q->entries[slot].hash, hash, 32);
    q->entries[slot].index = index;
    q->tail++;
}

static QueueEntry queue_pop(ProofQueue* q) {
    return q->entries[(q->head++) % (MERKLE_MAX_PROOF_DEPTH + 2)];
}

static QueueEntry* queue_front(ProofQueue* q) {
    return &q->entries[q->head % (MERKLE_MAX_PROOF_DEPTH + 2)];
}

// Insert maintaining descending order by index (insertion sort, small queue)
static void queue_insert_sorted_desc(ProofQueue* q, const uint8_t* hash, uint32_t index) {
    // Add to tail first
    queue_push(q, hash, index);
    // Bubble up to maintain descending order
    int tail = q->tail - 1;
    while (tail > q->head) {
        int curr = tail % (MERKLE_MAX_PROOF_DEPTH + 2);
        int prev = (tail - 1) % (MERKLE_MAX_PROOF_DEPTH + 2);
        if (q->entries[curr].index > q->entries[prev].index) {
            // Swap
            QueueEntry tmp = q->entries[curr];
            q->entries[curr] = q->entries[prev];
            q->entries[prev] = tmp;
            tail--;
        } else {
            break;
        }
    }
}

// ─── Merkle::verify ──────────────────────────────────────────────────────────
// Returns true and sets txsCBMTRoot if proof is valid.

bool Merkle::verify(
    const uint8_t* txHash,
    const MerkleProof& proof,
    uint8_t* txsCBMTRoot
) {
    if (proof.depth == 0) {
        // Single-tx block: CBMT root IS the tx hash
        if (txsCBMTRoot) memcpy(txsCBMTRoot, txHash, 32);
        return true;
    }

    ProofQueue queue;
    queue_init(&queue);

    // Seed queue with the tx hash at its tree index
    queue_insert_sorted_desc(&queue, txHash, proof.indices[0]);

    int lemma_idx = 0;

    while (!queue_empty(&queue)) {
        QueueEntry e = queue_pop(&queue);
        uint8_t hash1[32];
        uint32_t index1 = e.index;
        memcpy(hash1, e.hash, 32);

        // Root reached
        if (index1 == 0) {
            if (txsCBMTRoot) memcpy(txsCBMTRoot, hash1, 32);
            return true;
        }

        uint32_t sib_idx = cbmt_sibling(index1);
        uint8_t  merged[32];
        uint8_t  hash2[32];

        if (!queue_empty(&queue) && queue_front(&queue)->index == sib_idx) {
            // Sibling is already in queue (multi-tx proof)
            QueueEntry sib = queue_pop(&queue);
            memcpy(hash2, sib.hash, 32);
            if (cbmt_is_left(index1)) {
                cbmt_merge(hash1, hash2, merged);
            } else {
                cbmt_merge(hash2, hash1, merged);
            }
        } else {
            // Take next lemma
            if (lemma_idx >= proof.depth) return false;
            memcpy(hash2, proof.lemmas[lemma_idx], 32);
            lemma_idx++;
            if (cbmt_is_left(index1)) {
                cbmt_merge(hash1, hash2, merged);
            } else {
                cbmt_merge(hash2, hash1, merged);
            }
        }

        queue_insert_sorted_desc(&queue, merged, cbmt_parent(index1));
    }

    return false;
}

// ─── Merkle::verifyTransactionsRoot ──────────────────────────────────────────
// header.transactions_root = merge(txs_CBMT_root, witnesses_root)

bool Merkle::verifyTransactionsRoot(
    const uint8_t* txsCBMTRoot,
    const uint8_t* witnessesRoot,
    const uint8_t* expectedRoot
) {
    uint8_t computed[32];
    cbmt_merge(txsCBMTRoot, witnessesRoot, computed);
    return memcmp(computed, expectedRoot, 32) == 0;
}

// ─── Merkle::verifyInclusion ──────────────────────────────────────────────────

bool Merkle::verifyInclusion(
    const uint8_t*     txHash,
    const MerkleProof& proof,
    const uint8_t*     witnessesRoot,
    const uint8_t*     expectedRoot
) {
    uint8_t txsCBMTRoot[32];
    if (!verify(txHash, proof, txsCBMTRoot)) return false;
    return verifyTransactionsRoot(txsCBMTRoot, witnessesRoot, expectedRoot);
}

// Parse proof JSON — CKB RPC uses "lemmas" (not "siblings")
// { "indices": ["0x5"], "lemmas": ["0xabc...", "0xdef..."] }

bool Merkle::parseProof(const char* json, MerkleProof& out) {
    out.depth = 0;
    memset(out.indices, 0, sizeof(out.indices));

    // Parse indices
    const char* idx_start = strstr(json, "\"indices\"");
    if (!idx_start) return false;
    const char* p = strchr(idx_start, '[');
    if (!p) return false;
    p++;
    uint8_t n_indices = 0;
    while (*p && *p != ']' && n_indices < MERKLE_MAX_PROOF_DEPTH) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == ',') p++;
        if (*p == ']') break;
        if (*p == '"') p++;
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
        uint32_t idx = 0;
        while ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F')) {
            idx <<= 4;
            char c = *p++;
            idx |= (c >= '0' && c <= '9') ? c-'0' :
                   (c >= 'a' && c <= 'f') ? c-'a'+10 : c-'A'+10;
        }
        out.indices[n_indices++] = idx;
        if (*p == '"') p++;
    }

    // Parse lemmas (sibling hashes)
    const char* lem_start = strstr(json, "\"lemmas\"");
    if (!lem_start) return false;
    p = strchr(lem_start, '[');
    if (!p) return false;
    p++;
    while (*p && *p != ']' && out.depth < MERKLE_MAX_PROOF_DEPTH) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == ',') p++;
        if (*p == ']') break;
        if (*p == '"') p++;
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
        uint8_t* dst = out.lemmas[out.depth];
        for (int i = 0; i < 32; i++) {
            if (!p[0] || !p[1]) return false;
            auto nib = [](char c) -> uint8_t {
                return (c >= '0' && c <= '9') ? c-'0' :
                       (c >= 'a' && c <= 'f') ? c-'a'+10 : c-'A'+10;
            };
            dst[i] = (nib(p[0]) << 4) | nib(p[1]);
            p += 2;
        }
        out.depth++;
        if (*p == '"') p++;
    }

    return (n_indices > 0);
}

#endif // LIGHT_NO_MERKLE
