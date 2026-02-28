#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "../LightConfig.h"

// =============================================================================
// block_filter.h — GCS compact block filter sync + script-hash matching
//
// CKB light client protocol (implemented in nervosnetwork/ckb-light-client)
// distributes compact block filters per block. Each filter is a Golomb-Coded
// Set (GCS) encoding all script hashes touched by that block's transactions.
//
// We test our watched script hashes against each filter. False positives are
// possible — they're resolved by fetching the full block and running Merkle
// proof verification (see merkle.h).
//
// ── Algorithm ─────────────────────────────────────────────────────────────
//
// Hash function:  SipHash-2-4   (NOT Blake2b)
//   key = 0, 0  (SipHasher24Builder::new(0, 0) in Rust reference)
//
// GCS constants (from golomb_coded_set crate — exact values TBD from source):
//   M = probability denominator (false positive rate = 1/M)
//   P = Golomb parameter (bit length of remainder)
//
// Matching is against SCRIPT HASHES (Blake2b-256 of serialised Script),
// NOT raw script bytes. Use computeScriptHash() to derive from code_hash + args.
//
// ── Sync Architecture ─────────────────────────────────────────────────────
//
// Three sub-protocols — must be used in this order for efficient initial sync:
//
// 1. GetBlockFilterCheckPoints
//    Downloads checkpoint hashes at regular intervals (e.g. every 2000 blocks).
//    Avoids downloading all 19M+ individual filter hashes from block 0.
//    Backend: CKB light client node RPC (NOT available on full nodes).
//
// 2. GetBlockFilterHashes
//    Downloads filter hashes between checkpoints, verified against checkpoints.
//    Only needed for blocks from your script's block_number onward.
//
// 3. GetBlockFilters
//    Downloads actual GCS filter data for relevant blocks only.
//    Filter is tested against watched scripts — match triggers phase 2 below.
//
// ── Two-Phase Matched-Block Flow ──────────────────────────────────────────
//
// Phase 1 — Filter hit:
//   filter match → queue block number in _matchedBlockQueue
//
// Phase 2 — Full block fetch + verify:
//   fetch full block → run filter_block() → Merkle::verifyInclusion() → UTXO update
//
// The filter is a probabilistic hint. Full block fetch is the confirmation step.
// False positives from the GCS filter are discarded at the Merkle verify stage.
//
// ── Script Tracking ───────────────────────────────────────────────────────
//
// Each watched script has a block_number threshold (start of monitoring).
// The light client only reports activity from that block onward.
// get_scripts_hash(block_number) — returns hashes for scripts active at that block.
// get_min_filtered_block_number() — tracks overall sync progress.
//
// ── Reference ─────────────────────────────────────────────────────────────
//
// Rust impl: nervosnetwork/ckb-light-client
//   light-client-lib/src/protocols/filter/block_filter.rs
//
// Relevant crate: golomb_coded_set (GCSFilterReader, SipHasher24Builder, M, P)
// =============================================================================

// Max events queued (matched + verified transactions for watched scripts)
#define FILTER_EVENT_QUEUE_SIZE      8

// Max matched blocks pending full fetch + Merkle verify
#define FILTER_MATCH_QUEUE_SIZE      4

typedef struct {
  char     txHash[67];    // "0x" + 64 hex chars + null
  uint64_t blockNumber;
} FilterEvent;

class BlockFilter {
public:
  BlockFilter();

  // ── Script registration ──────────────────────────────────────────────────

  // Register a script hash to watch (Blake2b-256 of serialised Script Molecule).
  // blockNumber: only report activity at or after this block (0 = genesis).
  // Returns false if LIGHT_MAX_WATCHED_SCRIPTS exceeded.
  bool addScriptHash(const uint8_t* scriptHash32, uint64_t blockNumber = 0);

  // ── Filter testing ───────────────────────────────────────────────────────

  // Test a received GCS filter against all watched script hashes.
  // filterData:  raw GCS bytes from GetBlockFilters RPC response
  // filterLen:   length of filterData
  // blockNumber: which block this filter covers
  // Returns true if any watched script *may* appear in this block.
  // If true, the block should be fetched and Merkle-verified.
  bool testFilter(uint64_t blockNumber, const uint8_t* filterData, size_t filterLen);

  // ── Matched block queue ──────────────────────────────────────────────────

  // Push a block number that matched the filter (pending full fetch + verify).
  // Called internally by testFilter() on a positive match.
  bool queueMatchedBlock(uint64_t blockNumber);

  // Pop next matched block for fetching. Returns false if queue empty.
  bool nextMatchedBlock(uint64_t* blockNumber);

  bool hasMatchedBlocks() const;

  // ── Event queue ─────────────────────────────────────────────────────────

  // Called by LightClient after Merkle proof confirms a tx for a watched script.
  bool queueEvent(const char* txHash, uint64_t blockNumber);

  // Pop next confirmed event. Returns false if empty.
  bool nextEvent(FilterEvent& out);

  bool hasEvents() const { return _eventHead != _eventTail; }

  // ── Sync progress ────────────────────────────────────────────────────────

  // Minimum block number we need to scan from (earliest script start).
  uint64_t minFilterBlockNumber() const;

  // ── Utilities ────────────────────────────────────────────────────────────

  // Compute script hash from Script Molecule fields.
  // Blake2b-256 of: code_hash[32] || hash_type[1] || args_len_le32[4] || args[argsLen]
  // (full Molecule-encoded Script table — see RFC 0022)
  static void computeScriptHash(
    const uint8_t* codeHash32,
    uint8_t        hashType,     // 0=data, 1=type, 2=data1
    const uint8_t* args,
    size_t         argsLen,
    uint8_t*       out32
  );

#ifdef HOST_TEST
public:
#else
private:
#endif
  // Watched scripts
  uint8_t  _scriptHashes[LIGHT_MAX_WATCHED_SCRIPTS][32];
  uint64_t _scriptStartBlock[LIGHT_MAX_WATCHED_SCRIPTS];
  uint8_t  _scriptCount;

  // Matched blocks pending full fetch (ring buffer)
  uint64_t _matchedBlockQueue[FILTER_MATCH_QUEUE_SIZE];
  uint8_t  _matchHead;
  uint8_t  _matchTail;

  // Confirmed events (ring buffer)
  FilterEvent _eventQueue[FILTER_EVENT_QUEUE_SIZE];
  uint8_t     _eventHead;
  uint8_t     _eventTail;

  // GCS SipHash-2-4 filter test — returns true if element *may* be in set.
  // element32: Blake2b-256 script hash to test
  bool _gcsContains(const uint8_t* filterData, size_t filterLen,
                    const uint8_t* element32);

  // SipHash-2-4: hash element with key (k0=0, k1=0 per CKB GCS spec)
  static uint64_t _sipHash24(const uint8_t* data, size_t len,
                              uint64_t k0 = 0, uint64_t k1 = 0);
};
