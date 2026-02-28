#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "../LightConfig.h"

// =============================================================================
// block_filter.h — GCS (Golomb-coded set) block filter sync + script matching
//
// CKB light client protocol sends compact block filters per block.
// Each filter encodes all script hashes touched by that block.
// We test our watched scripts against the filter — false positives
// are possible (handled by full block fetch + Merkle verify).
//
// Reference: similar to BIP157/158 (Bitcoin compact block filters)
// =============================================================================

// Max event queue depth (new tx detected for a watched script)
#define FILTER_EVENT_QUEUE_SIZE  8

typedef struct {
  char     txHash[67];    // 0x + 64 hex chars + null
  uint64_t blockNumber;
} FilterEvent;

class BlockFilter {
public:
  BlockFilter();

  // Register a script hash to watch (Blake2b-256 of serialised script)
  // Returns false if LIGHT_MAX_WATCHED_SCRIPTS exceeded
  bool addScriptHash(const uint8_t* scriptHash32);

  // Test a received GCS filter blob against all watched script hashes
  // blockNumber: which block this filter is for
  // filterData:  raw GCS bytes from RPC
  // filterLen:   length of filterData
  // Returns true if any watched script *may* appear in this block
  bool testFilter(uint64_t blockNumber, const uint8_t* filterData, size_t filterLen);

  // Called when a tx is confirmed for a watched script
  // Queues an event for the application to retrieve
  bool queueEvent(const char* txHash, uint64_t blockNumber);

  // Pop next event from queue
  // Returns false if empty
  bool nextEvent(FilterEvent& out);

  bool hasEvents() const { return _eventHead != _eventTail; }

  // Utility: compute script hash from code_hash + args + hash_type
  static void computeScriptHash(
    const uint8_t* codeHash32,
    const uint8_t* args,
    size_t argsLen,
    uint8_t hashType,
    uint8_t* out32
  );

private:
  uint8_t _scriptHashes[LIGHT_MAX_WATCHED_SCRIPTS][32];
  uint8_t _scriptCount;

  FilterEvent _eventQueue[FILTER_EVENT_QUEUE_SIZE];
  uint8_t _eventHead;
  uint8_t _eventTail;

  // GCS filter test — returns true if element *may* be in set
  bool _gcsContains(const uint8_t* filterData, size_t filterLen,
                    const uint8_t* element32);
};
