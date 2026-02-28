#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "../LightConfig.h"

// =============================================================================
// header_chain.h — Block header sync and Eaglesong PoW verification
//
// Maintains a rolling cache of verified block headers.
// Each header is verified for:
//   1. Eaglesong PoW (hash meets compact target)
//   2. Parent hash linkage
//   3. Timestamp monotonicity
// =============================================================================

// Compact representation of a CKB block header (what we store in cache)
typedef struct {
  uint64_t  number;
  uint32_t  timestamp;
  uint8_t   hash[32];
  uint8_t   parent_hash[32];
  uint32_t  compact_target;
  uint64_t  nonce;            // 128-bit nonce, lower 64 for now
  bool      verified;
} CKBHeader;

class HeaderChain {
public:
  HeaderChain();

  // Parse + verify a raw header JSON object from the RPC response
  // Returns true if valid and added to cache
  bool addHeader(const char* headerJson);

  // Verify Eaglesong PoW for a header
  // Returns true if hash meets compact_target
  static bool verifyPoW(const CKBHeader& header);

  // Get the current tip
  bool getTip(CKBHeader& out) const;
  uint64_t tipNumber() const;
  const uint8_t* tipHash() const;

  // Get header at a specific block number (if cached)
  bool getByNumber(uint64_t number, CKBHeader& out) const;

  // True if chain has been initialised with at least one verified header
  bool isInitialised() const { return _count > 0; }

  // Reset chain (e.g. on reorg detection)
  void reset();

private:
  CKBHeader _cache[LIGHT_HEADER_CACHE_SIZE];
  uint8_t   _count;
  uint8_t   _tipIdx;

  bool _parseHeader(const char* json, CKBHeader& out);
  bool _checkParentLink(const CKBHeader& header);
};
