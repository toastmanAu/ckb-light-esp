#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "../LightConfig.h"

// =============================================================================
// header_chain.h — Block header sync and Eaglesong PoW verification
//
// CKB header PoW pipeline:
//   1. Serialise header fields → Molecule bytes (192 bytes, fixed)
//   2. Blake2b-256(bytes, "ckb-default-hash") → pow_hash[32]
//   3. Eaglesong(pow_hash || nonce_le[16]) → result[32]
//   4. compact_target → expanded target[32]
//   5. result (LE) <= target (LE) → valid
// =============================================================================

// Full raw header fields needed for Molecule serialisation + pow_hash
// (superset of what we cache — only used during verification)
typedef struct {
    uint32_t version;
    uint32_t compact_target;
    uint64_t timestamp;           // milliseconds (raw from RPC)
    uint64_t number;
    uint64_t epoch;
    uint8_t  parent_hash[32];
    uint8_t  transactions_root[32];
    uint8_t  proposals_hash[32];
    uint8_t  extra_hash[32];
    uint8_t  dao[32];
} RawHeader;

// Compact representation stored in the rolling cache after verification
typedef struct {
    uint64_t number;
    uint32_t timestamp;           // seconds (truncated for storage)
    uint32_t compact_target;
    uint8_t  hash[32];
    uint8_t  parent_hash[32];
    uint8_t  nonce[16];           // 128-bit nonce, little-endian
    bool     verified;
} CKBHeader;

class HeaderChain {
public:
    HeaderChain();

    // Parse a header JSON string (from get_tip_header / get_header RPC),
    // verify parent linkage and Eaglesong PoW, add to rolling cache.
    // Returns true on success.
    bool addHeader(const char* headerJson);

    // Verify Eaglesong PoW for a header + its raw fields.
    // Static — can be called without a HeaderChain instance.
    static bool verifyPoW(const CKBHeader& header, const RawHeader& raw);

    // Verify block hash integrity (Blake2b of raw_struct || nonce_le == header.hash)
    static bool verifyBlockHash(const CKBHeader& header, const RawHeader& raw);

    // Chain tip accessors
    bool            getTip(CKBHeader& out) const;
    uint64_t        tipNumber() const;
    const uint8_t*  tipHash() const;     // returns pointer into cache (valid until reset/addHeader)

    // Look up a cached header by block number
    bool getByNumber(uint64_t number, CKBHeader& out) const;

    bool isInitialised() const { return _count > 0; }

    // Reset chain (e.g. on reorg detection)
    void reset();

private:
    CKBHeader _cache[LIGHT_HEADER_CACHE_SIZE];
    uint8_t   _count;
    uint8_t   _tipIdx;

    bool _parseHeader(const char* json, CKBHeader& out, RawHeader& rawOut);
    bool _checkParentLink(const CKBHeader& header);
};
