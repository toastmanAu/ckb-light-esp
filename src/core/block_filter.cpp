// block_filter.cpp — GCS compact block filter implementation
// Part of ckb-light-esp (toastmanAu/ckb-light-esp)
//
// Algorithm verified against golomb-coded-set crate v0.2.1 source:
//   P = 19 (Golomb-Rice remainder bits)
//   M = 784931 (false-positive denominator, BIP-158 optimal)
//   SipHash-2-4, keys k0=0, k1=0
//   Filter wire format:
//     [8 bytes LE] n_elements
//     [bitstream]  Golomb-Rice coded deltas of sorted map_to_range values
//
// map_to_range(hash, nm) = (uint128(hash) * uint128(nm)) >> 64
//
// Elements in the filter are raw 32-byte script hashes (Blake2b-256 of
// Molecule-encoded Script). We hash them the same way: siphash(scriptHash32, 32).

#ifdef HOST_TEST
  #include <stdio.h>
  #include <string.h>
  #include <stdlib.h>
  // Stub out Arduino/CKB-ESP32 includes
  namespace { void blake2b_stub(...){} }
#else
  #include <Arduino.h>
  // CKB-ESP32 Blake2b for computeScriptHash
  #include "../../lib/CKB-ESP32/src/ckb_blake2b.h"
#endif

#include "block_filter.h"

// ── Constants (verified from golomb-coded-set crate v0.2.1) ──────────────────
static const uint8_t  GCS_P = 19;
static const uint64_t GCS_M = 784931ULL;

// ── SipHash-2-4 ───────────────────────────────────────────────────────────────
// Reference: https://131002.net/siphash/siphash.pdf
// CKB uses k0=0, k1=0 always.

#define ROTL64(x, r) (((x) << (r)) | ((x) >> (64 - (r))))

#define SIP_ROUND(v0,v1,v2,v3) do { \
    (v0) += (v1); (v1) = ROTL64((v1),13); (v1) ^= (v0); (v0) = ROTL64((v0),32); \
    (v2) += (v3); (v3) = ROTL64((v3),16); (v3) ^= (v2);                           \
    (v0) += (v3); (v3) = ROTL64((v3),21); (v3) ^= (v0);                           \
    (v2) += (v1); (v1) = ROTL64((v1),17); (v1) ^= (v2); (v2) = ROTL64((v2),32);  \
} while(0)

uint64_t BlockFilter::_sipHash24(const uint8_t* data, size_t len,
                                  uint64_t k0, uint64_t k1) {
    // Initialisation
    uint64_t v0 = k0 ^ 0x736f6d6570736575ULL;
    uint64_t v1 = k1 ^ 0x646f72616e646f6dULL;
    uint64_t v2 = k0 ^ 0x6c7967656e657261ULL;
    uint64_t v3 = k1 ^ 0x7465646279746573ULL;

    size_t blocks = len / 8;
    const uint8_t* ptr = data;

    // Process full 8-byte blocks
    for (size_t i = 0; i < blocks; i++) {
        uint64_t m = 0;
        for (int j = 0; j < 8; j++) m |= ((uint64_t)ptr[j] << (j * 8));
        ptr += 8;
        v3 ^= m;
        SIP_ROUND(v0, v1, v2, v3);
        SIP_ROUND(v0, v1, v2, v3);
        v0 ^= m;
    }

    // Last partial block (with length in top byte)
    uint64_t last = (uint64_t)(len & 0xff) << 56;
    size_t rem = len % 8;
    for (size_t i = 0; i < rem; i++) last |= ((uint64_t)ptr[i] << (i * 8));

    v3 ^= last;
    SIP_ROUND(v0, v1, v2, v3);
    SIP_ROUND(v0, v1, v2, v3);
    v0 ^= last;

    // Finalisation (SipHash-2-4: 4 finalisation rounds)
    v2 ^= 0xff;
    SIP_ROUND(v0, v1, v2, v3);
    SIP_ROUND(v0, v1, v2, v3);
    SIP_ROUND(v0, v1, v2, v3);
    SIP_ROUND(v0, v1, v2, v3);

    return v0 ^ v1 ^ v2 ^ v3;
}

// ── Bit-stream reader ─────────────────────────────────────────────────────────
// Reads bits MSB-first from a byte buffer, matching the Rust BitStreamReader.

struct BitReader {
    const uint8_t* buf;
    size_t          bufLen;
    size_t          bytePos;
    uint8_t         bitPos;   // bits consumed in current byte (0=fresh byte)

    bool init(const uint8_t* data, size_t len) {
        buf = data; bufLen = len; bytePos = 0; bitPos = 0;
        return true;
    }

    // Read nbits (max 64). Returns false on underflow.
    bool read(uint8_t nbits, uint64_t& out) {
        out = 0;
        while (nbits > 0) {
            if (bytePos >= bufLen) return false;
            uint8_t avail = 8 - bitPos;
            uint8_t take  = (nbits < avail) ? nbits : avail;
            // Mask to 8 bits BEFORE shift to prevent sign/width extension
            uint8_t shifted = (uint8_t)((buf[bytePos] << bitPos) & 0xFF) >> (8 - take);
            out = (out << take) | shifted;
            bitPos += take;
            if (bitPos == 8) { bitPos = 0; bytePos++; }
            nbits -= take;
        }
        return true;
    }
};

// ── Golomb-Rice decode (parameter P=19) ───────────────────────────────────────
// Encoded value = unary quotient (1-bits then 0) | P remainder bits
// Returns delta value; caller accumulates running total.
static bool golombDecode(BitReader& br, uint64_t& value) {
    uint64_t bit;
    uint64_t q = 0;
    // Count leading 1-bits (quotient)
    while (true) {
        if (!br.read(1, bit)) return false;
        if (bit == 0) break;
        q++;
    }
    // Read P remainder bits
    uint64_t r;
    if (!br.read(GCS_P, r)) return false;
    value = (q << GCS_P) | r;
    return true;
}

// ── map_to_range ─────────────────────────────────────────────────────────────
// Maps a 64-bit hash to [0, nm) using the fast reduction from the crate:
//   result = (uint128(hash) * uint128(nm)) >> 64
static uint64_t mapToRange(uint64_t hash, uint64_t nm) {
    // Use __uint128_t if available (GCC/Clang), otherwise do it manually
#ifdef __SIZEOF_INT128__
    return (uint64_t)(((unsigned __int128)hash * (unsigned __int128)nm) >> 64);
#else
    // Manual 128-bit multiply: split into 32-bit halves
    uint64_t hHi = hash >> 32, hLo = hash & 0xFFFFFFFFULL;
    uint64_t nHi = nm   >> 32, nLo = nm   & 0xFFFFFFFFULL;
    uint64_t a = hHi * nHi;
    uint64_t b = hHi * nLo;
    uint64_t c = hLo * nHi;
    uint64_t d = hLo * nLo;
    // Sum the cross terms (careful about overflow)
    uint64_t mid = (b & 0xFFFFFFFFULL) + (c & 0xFFFFFFFFULL) + (d >> 32);
    return a + (b >> 32) + (c >> 32) + (mid >> 32);
#endif
}

// ── GCS contains check ────────────────────────────────────────────────────────
// Tests whether element32 (a 32-byte script hash) may be in the filter.
// Implements match_any for a single element — O(n_elements) scan.
bool BlockFilter::_gcsContains(const uint8_t* filterData, size_t filterLen,
                                const uint8_t* element32) {
    if (filterLen < 8) return false;

    // Read n_elements (8-byte LE)
    uint64_t nElements = 0;
    for (int i = 0; i < 8; i++) nElements |= ((uint64_t)filterData[i] << (i * 8));
    if (nElements == 0) return false;

    // Hash our element and map to range
    uint64_t h    = _sipHash24(element32, 32, 0, 0);
    uint64_t nm   = nElements * GCS_M;
    uint64_t target = mapToRange(h, nm);

    // Walk the Golomb-Rice coded sorted list looking for target
    BitReader br;
    br.init(filterData + 8, filterLen - 8);

    uint64_t running = 0;
    for (uint64_t i = 0; i < nElements; i++) {
        uint64_t delta;
        if (!golombDecode(br, delta)) return false;
        running += delta;
        if (running == target) return true;
        if (running >  target) return false; // sorted — can't match later
    }
    return false;
}

// ── Constructor ───────────────────────────────────────────────────────────────
BlockFilter::BlockFilter()
    : _scriptCount(0),
      _matchHead(0), _matchTail(0),
      _eventHead(0), _eventTail(0) {
    memset(_scriptHashes,    0, sizeof(_scriptHashes));
    memset(_scriptStartBlock, 0, sizeof(_scriptStartBlock));
}

// ── Script registration ───────────────────────────────────────────────────────
bool BlockFilter::addScriptHash(const uint8_t* scriptHash32, uint64_t blockNumber) {
    if (_scriptCount >= LIGHT_MAX_WATCHED_SCRIPTS) return false;
    memcpy(_scriptHashes[_scriptCount], scriptHash32, 32);
    _scriptStartBlock[_scriptCount] = blockNumber;
    _scriptCount++;
    return true;
}

// ── Filter test ───────────────────────────────────────────────────────────────
bool BlockFilter::testFilter(uint64_t blockNumber,
                              const uint8_t* filterData, size_t filterLen) {
    for (uint8_t i = 0; i < _scriptCount; i++) {
        if (blockNumber < _scriptStartBlock[i]) continue;
        if (_gcsContains(filterData, filterLen, _scriptHashes[i])) {
            queueMatchedBlock(blockNumber);
            return true;
        }
    }
    return false;
}

// ── Matched block queue ───────────────────────────────────────────────────────
bool BlockFilter::queueMatchedBlock(uint64_t blockNumber) {
    uint8_t next = (_matchTail + 1) % FILTER_MATCH_QUEUE_SIZE;
    if (next == _matchHead) return false; // full
    _matchedBlockQueue[_matchTail] = blockNumber;
    _matchTail = next;
    return true;
}

bool BlockFilter::nextMatchedBlock(uint64_t* blockNumber) {
    if (_matchHead == _matchTail) return false;
    *blockNumber = _matchedBlockQueue[_matchHead];
    _matchHead = (_matchHead + 1) % FILTER_MATCH_QUEUE_SIZE;
    return true;
}

bool BlockFilter::hasMatchedBlocks() const {
    return _matchHead != _matchTail;
}

// ── Event queue ───────────────────────────────────────────────────────────────
bool BlockFilter::queueEvent(const char* txHash, uint64_t blockNumber) {
    uint8_t next = (_eventTail + 1) % FILTER_EVENT_QUEUE_SIZE;
    if (next == _eventHead) return false; // full
    strncpy(_eventQueue[_eventTail].txHash, txHash, 66);
    _eventQueue[_eventTail].txHash[66] = '\0';
    _eventQueue[_eventTail].blockNumber = blockNumber;
    _eventTail = next;
    return true;
}

bool BlockFilter::nextEvent(FilterEvent& out) {
    if (_eventHead == _eventTail) return false;
    out = _eventQueue[_eventHead];
    _eventHead = (_eventHead + 1) % FILTER_EVENT_QUEUE_SIZE;
    return true;
}

// ── Sync progress ─────────────────────────────────────────────────────────────
uint64_t BlockFilter::minFilterBlockNumber() const {
    if (_scriptCount == 0) return 0;
    uint64_t min = _scriptStartBlock[0];
    for (uint8_t i = 1; i < _scriptCount; i++) {
        if (_scriptStartBlock[i] < min) min = _scriptStartBlock[i];
    }
    return min;
}

// ── computeScriptHash ─────────────────────────────────────────────────────────
// Molecule-encodes a Script and hashes it with Blake2b-256.
// Script table layout (RFC 0022 Molecule):
//   total_size  [4 LE]       = 4+4+4+4 + 33 + (4+argsLen)
//   offsets[3]  [3 x 4 LE]  = offsets to: code_hash field, hash_type field, args field
//   code_hash   [32]
//   hash_type   [1]
//   args_len    [4 LE]       = argsLen (Molecule Bytes header)
//   args        [argsLen]
//
// This matches what the light client node computes for script hash matching.
void BlockFilter::computeScriptHash(
    const uint8_t* codeHash32,
    uint8_t        hashType,
    const uint8_t* args,
    size_t         argsLen,
    uint8_t*       out32)
{
    // Molecule Script table:
    // Header = total_size(4) + 3 offsets(4 each) = 16 bytes
    // Field 0 (code_hash): fixed 32 bytes
    // Field 1 (hash_type): fixed 1 byte
    // Field 2 (args):      4-byte Bytes length prefix + argsLen bytes
    uint32_t totalSize = 16 + 32 + 1 + 4 + (uint32_t)argsLen;

    // Offsets point to the start of each field's data (after header)
    uint32_t off0 = 16;              // code_hash starts at byte 16
    uint32_t off1 = off0 + 32;       // hash_type starts at byte 48
    uint32_t off2 = off1 + 1;        // args starts at byte 49

    // Build molecule buffer (max ~300 bytes for typical scripts)
    uint8_t  buf[300];
    size_t   pos = 0;

    auto writeU32 = [&](uint32_t v) {
        buf[pos++] = v & 0xff;
        buf[pos++] = (v >> 8) & 0xff;
        buf[pos++] = (v >> 16) & 0xff;
        buf[pos++] = (v >> 24) & 0xff;
    };

    writeU32(totalSize);
    writeU32(off0);
    writeU32(off1);
    writeU32(off2);
    memcpy(buf + pos, codeHash32, 32); pos += 32;
    buf[pos++] = hashType;
    writeU32((uint32_t)argsLen);
    if (argsLen > 0 && args) {
        memcpy(buf + pos, args, argsLen);
        pos += argsLen;
    }

#ifdef HOST_TEST
    // Host-side stub — real Blake2b implemented separately in tests
    (void)out32; // filled by test harness
    extern void hostBlake2b(const uint8_t*, size_t, uint8_t*);
    hostBlake2b(buf, pos, out32);
#else
    ckb_blake2b_256(buf, pos, out32);
#endif
}
