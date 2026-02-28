// =============================================================================
// header_chain.cpp — CKB block header sync and Eaglesong PoW verification
//
// CKB PoW pipeline (verified against mainnet block #18,731,746):
//
//   1. Serialise RawHeader fields as Molecule STRUCT (fixed-size, 192 bytes):
//      version(u32) | compact_target(u32) | timestamp(u64) | number(u64) |
//      epoch(u64) | parent_hash(32) | transactions_root(32) |
//      proposals_hash(32) | extra_hash(32) | dao(32)
//      All integers little-endian. No molecule table header (it's a struct).
//
//   2. Blake2b-256(raw_bytes, person="ckb-default-hash") → pow_hash[32]
//
//   3. Parse RPC nonce: "0xXXXX..." is the big-endian hex of a u128 value.
//      Convert to little-endian bytes: nonce_le = u128.to_le_bytes()
//
//   4. Eaglesong(pow_hash[32] || nonce_le[16]) → result[32]
//      result bytes are big-endian (byte[0] = MSB).
//
//   5. Expand compact_target → 32-byte big-endian target.
//      exponent = compact >> 24
//      mantissa = compact & 0x007FFFFF
//      target[32 - exponent .. 32 - exponent + 3] = mantissa bytes
//
//   6. result (BE, byte[0] first) <= target (BE) → valid block
//
// Block hash (for parent linkage verification):
//   Blake2b-256(raw_bytes[192] || nonce_le[16], person="ckb-default-hash")
//   i.e. same as step 2 but include nonce_le appended to the struct bytes.
// =============================================================================

#include "header_chain.h"
#include "eaglesong.h"
#include <ArduinoJson.h>
#include <string.h>

// ─── Utility helpers ──────────────────────────────────────────────────────────

static bool hex_to_bytes(const char* hex, uint8_t* out, size_t outLen) {
    if (!hex) return false;
    if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) hex += 2;
    if (strlen(hex) != outLen * 2) return false;
    for (size_t i = 0; i < outLen; i++) {
        auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int h = nibble(hex[i*2]), l = nibble(hex[i*2+1]);
        if (h < 0 || l < 0) return false;
        out[i] = (uint8_t)((h << 4) | l);
    }
    return true;
}

static uint64_t hex_to_u64(const char* hex) {
    if (!hex) return 0;
    if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) hex += 2;
    uint64_t v = 0;
    while (*hex) {
        v <<= 4;
        char c = *hex++;
        if      (c >= '0' && c <= '9') v |= (c - '0');
        else if (c >= 'a' && c <= 'f') v |= (c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= (c - 'A' + 10);
    }
    return v;
}

static void write_u32_le(uint8_t* buf, uint32_t v) {
    buf[0] = v & 0xFF; buf[1] = (v >> 8) & 0xFF;
    buf[2] = (v >> 16) & 0xFF; buf[3] = (v >> 24) & 0xFF;
}

static void write_u64_le(uint8_t* buf, uint64_t v) {
    for (int i = 0; i < 8; i++) buf[i] = (v >> (i * 8)) & 0xFF;
}

// ─── compact_target → 32-byte big-endian target ──────────────────────────────
//
// CKB uses the same compact_target format as Bitcoin (nBits):
//   exponent = compact >> 24        (number of bytes in value)
//   mantissa = compact & 0x007FFFFF (coefficient)
//   value    = mantissa * 256^(exponent-3)
//
// We store as 32-byte big-endian for byte-by-byte comparison with
// eaglesong output (which is also big-endian, byte[0] = MSB).

static void compact_to_target_be(uint32_t compact, uint8_t target[32]) {
    memset(target, 0, 32);
    uint32_t exponent = compact >> 24;
    uint32_t mantissa = compact & 0x007FFFFF;
    if (exponent == 0 || exponent > 32) return;
    int pos = (int)(32 - exponent);  // byte index of MSB of mantissa in 32-byte BE
    if (pos >= 0 && pos + 2 < 32) {
        target[pos]     = (mantissa >> 16) & 0xFF;
        target[pos + 1] = (mantissa >>  8) & 0xFF;
        target[pos + 2] = (mantissa >>  0) & 0xFF;
    }
}

// ─── PoW result comparison ────────────────────────────────────────────────────
// Both result and target are 32-byte big-endian (byte[0] = MSB).
// Returns true if result <= target.

static bool pow_result_valid(const uint8_t result[32], const uint8_t target[32]) {
    for (int i = 0; i < 32; i++) {
        if (result[i] < target[i]) return true;
        if (result[i] > target[i]) return false;
    }
    return true;  // exactly equal is valid
}

// ─── Nonce RPC → eaglesong LE bytes ──────────────────────────────────────────
//
// CKB RPC nonce: "0x" + 32 hex chars = big-endian representation of a u128 value.
// Eaglesong needs: the u128 value stored as little-endian bytes (16 bytes).
// Conversion: reverse the 16 raw hex bytes.

static bool nonce_rpc_to_le(const char* nonceHex, uint8_t nonce_le[16]) {
    uint8_t rpc_bytes[16];
    if (!hex_to_bytes(nonceHex, rpc_bytes, 16)) return false;
    // RPC bytes are big-endian u128 → reverse to get LE
    for (int i = 0; i < 16; i++) nonce_le[i] = rpc_bytes[15 - i];
    return true;
}

// ─── Molecule STRUCT serialisation → raw bytes ───────────────────────────────
// RawHeader is a Molecule STRUCT (all fixed-size fields, no table header).
// Total: 4+4+8+8+8+32+32+32+32+32 = 192 bytes.

static bool build_raw_struct(const RawHeader& raw, uint8_t buf[192]) {
    uint8_t* p = buf;
    write_u32_le(p, raw.version);            p += 4;
    write_u32_le(p, raw.compact_target);     p += 4;
    write_u64_le(p, raw.timestamp);          p += 8;
    write_u64_le(p, raw.number);             p += 8;
    write_u64_le(p, raw.epoch);              p += 8;
    memcpy(p, raw.parent_hash,          32); p += 32;
    memcpy(p, raw.transactions_root,    32); p += 32;
    memcpy(p, raw.proposals_hash,       32); p += 32;
    memcpy(p, raw.extra_hash,           32); p += 32;
    memcpy(p, raw.dao,                  32); p += 32;
    return (p - buf) == 192;
}

// ─── HeaderChain implementation ──────────────────────────────────────────────

HeaderChain::HeaderChain() : _count(0), _tipIdx(0) {
    memset(_cache, 0, sizeof(_cache));
}

void HeaderChain::reset() {
    _count  = 0;
    _tipIdx = 0;
    memset(_cache, 0, sizeof(_cache));
}

bool HeaderChain::_parseHeader(const char* json, CKBHeader& out, RawHeader& rawOut) {
    StaticJsonDocument<LIGHT_JSON_BUFFER_SIZE> doc;
    if (deserializeJson(doc, json) != DeserializationError::Ok) return false;

    const char* compact_target_hex  = doc["compact_target"];
    const char* hash_hex            = doc["hash"];
    const char* nonce_hex           = doc["nonce"];
    const char* number_hex          = doc["number"];
    const char* parent_hash_hex     = doc["parent_hash"];
    const char* timestamp_hex       = doc["timestamp"];
    const char* epoch_hex           = doc["epoch"];
    const char* txroot_hex          = doc["transactions_root"];
    const char* proposals_hash_hex  = doc["proposals_hash"];
    const char* extra_hash_hex      = doc["extra_hash"];
    const char* dao_hex             = doc["dao"];

    if (!compact_target_hex || !hash_hex || !nonce_hex ||
        !number_hex || !parent_hash_hex || !timestamp_hex) return false;

    out.compact_target = (uint32_t)hex_to_u64(compact_target_hex);
    out.number         = hex_to_u64(number_hex);
    out.timestamp      = (uint32_t)(hex_to_u64(timestamp_hex) / 1000);  // ms → s

    if (!hex_to_bytes(hash_hex,        out.hash,        32)) return false;
    if (!hex_to_bytes(parent_hash_hex, out.parent_hash, 32)) return false;
    if (!nonce_rpc_to_le(nonce_hex, out.nonce))              return false;

    // Build RawHeader for PoW verification
    rawOut.version        = 0;
    rawOut.compact_target = out.compact_target;
    rawOut.timestamp      = hex_to_u64(timestamp_hex);  // full ms value
    rawOut.number         = out.number;
    rawOut.epoch          = epoch_hex ? hex_to_u64(epoch_hex) : 0;
    memcpy(rawOut.parent_hash, out.parent_hash, 32);

    memset(rawOut.transactions_root, 0, 32);
    memset(rawOut.proposals_hash,    0, 32);
    memset(rawOut.extra_hash,        0, 32);
    memset(rawOut.dao,               0, 32);

    if (txroot_hex)        hex_to_bytes(txroot_hex,       rawOut.transactions_root, 32);
    if (proposals_hash_hex)hex_to_bytes(proposals_hash_hex, rawOut.proposals_hash,  32);
    if (extra_hash_hex)    hex_to_bytes(extra_hash_hex,   rawOut.extra_hash,        32);
    if (dao_hex)           hex_to_bytes(dao_hex,          rawOut.dao,               32);

    out.verified = false;
    return true;
}

bool HeaderChain::verifyPoW(const CKBHeader& header, const RawHeader& raw) {
    // 1. Molecule STRUCT serialisation
    uint8_t buf[192];
    if (!build_raw_struct(raw, buf)) return false;

    // 2. Blake2b-256(buf) → pow_hash
    uint8_t pow_hash[32];
    CKB_Blake2b ctx;
    ckb_blake2b_init(&ctx);
    ckb_blake2b_update(&ctx, buf, 192);
    ckb_blake2b_final(&ctx, pow_hash);

    // 3. Eaglesong(pow_hash || nonce_le) → result (BE, byte[0]=MSB)
    uint8_t result[32];
    ckb_pow_hash(pow_hash, header.nonce, result);

    // 4. Expand compact_target → 32-byte BE target
    uint8_t target[32];
    compact_to_target_be(header.compact_target, target);

    // 5. result (BE) <= target (BE) → valid
    return pow_result_valid(result, target);
}

bool HeaderChain::verifyBlockHash(const CKBHeader& header, const RawHeader& raw) {
    // Block hash = Blake2b(raw_struct[192] || nonce_le[16])
    uint8_t buf[192];
    if (!build_raw_struct(raw, buf)) return false;

    uint8_t computed[32];
    CKB_Blake2b ctx;
    ckb_blake2b_init(&ctx);
    ckb_blake2b_update(&ctx, buf,          192);
    ckb_blake2b_update(&ctx, header.nonce, 16);
    ckb_blake2b_final(&ctx, computed);

    return memcmp(computed, header.hash, 32) == 0;
}

bool HeaderChain::_checkParentLink(const CKBHeader& header) {
    if (_count == 0) return true;
    const CKBHeader& tip = _cache[_tipIdx];
    if (memcmp(header.parent_hash, tip.hash, 32) != 0) return false;
    if (header.number != tip.number + 1) return false;
    if (header.timestamp < tip.timestamp) return false;
    return true;
}

bool HeaderChain::addHeader(const char* headerJson) {
    CKBHeader h;
    RawHeader raw;
    memset(&h,   0, sizeof(h));
    memset(&raw, 0, sizeof(raw));

    if (!_parseHeader(headerJson, h, raw))   return false;
    if (!verifyBlockHash(h, raw))            return false;  // hash integrity first
    if (!_checkParentLink(h))                return false;  // chain continuity
    if (!verifyPoW(h, raw))                  return false;  // PoW validity

    h.verified = true;

    // Rolling circular cache
    uint8_t idx = (_count < LIGHT_HEADER_CACHE_SIZE)
        ? _count
        : (uint8_t)((_tipIdx + 1) % LIGHT_HEADER_CACHE_SIZE);

    _cache[idx] = h;
    _tipIdx = idx;
    if (_count < LIGHT_HEADER_CACHE_SIZE) _count++;

    return true;
}

bool HeaderChain::getTip(CKBHeader& out) const {
    if (_count == 0) return false;
    out = _cache[_tipIdx];
    return true;
}

uint64_t HeaderChain::tipNumber() const {
    return (_count == 0) ? 0 : _cache[_tipIdx].number;
}

const uint8_t* HeaderChain::tipHash() const {
    return (_count == 0) ? nullptr : _cache[_tipIdx].hash;
}

bool HeaderChain::getByNumber(uint64_t number, CKBHeader& out) const {
    for (uint8_t i = 0; i < _count; i++) {
        if (_cache[i].number == number && _cache[i].verified) {
            out = _cache[i];
            return true;
        }
    }
    return false;
}
