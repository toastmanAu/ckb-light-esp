#pragma once
// ckb_hex.h — hex encode/decode utilities for ckb-light-esp
// Host and device compatible (no Arduino deps).
//
// Used everywhere: block_filter.cpp, LightClient.cpp, test files.
// Centralised here to avoid copy-paste drift.

#include <stdint.h>
#include <stddef.h>
#include <string.h>

// ── Decode ────────────────────────────────────────────────────────────────────

// Hex string → bytes. Skips leading "0x" if present.
// Returns number of bytes written, or 0 on error.
// outBuf must be at least (strlen(hex)-2)/2 bytes.
static inline size_t ckbHexDecode(const char* hex, uint8_t* out, size_t outMax) {
    if (!hex || !out) return 0;
    if (hex[0]=='0' && (hex[1]=='x'||hex[1]=='X')) hex += 2;
    size_t hexLen = strlen(hex);
    if (hexLen % 2 != 0) return 0;
    size_t byteLen = hexLen / 2;
    if (byteLen > outMax) return 0;
    for (size_t i = 0; i < byteLen; i++) {
        unsigned v = 0;
        const char* p = hex + i*2;
        // Manual parse — avoids sscanf overhead on device
        auto hexNibble = [](char c) -> int {
            if (c>='0'&&c<='9') return c-'0';
            if (c>='a'&&c<='f') return c-'a'+10;
            if (c>='A'&&c<='F') return c-'A'+10;
            return -1;
        };
        int hi = hexNibble(p[0]), lo = hexNibble(p[1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return byteLen;
}

// Decode exactly N bytes from hex string. Returns true on success.
static inline bool ckbHexDecodeN(const char* hex, uint8_t* out, size_t n) {
    return ckbHexDecode(hex, out, n) == n;
}

// ── Encode ────────────────────────────────────────────────────────────────────

// bytes → lowercase hex string with "0x" prefix.
// outBuf must be at least 2 + n*2 + 1 bytes.
static inline void ckbHexEncode(const uint8_t* bytes, size_t n,
                                 char* out, size_t outSize) {
    if (!out || outSize < 3) return;
    out[0] = '0'; out[1] = 'x';
    size_t pos = 2;
    static const char* hx = "0123456789abcdef";
    for (size_t i = 0; i < n && pos + 2 < outSize; i++) {
        out[pos++] = hx[(bytes[i] >> 4) & 0xf];
        out[pos++] = hx[ bytes[i]       & 0xf];
    }
    out[pos] = '\0';
}

// ── uint64_t hex ─────────────────────────────────────────────────────────────

// Parse "0x..." hex string to uint64_t. Returns 0 on error.
static inline uint64_t ckbHexToU64(const char* hex) {
    if (!hex) return 0;
    if (hex[0]=='0' && (hex[1]=='x'||hex[1]=='X')) hex += 2;
    uint64_t v = 0;
    while (*hex) {
        char c = *hex++;
        int n;
        if (c>='0'&&c<='9') n=c-'0';
        else if (c>='a'&&c<='f') n=c-'a'+10;
        else if (c>='A'&&c<='F') n=c-'A'+10;
        else break;
        v = (v << 4) | (uint64_t)n;
    }
    return v;
}

// Format uint64_t as "0xNN" hex string into buf (needs >=18 bytes)
static inline void ckbU64ToHex(uint64_t v, char* buf, size_t bufSize) {
    snprintf(buf, bufSize, "0x%llx", (unsigned long long)v);
}
