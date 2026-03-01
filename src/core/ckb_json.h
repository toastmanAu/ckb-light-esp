#pragma once
// ckb_json.h — minimal JSON field extractor for ckb-light-esp
// No dynamic allocation. No full parser. Just the RPC fields we need.
// Host and device compatible.
//
// These functions were previously duplicated in LightClient.cpp.
// Centralised here for reuse in native_locks.cpp, ckbvm_interp.cpp, etc.

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "ckb_hex.h"

// ── String field ─────────────────────────────────────────────────────────────

// Extract value of "key": "value" → copies into out (without quotes).
// Skips whitespace around colon. Returns true if found.
static inline bool ckbJsonGetStr(const char* json, const char* key,
                                  char* out, size_t outLen) {
    if (!json || !key || !out || outLen == 0) return false;
    char search[80];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char* pos = strstr(json, search);
    if (!pos) return false;
    pos += strlen(search);
    while (*pos == ' ' || *pos == ':') pos++;
    if (*pos != '"') return false;
    pos++;
    size_t i = 0;
    while (*pos && *pos != '"' && i < outLen - 1) out[i++] = *pos++;
    out[i] = '\0';
    return i > 0;
}

// ── Hex-encoded uint64_t field ────────────────────────────────────────────────

// Extract "key": "0x..." → parse as uint64_t.
static inline bool ckbJsonGetHexU64(const char* json, const char* key,
                                     uint64_t* out) {
    char buf[24];
    if (!ckbJsonGetStr(json, key, buf, sizeof(buf))) return false;
    if (buf[0]=='0' && (buf[1]=='x'||buf[1]=='X')) {
        *out = ckbHexToU64(buf);
        return true;
    }
    return false;
}

// ── Numeric (decimal) field ───────────────────────────────────────────────────

// Extract "key": <number> (unquoted) → parse as uint64_t.
static inline bool ckbJsonGetU64(const char* json, const char* key,
                                  uint64_t* out) {
    char search[80];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char* pos = strstr(json, search);
    if (!pos) return false;
    pos += strlen(search);
    while (*pos == ' ' || *pos == ':') pos++;
    if (*pos < '0' || *pos > '9') return false;
    *out = (uint64_t)strtoull(pos, nullptr, 10);
    return true;
}

// ── Result field ──────────────────────────────────────────────────────────────

// Find "result": <value> and return pointer to start of value.
// Sets *len to length of the value token (object/array/string/atom).
// Returns nullptr if result is null or missing.
static inline const char* ckbJsonGetResult(const char* json, size_t* len) {
    if (!json) return nullptr;
    const char* pos = strstr(json, "\"result\"");
    if (!pos) return nullptr;
    pos += 8;
    while (*pos == ' ' || *pos == ':') pos++;
    if (!*pos || strncmp(pos, "null", 4) == 0) return nullptr;
    const char* start = pos;
    int depth = 0;
    bool inStr = false;
    const char* p = start;
    while (*p) {
        if (inStr) {
            if (*p == '\\') p++;
            else if (*p == '"') inStr = false;
        } else {
            if (*p == '"') inStr = true;
            else if (*p == '{' || *p == '[') depth++;
            else if (*p == '}' || *p == ']') {
                if (depth == 0) break;
                if (--depth == 0) { p++; break; }
            } else if (depth == 0 && (*p == ',' || *p == '}' || *p == ']')) break;
        }
        p++;
    }
    if (len) *len = (size_t)(p - start);
    return start;
}

// ── Boolean field ─────────────────────────────────────────────────────────────

// Extract "key": true/false → bool.
static inline bool ckbJsonGetBool(const char* json, const char* key, bool* out) {
    char search[80];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char* pos = strstr(json, search);
    if (!pos) return false;
    pos += strlen(search);
    while (*pos == ' ' || *pos == ':') pos++;
    if (strncmp(pos, "true", 4) == 0)  { *out = true;  return true; }
    if (strncmp(pos, "false", 5) == 0) { *out = false; return true; }
    return false;
}

// ── Array element count ────────────────────────────────────────────────────────

// Count top-level elements in a JSON array string (e.g. result of get_peers).
// Handles nested objects/arrays. Returns -1 on parse error.
static inline int ckbJsonArrayLen(const char* arr) {
    if (!arr) return -1;
    const char* p = arr;
    while (*p == ' ') p++;
    if (*p != '[') return -1;
    p++;
    while (*p == ' ') p++;
    if (*p == ']') return 0;
    int count = 1, depth = 0;
    bool inStr = false;
    while (*p) {
        if (inStr) {
            if (*p == '\\') p++;
            else if (*p == '"') inStr = false;
        } else {
            if (*p == '"') inStr = true;
            else if (*p == '{' || *p == '[') depth++;
            else if (*p == '}' || *p == ']') {
                if (depth == 0) break;
                depth--;
            } else if (depth == 0 && *p == ',') count++;
        }
        p++;
    }
    return count;
}
