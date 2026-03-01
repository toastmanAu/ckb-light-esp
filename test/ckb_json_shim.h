#pragma once
// ckb_json_shim.h — ArduinoJson-compatible shim for HOST_TEST builds
// Provides StaticJsonDocument<N> + bracket access using ckb_json.h underneath.
// Covers only the subset used in header_chain.cpp (_parseHeader).

#include <string>
#include <string.h>
#include <stdlib.h>
#include "../src/core/ckb_json.h"

// Minimal "value" type returned by doc["key"] — holds a string or is null
struct JsonValue {
    char  _buf[256];
    bool  _valid;
    JsonValue() : _valid(false) { _buf[0] = '\0'; }
    JsonValue(const char* s) : _valid(s != nullptr) {
        if (s) { strncpy(_buf, s, sizeof(_buf)-1); _buf[sizeof(_buf)-1]='\0'; }
        else   { _buf[0] = '\0'; }
    }
    // Implicit conversion to const char* (null if not found)
    operator const char*() const { return _valid ? _buf : nullptr; }
    bool isNull() const { return !_valid; }
};

// Minimal DeserializationError mock
struct DeserializationError {
    bool _ok;
    DeserializationError(bool ok) : _ok(ok) {}
    static DeserializationError Ok;
    bool operator==(const DeserializationError& o) const { return _ok == o._ok; }
    bool operator!=(const DeserializationError& o) const { return _ok != o._ok; }
};
inline DeserializationError DeserializationError::Ok(true);

template<size_t N>
struct StaticJsonDocument {
    char _json[N];
    bool _valid = false;

    JsonValue operator[](const char* key) const {
        if (!_valid) return JsonValue();
        char tmp[256];
        if (ckbJsonGetStr(_json, key, tmp, sizeof(tmp))) return JsonValue(tmp);
        return JsonValue();
    }
};

template<size_t N>
static inline DeserializationError deserializeJson(StaticJsonDocument<N>& doc,
                                                    const char* json) {
    if (!json) return DeserializationError(false);
    strncpy(doc._json, json, N-1);
    doc._json[N-1] = '\0';
    doc._valid = true;
    return DeserializationError(true);
}
