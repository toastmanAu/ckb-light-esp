#pragma once
// wifi_client_stub.h — shared WiFiClient + Arduino shim for host tests
// Include this BEFORE any transport headers.

#include <stdio.h>
#include <string.h>
#include <string>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

// Arduino shims — guarded so they can be included multiple times
#define WY_ARDUINO_SHIMS_DEFINED
#define WY_WIFI_CLIENT_DEFINED
static uint32_t _fake_millis_base = 0;
uint32_t millis() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}
void delay(int) {}

// WiFiClient stub — can be preloaded with multiple concatenated HTTP responses
struct WiFiClient {
    std::string _buf;
    int         _pos = 0;
    bool        _alive = false;

    // Load (append) a canned HTTP response
    void load(const char* s) { _buf += s; _alive = true; }
    void reset() { _buf.clear(); _pos = 0; _alive = false; }

    bool connect(const char*, uint16_t) { _alive = true; return true; }
    bool connected() const { return _alive && _pos < (int)_buf.size(); }
    void stop() { _alive = false; }
    bool available() const { return _pos < (int)_buf.size(); }
    char read() { return (_pos < (int)_buf.size()) ? _buf[_pos++] : 0; }
    size_t write(const uint8_t*, size_t len) { return len; } // swallow writes
};
