#pragma once
// posix_socket_client.h — real TCP WiFiClient shim using POSIX sockets
// Drop-in replacement for wifi_client_stub.h when you want host tests
// to make real TCP connections (e.g. to the devchain at 192.168.68.93:8114).
//
// Usage: include this INSTEAD of wifi_client_stub.h before any transport headers.
//   #define HOST_TEST
//   #include "posix_socket_client.h"
//   #include "../src/transport/wifi_transport.cpp"
//   // ... rest of test

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>

// Arduino shims
uint32_t millis() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}
void delay(int ms) { usleep(ms * 1000); }

// Real TCP WiFiClient using POSIX sockets
struct WiFiClient {
    int  _fd      = -1;
    bool _alive   = false;
    // Single-byte readahead buffer (makes available()/read() work like Arduino)
    char _peek    = 0;
    bool _hasPeek = false;

    bool connect(const char* host, uint16_t port) {
        _close();
        struct addrinfo hints = {}, *res = nullptr;
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        char portStr[8];
        snprintf(portStr, sizeof(portStr), "%u", port);
        if (getaddrinfo(host, portStr, &hints, &res) != 0 || !res) return false;
        _fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (_fd < 0) { freeaddrinfo(res); return false; }
        // 5s connect timeout via SO_SNDTIMEO
        struct timeval tv = {5, 0};
        setsockopt(_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        int r = ::connect(_fd, res->ai_addr, res->ai_addrlen);
        freeaddrinfo(res);
        if (r < 0) { _close(); return false; }
        _alive = true;
        return true;
    }

    bool connected() const { return _alive && _fd >= 0; }

    void stop() { _close(); }

    // Returns true if at least one byte is readable (non-blocking peek)
    bool available() {
        if (_hasPeek) return true;
        if (_fd < 0) return false;
        // Non-blocking check: set O_NONBLOCK, try read, restore
        int flags = fcntl(_fd, F_GETFL, 0);
        fcntl(_fd, F_SETFL, flags | O_NONBLOCK);
        ssize_t n = recv(_fd, &_peek, 1, 0);
        fcntl(_fd, F_SETFL, flags);  // restore blocking
        if (n == 1) { _hasPeek = true; return true; }
        if (n == 0) { _alive = false; } // EOF
        return false;
    }

    char read() {
        if (_hasPeek) { _hasPeek = false; return _peek; }
        if (_fd < 0) return 0;
        char c = 0;
        ssize_t n = recv(_fd, &c, 1, 0);
        if (n <= 0) { _alive = false; return 0; }
        return c;
    }

    size_t write(const uint8_t* buf, size_t len) {
        if (_fd < 0) return 0;
        ssize_t sent = send(_fd, buf, len, MSG_NOSIGNAL);
        return sent < 0 ? 0 : (size_t)sent;
    }

    // Stub method — not used by real transport but present in wifi_client_stub.h
    void load(const char*) {}

private:
    void _close() {
        if (_fd >= 0) { ::close(_fd); _fd = -1; }
        _alive   = false;
        _hasPeek = false;
    }
};
