// =============================================================================
// wifi_transport.cpp — WiFi TCP transport to CKB light client node RPC
//
// Target: CKB light client node RPC (default port 9000).
//         NOT a full node (port 8114) — full nodes don't serve block filters.
//
// Protocol: HTTP/1.1 POST with JSON-RPC body. Keep-alive connection reused
//           across calls to avoid TCP handshake overhead on every request.
//
// RPC wire format (from ckb-light-client README):
//   Request:  POST / HTTP/1.1
//             Content-Type: application/json
//             { "jsonrpc": "2.0", "method": "<m>", "params": <p>, "id": <n> }
//   Response: HTTP/1.1 200 OK
//             { "jsonrpc": "2.0", "result": <r>, "id": <n> }
//
// set_scripts params shape (IMPORTANT — takes full Script objects, not hashes):
//   [
//     [{ "script": { "code_hash": "0x...", "hash_type": "type", "args": "0x..." },
//        "script_type": "lock",
//        "block_number": "0x0" }],
//     "partial"   <- optional command: "all" (default) | "partial" | "delete"
//   ]
// =============================================================================

#ifdef HOST_TEST
// Host build shims (not needed on device — Arduino.h provides these)
#ifndef IRAM_ATTR
#define IRAM_ATTR
#endif
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#ifndef WY_ARDUINO_SHIMS_DEFINED
#define WY_ARDUINO_SHIMS_DEFINED
static uint32_t millis() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}
static void delay(int) {}
#endif
#endif // HOST_TEST

#ifndef LIGHT_JSON_BUFFER_SIZE
#define LIGHT_JSON_BUFFER_SIZE 2048
#endif
#ifndef HOST_TEST
#  include <ckb_blake2b.h>
#  include "../LightConfig.h"
#endif
#include "wifi_transport.h"

// ─── Constructor ─────────────────────────────────────────────────────────────

WiFiTransport::WiFiTransport()
    : _port(9000), _reqId(1) {
    _host[0]      = '\0';
    _lastError[0] = '\0';
}

// ─── connect / disconnect ─────────────────────────────────────────────────────

bool WiFiTransport::connect(const char* host, uint16_t port) {
    strncpy(_host, host, sizeof(_host) - 1);
    _host[sizeof(_host) - 1] = '\0';
    _port = port;
    return _reconnect();
}

void WiFiTransport::disconnect() {
    _client.stop();
}

bool WiFiTransport::isConnected() {
    return _client.connected();
}

bool WiFiTransport::_reconnect() {
    if (_client.connected()) return true;
    _client.stop();
    if (!_client.connect(_host, _port)) {
        snprintf(_lastError, sizeof(_lastError), "TCP connect: %.40s", _host);
        return false;
    }
    return true;
}

// ─── _buildRequest ───────────────────────────────────────────────────────────
// Build an HTTP/1.1 POST request with JSON-RPC body into caller's buffer.
// Returns total byte count, or -1 if buffer too small.

int WiFiTransport::_buildRequest(const char* method, const char* params,
                                  char* out, size_t outSize) {
    // Build JSON body first so we know Content-Length
    char body[LIGHT_JSON_BUFFER_SIZE];
    int bodyLen = snprintf(body, sizeof(body),
        "{\"jsonrpc\":\"2.0\",\"method\":\"%s\",\"params\":%s,\"id\":%lu}",
        method, params, (unsigned long)_reqId);
    if (bodyLen <= 0 || (size_t)bodyLen >= sizeof(body)) {
        snprintf(_lastError, sizeof(_lastError), "JSON body overflow");
        return -1;
    }

    // Build HTTP header
    int total = snprintf(out, outSize,
        "POST / HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        "%s",
        _host, bodyLen, body);

    if (total <= 0 || (size_t)total >= outSize) {
        snprintf(_lastError, sizeof(_lastError), "HTTP request overflow");
        return -1;
    }
    return total;
}

// ─── request ─────────────────────────────────────────────────────────────────
// Send a JSON-RPC request and read the response body into responseBuf.
// Skips HTTP headers, returns JSON body length or -1 on error.

int WiFiTransport::request(const char* method, const char* params,
                            char* responseBuf, size_t responseBufSize,
                            uint32_t timeoutMs) {
    // Build and send
    char reqBuf[LIGHT_JSON_BUFFER_SIZE + 256];
    int reqLen = _buildRequest(method, params, reqBuf, sizeof(reqBuf));
    if (reqLen < 0) return -1;

    if (!_reconnect()) return -1;

    if (_client.write((uint8_t*)reqBuf, reqLen) != (size_t)reqLen) {
        snprintf(_lastError, sizeof(_lastError), "TCP write failed");
        _client.stop();
        return -1;
    }
    _reqId++;

    // ── Read response ──────────────────────────────────────────────────────
    // We need to:
    //  1. Skip HTTP status line + headers
    //  2. Handle chunked transfer encoding OR Content-Length
    //  3. Copy body into responseBuf

    uint32_t deadline = millis() + timeoutMs;
    bool     headersEnd   = false;
    bool     chunked      = false;
    int      contentLen   = -1;
    int      bodyWritten  = 0;
    char     lineBuf[128];
    int      linePos      = 0;

    // ── Parse header lines ────────────────────────────────────────────────
    while (!headersEnd && millis() < deadline) {
        if (!_client.available()) {
            delay(1);
            continue;
        }
        char c = (char)_client.read();
        if (c == '\r') continue;  // ignore CR

        if (c == '\n') {
            lineBuf[linePos] = '\0';
            linePos = 0;

            if (strlen(lineBuf) == 0) {
                // Blank line = end of headers
                headersEnd = true;
            } else if (strncasecmp(lineBuf, "transfer-encoding:", 18) == 0) {
                if (strstr(lineBuf + 18, "chunked")) chunked = true;
            } else if (strncasecmp(lineBuf, "content-length:", 15) == 0) {
                contentLen = atoi(lineBuf + 15);
            }
            // (ignore other headers)
        } else {
            if (linePos < (int)sizeof(lineBuf) - 1)
                lineBuf[linePos++] = c;
        }
    }

    if (!headersEnd) {
        snprintf(_lastError, sizeof(_lastError), "Header timeout");
        return -1;
    }

    // ── Read body ─────────────────────────────────────────────────────────
    if (chunked) {
        // Chunked transfer: read chunk-size\r\n + data\r\n, repeat until 0\r\n
        while (millis() < deadline) {
            // Read chunk size line (hex)
            linePos = 0;
            while (millis() < deadline) {
                if (!_client.available()) { delay(1); continue; }
                char c = (char)_client.read();
                if (c == '\r') continue;
                if (c == '\n') break;
                if (linePos < (int)sizeof(lineBuf) - 1)
                    lineBuf[linePos++] = c;
            }
            lineBuf[linePos] = '\0';
            int chunkSize = (int)strtol(lineBuf, nullptr, 16);
            if (chunkSize == 0) break;  // final chunk

            for (int i = 0; i < chunkSize && millis() < deadline; i++) {
                while (!_client.available() && millis() < deadline) delay(1);
                char c = (char)_client.read();
                if (bodyWritten < (int)responseBufSize - 1)
                    responseBuf[bodyWritten++] = c;
            }
            // Consume trailing \r\n after chunk data
            while (_client.available()) {
                char c = (char)_client.read();
                if (c == '\n') break;
            }
        }
    } else if (contentLen > 0) {
        // Fixed-length body
        int toRead = contentLen;
        while (toRead > 0 && millis() < deadline) {
            if (!_client.available()) { delay(1); continue; }
            char c = (char)_client.read();
            if (bodyWritten < (int)responseBufSize - 1)
                responseBuf[bodyWritten++] = c;
            toRead--;
        }
    } else {
        // No content-length or chunked — read until connection closes or timeout
        while (millis() < deadline && _client.connected()) {
            if (!_client.available()) { delay(1); continue; }
            char c = (char)_client.read();
            if (bodyWritten < (int)responseBufSize - 1)
                responseBuf[bodyWritten++] = c;
        }
    }

    responseBuf[bodyWritten] = '\0';

    if (bodyWritten == 0) {
        snprintf(_lastError, sizeof(_lastError), "Empty response body");
        return -1;
    }

    // Basic JSON-RPC error check
    if (strstr(responseBuf, "\"error\"") && !strstr(responseBuf, "\"result\"")) {
        snprintf(_lastError, sizeof(_lastError), "RPC error in response");
        return -1;
    }

    return bodyWritten;
}

// ─── setScripts ──────────────────────────────────────────────────────────────
// Register a lock script with the light client node.
// The light client node tracks activity from blockNumber onward.
//
// set_scripts params format (from README):
//   [[{ "script": { "code_hash": "0x...", "hash_type": "type", "args": "0x..." },
//      "script_type": "lock",
//      "block_number": "0x0" }], "partial"]
//
// codeHashHex:  "0x" + 64 hex chars
// hashType:     "type" or "data"
// argsHex:      "0x" + hex-encoded args bytes
// blockNumber:  filter start (0 = from genesis)

bool WiFiTransport::setScripts(const char* codeHashHex, const char* hashType,
                                const char* argsHex, uint64_t blockNumber) {
    char params[512];
    char blockHex[20];
    snprintf(blockHex, sizeof(blockHex), "0x%llx", (unsigned long long)blockNumber);

    int n = snprintf(params, sizeof(params),
        "[[{\"script\":{\"code_hash\":\"%s\",\"hash_type\":\"%s\",\"args\":\"%s\"},"
        "\"script_type\":\"lock\","
        "\"block_number\":\"%s\"}],\"partial\"]",
        codeHashHex, hashType, argsHex, blockHex);

    if (n <= 0 || (size_t)n >= sizeof(params)) {
        snprintf(_lastError, sizeof(_lastError), "setScripts: params overflow");
        return false;
    }

    char resp[256];
    int len = request("set_scripts", params, resp, sizeof(resp));
    // set_scripts returns null on success
    return (len >= 0);
}

// ─── getTipHeader ─────────────────────────────────────────────────────────────
// Fetch current chain tip. Parses "number" field from HeaderView JSON.
// Returns true and fills *blockNumber on success.

bool WiFiTransport::getTipHeader(uint64_t* blockNumber) {
    char resp[LIGHT_JSON_BUFFER_SIZE];
    int len = request("get_tip_header", "[]", resp, sizeof(resp));
    if (len < 0) return false;

    // Parse "number":"0x..." from response
    // HeaderView JSON: { "result": { "number": "0x...", ... } }
    const char* p = strstr(resp, "\"number\"");
    if (!p) {
        snprintf(_lastError, sizeof(_lastError), "getTipHeader: no 'number' field");
        return false;
    }
    p = strchr(p, ':');
    if (!p) return false;
    p++;
    while (*p == ' ' || *p == '"') p++;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;

    uint64_t num = 0;
    while ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F')) {
        num <<= 4;
        char c = *p++;
        num |= (c >= '0' && c <= '9') ? c - '0' :
               (c >= 'a' && c <= 'f') ? c - 'a' + 10 : c - 'A' + 10;
    }
    *blockNumber = num;
    return true;
}

// ─── fetchTransaction ─────────────────────────────────────────────────────────
// Async fetch: returns "fetched", "fetching", "added", or "not_found".
// On "fetched", copies result into responseBuf.
// Caller should retry if "fetching" or "added".

WiFiTransport::FetchStatus WiFiTransport::fetchTransaction(
    const char* txHashHex, char* responseBuf, size_t responseBufSize) {

    char params[80];
    snprintf(params, sizeof(params), "[\"%s\"]", txHashHex);

    int len = request("fetch_transaction", params, responseBuf, responseBufSize);
    if (len < 0) return FETCH_ERROR;

    if (strstr(responseBuf, "\"fetched\""))  return FETCH_DONE;
    if (strstr(responseBuf, "\"fetching\"")) return FETCH_PENDING;
    if (strstr(responseBuf, "\"added\""))    return FETCH_PENDING;
    if (strstr(responseBuf, "\"not_found\""))return FETCH_NOT_FOUND;
    return FETCH_ERROR;
}

// ─── getPeerCount ─────────────────────────────────────────────────────────────
// Returns number of connected peers, or -1 on error.
// Useful for health checks — if peers == 0, we're not syncing.

int WiFiTransport::getPeerCount() {
    char resp[1024];
    int len = request("get_peers", "[]", resp, sizeof(resp));
    if (len < 0) return -1;

    // Count occurrences of "node_id" in result array — one per peer
    int count = 0;
    const char* p = resp;
    while ((p = strstr(p, "\"node_id\"")) != nullptr) {
        count++;
        p += 9;
    }
    return count;
}

// ─── getCellsCapacity ─────────────────────────────────────────────────────────
// Single-call balance query via get_cells_capacity RPC.
// Returns total capacity of all live cells for the given lock script.
// Much faster than filter sync — answers from light node's indexed state.

bool WiFiTransport::getCellsCapacity(const char* codeHashHex, const char* hashType,
                                     const char* argsHex, uint64_t* outShannons) {
    if (!outShannons) return false;
    *outShannons = 0;

    char params[320];
    snprintf(params, sizeof(params),
        "[{\"script\":{\"code_hash\":\"%s\",\"hash_type\":\"%s\",\"args\":\"%s\"},"
        "\"script_type\":\"lock\"}]",
        codeHashHex, hashType, argsHex);

    char resp[256];
    int len = request("get_cells_capacity", params, resp, sizeof(resp));
    if (len < 0) return false;

    // result is {"capacity":"0x..."} — parse hex capacity
    const char* cap = strstr(resp, "\"capacity\":");
    if (!cap) {
        snprintf(_lastError, sizeof(_lastError), "getCellsCapacity: no capacity field");
        return false;
    }
    cap += 11;
    while (*cap == ' ' || *cap == '"') cap++;
    if (*cap == '0' && *(cap+1) == 'x') cap += 2;
    *outShannons = (uint64_t)strtoull(cap, nullptr, 16);
    return true;
}

// ─── getScripts ───────────────────────────────────────────────────────────────
// Retrieve currently watched scripts from the light node.
// Useful to verify or restore watch state after reboot.

bool WiFiTransport::getScripts(char* responseBuf, size_t responseBufSize) {
    int len = request("get_scripts", "[]", responseBuf, responseBufSize);
    return len > 0;
}

// ─── getCells ─────────────────────────────────────────────────────────────────
// Fetch live cells for a lock script. Returns JSON array of cells.
// Use limit to cap results, afterCursor for pagination (pass nullptr for first page).

bool WiFiTransport::getCells(const char* codeHashHex, const char* hashType,
                             const char* argsHex,
                             char* responseBuf, size_t responseBufSize,
                             uint32_t limit, const char* afterCursor) {
    char params[512];
    if (afterCursor && *afterCursor) {
        snprintf(params, sizeof(params),
            "[{\"script\":{\"code_hash\":\"%s\",\"hash_type\":\"%s\",\"args\":\"%s\"},"
            "\"script_type\":\"lock\",\"filter\":null,\"limit\":\"0x%x\","
            "\"cursor\":\"%s\"}]",
            codeHashHex, hashType, argsHex, limit, afterCursor);
    } else {
        snprintf(params, sizeof(params),
            "[{\"script\":{\"code_hash\":\"%s\",\"hash_type\":\"%s\",\"args\":\"%s\"},"
            "\"script_type\":\"lock\",\"filter\":null,\"limit\":\"0x%x\"}]",
            codeHashHex, hashType, argsHex, limit);
    }

    int len = request("get_cells", params, responseBuf, responseBufSize);
    return len > 0;
}

// ─── estimateCycles ───────────────────────────────────────────────────────────
// Estimate script execution cycles for a transaction.
// Returns UINT64_MAX on error.

uint64_t WiFiTransport::estimateCycles(const char* txJson) {
    char params[64 + strlen(txJson)];
    snprintf(params, sizeof(params), "[%s]", txJson);

    char resp[128];
    int len = request("estimate_cycles", params, resp, sizeof(resp));
    if (len < 0) return UINT64_MAX;

    const char* cycles = strstr(resp, "\"cycles\":");
    if (!cycles) return UINT64_MAX;
    cycles += 9;
    while (*cycles == ' ' || *cycles == '"') cycles++;
    if (*cycles == '0' && *(cycles+1) == 'x') cycles += 2;
    return (uint64_t)strtoull(cycles, nullptr, 16);
}
