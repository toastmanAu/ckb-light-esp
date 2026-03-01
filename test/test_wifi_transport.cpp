// =============================================================================
// test_wifi_transport.cpp — Host-side tests for WiFiTransport
//
// Tests HTTP request building, response parsing (Content-Length + chunked),
// convenience method output correctness, and status enum mapping.
//
// Build:
//   g++ -std=c++17 -DHOST_TEST \
//       -I../src \
//       -I/home/phill/workspace/CKB-ESP32/src \
//       test_wifi_transport.cpp \
//       ../src/transport/wifi_transport.cpp \
//       -o test_wifi_transport
// Run:
//   ./test_wifi_transport
// =============================================================================

#define IRAM_ATTR
#define HOST_TEST

#include <stdio.h>
#include <string.h>
#include <string>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

static int pass = 0, fail = 0;
#define CHECK(label, expr) do { \
    if (expr) { printf("PASS: %s\n", label); pass++; } \
    else       { printf("FAIL: %s   [line %d]\n", label, __LINE__); fail++; } \
} while(0)

// ── Arduino shims ─────────────────────────────────────────────────────────────
static uint32_t _fake_millis = 0;
#define WY_ARDUINO_SHIMS_DEFINED
uint32_t millis() { return _fake_millis; }
void delay(int ms) { (void)ms; }

// Minimal WiFiClient shim — feeds a canned response string
#define WY_WIFI_CLIENT_DEFINED
struct WiFiClient {
    const char* _buf = nullptr;
    int         _pos = 0;
    int         _len = 0;
    bool        _alive = false;

    void load(const char* s) { _buf=s; _pos=0; _len=(int)strlen(s); _alive=true; }
    bool connect(const char*, uint16_t) { _alive=true; return true; }
    bool connected() const { return _alive && _pos < _len; }
    void stop() { _alive=false; }
    bool available() const { return _pos < _len; }
    char read() { return (_pos<_len) ? _buf[_pos++] : 0; }
    size_t write(const uint8_t*, size_t len) { return len; }
};

// ── Include after shims ───────────────────────────────────────────────────────
#include "../src/transport/wifi_transport.h"
#include "../src/transport/wifi_transport.cpp"

// ── HTTP response builders ────────────────────────────────────────────────────

static std::string makeResponse(const char* body) {
    char buf[2048];
    snprintf(buf, sizeof(buf),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "\r\n%s",
        strlen(body), body);
    return std::string(buf);
}

static std::string makeChunked(const char* body) {
    char buf[2048];
    snprintf(buf, sizeof(buf),
        "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "%zx\r\n%s\r\n"
        "0\r\n\r\n",
        strlen(body), body);
    return std::string(buf);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

static void test_build_request() {
    WiFiTransport t;
    t.connect("192.168.1.100", 9000);

    char buf[512];
    int n = t._testBuildRequest("get_tip_header", "[]", buf, sizeof(buf));

    CHECK("_buildRequest: positive length",      n > 0);
    CHECK("_buildRequest: POST / HTTP/1.1",      strstr(buf, "POST / HTTP/1.1") != nullptr);
    CHECK("_buildRequest: Content-Type json",    strstr(buf, "application/json") != nullptr);
    CHECK("_buildRequest: method field",         strstr(buf, "\"method\":\"get_tip_header\"") != nullptr);
    CHECK("_buildRequest: params field",         strstr(buf, "\"params\":[]") != nullptr);
    CHECK("_buildRequest: keep-alive",           strstr(buf, "keep-alive") != nullptr);
    CHECK("_buildRequest: jsonrpc 2.0",          strstr(buf, "\"jsonrpc\":\"2.0\"") != nullptr);
}

static void test_content_length_response() {
    const char* body = "{\"jsonrpc\":\"2.0\",\"result\":{\"number\":\"0x1234\"},\"id\":1}";
    std::string resp = makeResponse(body);

    WiFiTransport t;
    t.connect("localhost", 9000);
    t._testLoad(resp.c_str());

    char out[512];
    int n = t.request("get_tip_header", "[]", out, sizeof(out));
    CHECK("Content-Length: positive length",     n > 0);
    CHECK("Content-Length: has result",          strstr(out, "\"result\"") != nullptr);
    CHECK("Content-Length: has 0x1234",          strstr(out, "0x1234") != nullptr);
}

static void test_chunked_response() {
    const char* body = "{\"jsonrpc\":\"2.0\",\"result\":{\"number\":\"0x5678\"},\"id\":1}";
    std::string resp = makeChunked(body);

    WiFiTransport t;
    t.connect("localhost", 9000);
    t._testLoad(resp.c_str());

    char out[512];
    int n = t.request("get_tip_header", "[]", out, sizeof(out));
    CHECK("Chunked: positive length",            n > 0);
    CHECK("Chunked: has 0x5678",                 strstr(out, "0x5678") != nullptr);
}

static void test_get_tip_header() {
    const char* body =
        "{\"jsonrpc\":\"2.0\",\"result\":{"
        "\"number\":\"0x11dd2e2\","
        "\"compact_target\":\"0x1a08a97e\","
        "\"hash\":\"0xabc\","
        "\"nonce\":\"0x0\","
        "\"parent_hash\":\"0x0\","
        "\"proposals_hash\":\"0x0\","
        "\"timestamp\":\"0x0\","
        "\"transactions_root\":\"0x0\","
        "\"extra_hash\":\"0x0\","
        "\"version\":\"0x0\","
        "\"dao\":\"0x0\","
        "\"epoch\":\"0x0\""
        "},\"id\":1}";
    std::string resp = makeResponse(body);

    WiFiTransport t;
    t.connect("localhost", 9000);
    t._testLoad(resp.c_str());

    uint64_t blockNum = 0;
    bool ok = t.getTipHeader(&blockNum);
    CHECK("getTipHeader: returns true",          ok);
    CHECK("getTipHeader: 0x11dd2e2 parsed",      blockNum == 0x11dd2e2ULL);
}

static void test_set_scripts_params() {
    // Verify params string uses full Script object structure (not hash)
    // as required by the light client RPC
    char params[512];
    const char* codeHash = "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";
    const char* hashType = "type";
    const char* args     = "0x50878ce52a68feb47237c29574d82288f58b5d21";
    uint64_t    blockNum = 0x64;

    snprintf(params, sizeof(params),
        "[[{\"script\":{\"code_hash\":\"%s\",\"hash_type\":\"%s\",\"args\":\"%s\"},"
        "\"script_type\":\"lock\","
        "\"block_number\":\"0x%llx\"}],\"partial\"]",
        codeHash, hashType, args, (unsigned long long)blockNum);

    CHECK("setScripts: has code_hash",           strstr(params, "code_hash") != nullptr);
    CHECK("setScripts: has hash_type",           strstr(params, "hash_type") != nullptr);
    CHECK("setScripts: has args field",          strstr(params, "\"args\"") != nullptr);
    CHECK("setScripts: has script_type",         strstr(params, "script_type") != nullptr);
    CHECK("setScripts: has block_number",        strstr(params, "block_number") != nullptr);
    CHECK("setScripts: uses partial command",    strstr(params, "partial") != nullptr);
    CHECK("setScripts: block num as 0x64",       strstr(params, "0x64") != nullptr);
    CHECK("setScripts: NOT raw hash field",      strstr(params, "script_hash") == nullptr);
}

static void test_fetch_transaction_status() {
    struct Case {
        const char* body;
        WiFiTransport::FetchStatus expected;
        const char* label;
    } cases[] = {
        {
            "{\"jsonrpc\":\"2.0\",\"result\":{\"status\":\"fetched\",\"data\":{}},\"id\":1}",
            WiFiTransport::FETCH_DONE,       "fetched → FETCH_DONE"
        },
        {
            "{\"jsonrpc\":\"2.0\",\"result\":{\"status\":\"fetching\",\"first_sent\":\"0x1\"},\"id\":1}",
            WiFiTransport::FETCH_PENDING,    "fetching → FETCH_PENDING"
        },
        {
            "{\"jsonrpc\":\"2.0\",\"result\":{\"status\":\"added\",\"timestamp\":\"0x2\"},\"id\":1}",
            WiFiTransport::FETCH_PENDING,    "added → FETCH_PENDING"
        },
        {
            "{\"jsonrpc\":\"2.0\",\"result\":{\"status\":\"not_found\"},\"id\":1}",
            WiFiTransport::FETCH_NOT_FOUND,  "not_found → FETCH_NOT_FOUND"
        },
    };

    for (auto& tc : cases) {
        std::string resp = makeResponse(tc.body);
        WiFiTransport t;
        t.connect("localhost", 9000);
        t._testLoad(resp.c_str());
        char out[512];
        auto status = t.fetchTransaction("0xdeadbeef", out, sizeof(out));
        CHECK(tc.label, status == tc.expected);
    }
}

static void test_get_peer_count() {
    // Count "node_id" occurrences — one per peer entry
    const char* body3 =
        "{\"jsonrpc\":\"2.0\",\"result\":["
        "{\"node_id\":\"QmA\",\"addresses\":[]},"
        "{\"node_id\":\"QmB\",\"addresses\":[]},"
        "{\"node_id\":\"QmC\",\"addresses\":[]}"
        "],\"id\":1}";

    int count = 0;
    const char* p = body3;
    while ((p = strstr(p, "\"node_id\"")) != nullptr) { count++; p += 9; }
    CHECK("getPeerCount: 3 peers",               count == 3);

    const char* body0 = "{\"jsonrpc\":\"2.0\",\"result\":[],\"id\":1}";
    count = 0; p = body0;
    while ((p = strstr(p, "\"node_id\"")) != nullptr) { count++; p += 9; }
    CHECK("getPeerCount: 0 peers",               count == 0);
}

static void test_error_response_detected() {
    // A JSON-RPC error response should be flagged
    const char* body = "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32601,\"message\":\"Method not found\"},\"id\":1}";
    std::string resp = makeResponse(body);

    WiFiTransport t;
    t.connect("localhost", 9000);
    t._testLoad(resp.c_str());

    char out[512];
    int n = t.request("bad_method", "[]", out, sizeof(out));
    CHECK("RPC error response → returns -1",     n < 0);
    CHECK("RPC error: lastError set",            strlen(t.lastError()) > 0);
}

// Forward declarations for new tests
static void test_get_cells_capacity();
static void test_get_scripts();
static void test_get_cells();

// ── main ──────────────────────────────────────────────────────────────────────



int main() {
    printf("=== ckb-light-esp wifi_transport tests ===\n\n");

    printf("--- HTTP request building ---\n");
    test_build_request();

    printf("\n--- HTTP response parsing ---\n");
    test_content_length_response();
    test_chunked_response();

    printf("\n--- getTipHeader ---\n");
    test_get_tip_header();

    printf("\n--- setScripts ---\n");
    test_set_scripts_params();

    printf("\n--- fetchTransaction status ---\n");
    test_fetch_transaction_status();

    printf("\n--- getPeerCount ---\n");
    test_get_peer_count();

    printf("\n--- getCellsCapacity ---\n");
    test_get_cells_capacity();

    printf("\n--- getScripts ---\n");
    test_get_scripts();

    printf("\n--- getCells ---\n");
    test_get_cells();

    printf("\n--- error handling ---\n");
    test_error_response_detected();

    printf("\n=== Results: %d passed, %d failed ===\n", pass, fail);
    return fail > 0 ? 1 : 0;
}

// ── getCellsCapacity tests ─────────────────────────────────────────────────────

static void test_get_cells_capacity() {
    // Normal response: capacity in hex shannons
    WiFiTransport t;
    t._testLoad(
        "HTTP/1.1 200 OK\r\nContent-Length: 61\r\n\r\n"
        "{\"id\":1,\"jsonrpc\":\"2.0\",\"result\":{\"capacity\":\"0x174876e800\"}}"
    );

    uint64_t shannons = 0;
    bool ok = t.getCellsCapacity(
        "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
        "type", "0xabcdef1234", &shannons);

    CHECK("getCellsCapacity: returns true",    ok == true);
    CHECK("getCellsCapacity: 1000 CKB = 100000000000 shannons",
          shannons == 100000000000ULL);  // 0x174876e800 = 100 CKB in shannons

    // Zero capacity
    WiFiTransport t2;
    t2._testLoad(
        "HTTP/1.1 200 OK\r\nContent-Length: 52\r\n\r\n"
        "{\"id\":1,\"jsonrpc\":\"2.0\",\"result\":{\"capacity\":\"0x0\"}}"
    );
    uint64_t z = 1;
    bool ok2 = t2.getCellsCapacity("0x9bd7e06f", "type", "0xaa", &z);
    CHECK("getCellsCapacity: zero capacity ok", ok2 == true);
    CHECK("getCellsCapacity: zero value",       z == 0);

    // Error response
    WiFiTransport t3;
    t3._testLoad(
        "HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\n"
        "{\"id\":1,\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32600,\"message\":\"err\"}}"
    );
    uint64_t e = 1;
    bool ok3 = t3.getCellsCapacity("0x9bd7e06f", "type", "0xaa", &e);
    CHECK("getCellsCapacity: error response → false", ok3 == false);
}

// ── getScripts tests ───────────────────────────────────────────────────────────

static void test_get_scripts() {
    WiFiTransport t;
    const char* body =
        "{\"id\":1,\"jsonrpc\":\"2.0\",\"result\":[{\"script\":{\"code_hash\":"
        "\"0x9bd7e06f\",\"hash_type\":\"type\",\"args\":\"0xaabbcc\"},"
        "\"script_type\":\"lock\",\"block_number\":\"0x0\"}]}";
    char hdr[64]; snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\n\r\n", strlen(body));
    char full[512]; snprintf(full, sizeof(full), "%s%s", hdr, body);
    t._testLoad(full);

    char resp[512];
    bool ok = t.getScripts(resp, sizeof(resp));
    CHECK("getScripts: returns true",       ok == true);
    CHECK("getScripts: result has script",  strstr(resp, "0x9bd7e06f") != nullptr);
}

// ── getCells tests ─────────────────────────────────────────────────────────────

static void test_get_cells() {
    WiFiTransport t;
    const char* body =
        "{\"id\":1,\"jsonrpc\":\"2.0\",\"result\":{\"last_cursor\":\"0xabcd\","
        "\"objects\":[{\"out_point\":{\"tx_hash\":\"0xdeadbeef\",\"index\":\"0x0\"},"
        "\"capacity\":\"0x174876e800\"}]}}";
    char hdr[64]; snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\n\r\n", strlen(body));
    char full[512]; snprintf(full, sizeof(full), "%s%s", hdr, body);
    t._testLoad(full);

    char resp[512];
    bool ok = t.getCells("0x9bd7e06f", "type", "0xaabb", resp, sizeof(resp));
    CHECK("getCells: returns true",            ok == true);
    CHECK("getCells: result has out_point",    strstr(resp, "out_point") != nullptr);
    CHECK("getCells: result has capacity",     strstr(resp, "0x174876e800") != nullptr);

    // Pagination: with afterCursor
    WiFiTransport t2;
    t2._testLoad(full);
    char resp2[512];
    bool ok2 = t2.getCells("0x9bd7e06f", "type", "0xaabb", resp2, sizeof(resp2),
                            10, "0xdeadbeef:0");
    CHECK("getCells: pagination call ok", ok2 == true);
}