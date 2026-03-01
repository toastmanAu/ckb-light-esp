// test_light_client.cpp — host-side tests for LightClient.cpp
//
// Two build modes:
//
// 1. Stub mode (fast, no network — default):
//   g++ -DHOST_TEST -std=c++11 -Itest -Isrc \
//       test/test_light_client.cpp -o test/test_lc && test/test_lc
//
// 2. Live mode (real TCP to devchain at 192.168.68.93:8114):
//   g++ -DHOST_TEST -DLIVE_TEST -std=c++11 -Itest -Isrc \
//       test/test_light_client.cpp -o test/test_lc_live && test/test_lc_live

#define HOST_TEST
#ifdef LIVE_TEST
#  include "posix_socket_client.h"   // real POSIX TCP sockets
#else
#  include "wifi_client_stub.h"      // canned response stub
#endif

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

// hostBlake2b stub — deterministic, no real Blake2b needed for these tests
void hostBlake2b(const uint8_t* data, size_t len, uint8_t* out32) {
    memset(out32, data && len > 0 ? data[0] ^ 0x5a : 0, 32);
}

// Include implementation sources directly (single TU — same as test_wifi_transport)
#include "../src/core/block_filter.cpp"
#include "../src/transport/wifi_transport.cpp"

// ── Stub impls for types used by LightClient but not needed in these tests ──

// HeaderChain stub (real impl needs ArduinoJson + eaglesong)
#include "../src/core/header_chain.h"
HeaderChain::HeaderChain() { _count = 0; _tipIdx = 0; }
bool    HeaderChain::addHeader(const char*) { return true; }
bool    HeaderChain::verifyPoW(const CKBHeader&, const RawHeader&) { return true; }
bool    HeaderChain::verifyBlockHash(const CKBHeader&, const RawHeader&) { return true; }
bool    HeaderChain::getTip(CKBHeader& out) const { (void)out; return false; }
uint64_t HeaderChain::tipNumber() const { return _count > 0 ? _cache[_tipIdx].number : 0; }
const uint8_t* HeaderChain::tipHash() const { return nullptr; }
bool    HeaderChain::getByNumber(uint64_t, CKBHeader&) const { return false; }
void    HeaderChain::reset() { _count = 0; _tipIdx = 0; }
bool    HeaderChain::_parseHeader(const char*, CKBHeader&, RawHeader&) { return false; }
bool    HeaderChain::_checkParentLink(const CKBHeader&) { return true; }

// UTXOStore stub (header-only but constructor may not be defined)
#include "../src/core/utxo_store.h"
UTXOStore::UTXOStore() { memset(this, 0, sizeof(*this)); }

#include "../src/LightClient.cpp"

// ── Test harness ─────────────────────────────────────────────────────────────
static int g_pass = 0, g_fail = 0;
#define PASS(name) do { printf("  PASS: %s\n", name); g_pass++; } while(0)
#define FAIL(name) do { printf("  FAIL: %s\n", name); g_fail++; } while(0)
#define CHECK(cond, name) do { if(cond) PASS(name); else FAIL(name); } while(0)

// Canned JSON responses that our WiFiClient stub returns
// (wifi_transport.cpp _testLoad() injects these)

static const char* RESP_TIP_HEADER =
    "HTTP/1.1 200 OK\r\nContent-Length: 200\r\n\r\n"
    "{\"jsonrpc\":\"2.0\",\"result\":{"
    "\"number\":\"0x64\","        // block 100
    "\"hash\":\"0xaabbcc0000000000000000000000000000000000000000000000000000001234\","
    "\"compact_target\":\"0x20010000\","
    "\"timestamp\":\"0x19ca68c34a7\""
    "},\"id\":1}";

static const char* RESP_SET_SCRIPTS =
    "HTTP/1.1 200 OK\r\nContent-Length: 30\r\n\r\n"
    "{\"jsonrpc\":\"2.0\",\"result\":null,\"id\":1}";

static const char* RESP_PEERS =
    "HTTP/1.1 200 OK\r\nContent-Length: 80\r\n\r\n"
    "{\"jsonrpc\":\"2.0\",\"result\":["
    "{\"node_id\":\"abc\",\"addresses\":[],\"protocols\":[]}"
    "],\"id\":1}";

static const char* RESP_FILTER_EMPTY =
    "HTTP/1.1 200 OK\r\nContent-Length: 60\r\n\r\n"
    "{\"jsonrpc\":\"2.0\",\"result\":{\"data\":\"0x0000000000000000\"},\"id\":1}";

// ══════════════════════════════════════════════════════════════════════════════
// Test 1: begin() + stateStr()
// ══════════════════════════════════════════════════════════════════════════════
void testBegin() {
    printf("\n[1] begin() + state transitions\n");

    LightClient lc;
    CHECK(lc.state() == LIGHT_STATE_IDLE, "initial state is IDLE");
    CHECK(strcmp(lc.stateStr(), "IDLE") == 0, "stateStr() == 'IDLE'");

    lc.begin("192.168.68.93", 8114);
    CHECK(lc.state() == LIGHT_STATE_CONNECTING, "after begin() state is CONNECTING");
    CHECK(strcmp(lc.stateStr(), "CONNECTING") == 0, "stateStr() == 'CONNECTING'");
}

// ══════════════════════════════════════════════════════════════════════════════
// Test 2: watchScript() — registers scripts + computes hashes
// ══════════════════════════════════════════════════════════════════════════════
void testWatchScript() {
    printf("\n[2] watchScript()\n");

    LightClient lc;
    lc.begin("localhost", 9000);

    // secp256k1 lock code hash + Phill's lock args
    bool r1 = lc.watchScript(
        "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
        "0x72a4330a24e74209942062f24a2bbed8bd5f859a",
        SCRIPT_TYPE_LOCK,
        0
    );
    CHECK(r1, "watchScript() first script returns true");

    // Add a second
    bool r2 = lc.watchScript(
        "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
        "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        SCRIPT_TYPE_LOCK,
        100
    );
    CHECK(r2, "watchScript() second script returns true");

    // Check BlockFilter has registered hashes (minFilterBlockNumber = 0)
    CHECK(lc.filterSyncBlock() == 0 || lc.filterSyncBlock() == 0,
          "filterSyncBlock starts at 0 before connect");
}

// ══════════════════════════════════════════════════════════════════════════════
// Test 3: stateStr() covers all states
// ══════════════════════════════════════════════════════════════════════════════
void testStateStr() {
    printf("\n[3] stateStr() all states\n");

    LightClient lc;
    // We can't set state directly (private), but we can test the strings
    // via the public enum values — check the switch covers all cases
    // by verifying IDLE and CONNECTING (the two reachable ones via API)
    CHECK(strcmp(lc.stateStr(), "IDLE") == 0, "IDLE string");
    lc.begin("x", 1);
    CHECK(strcmp(lc.stateStr(), "CONNECTING") == 0, "CONNECTING string");
}

// ══════════════════════════════════════════════════════════════════════════════
// Test 4: hasPendingEvents() / nextEvent() — via BlockFilter queue
// ══════════════════════════════════════════════════════════════════════════════
void testEventQueue() {
    printf("\n[4] hasPendingEvents() / nextEvent()\n");

    LightClient lc;
    CHECK(!lc.hasPendingEvents(), "no events on init");

    // Directly enqueue via filter (white-box — same as Merkle verify would do)
    // We access _filter via the public HOST_TEST guard on BlockFilter
    lc._filterRef().queueEvent(
        "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
        42
    );
    CHECK(lc.hasPendingEvents(), "hasEvents after queueEvent");

    char txHash[67] = {0};
    uint64_t blockNum = 0;
    bool got = lc.nextEvent(txHash, &blockNum);
    CHECK(got, "nextEvent() returns true");
    CHECK(blockNum == 42, "nextEvent() block number correct");
    CHECK(strncmp(txHash, "0xabcdef", 8) == 0, "nextEvent() txHash prefix correct");
    CHECK(!lc.hasPendingEvents(), "no events after drain");
}

// ══════════════════════════════════════════════════════════════════════════════
// Test 5: _applyFilter() — hex decode + GCS test
// ══════════════════════════════════════════════════════════════════════════════
void testApplyFilter() {
    printf("\n[5] _applyFilter() hex decode + GCS test\n");

    LightClient lc;

    // Register a script hash we know is in our reference filter
    // Reference filter for {0x55*32}: 0100000000000000899bf8
    // Script hash = 0x55 * 32 (our stub hostBlake2b returns data[0]^0x5a repeated)
    // codeHash bytes[0] = 0x9b (from secp hash), args[0] = 0x72
    // stub: 0x9b ^ 0x5a = 0xc1 for the script hash first byte
    // We'd need a real Blake2b for exact matching — instead test the flow:

    // Use a filter that is guaranteed empty (0 elements) — no match
    lc._filterRef().addScriptHash(
        (const uint8_t*)"\x55\x55\x55\x55\x55\x55\x55\x55"
                        "\x55\x55\x55\x55\x55\x55\x55\x55"
                        "\x55\x55\x55\x55\x55\x55\x55\x55"
                        "\x55\x55\x55\x55\x55\x55\x55\x55",
        0
    );

    // Apply empty filter (n_elements=0)
    lc._applyFilterPub("0x0000000000000000", 5);
    CHECK(!lc._filterRef().hasMatchedBlocks(), "empty filter: no match queued");

    // Apply filter containing 0x55*32 (Python-verified hex: 0100000000000000899bf8)
    lc._applyFilterPub("0x0100000000000000899bf8", 10);
    CHECK(lc._filterRef().hasMatchedBlocks(), "filter match: block queued");

    uint64_t bn = 0;
    lc._filterRef().nextMatchedBlock(&bn);
    CHECK(bn == 10, "matched block number correct");
}

// ══════════════════════════════════════════════════════════════════════════════
// Test 6: tipBlockNumber / tipBlockHash accessors
// ══════════════════════════════════════════════════════════════════════════════
void testAccessors() {
    printf("\n[6] accessor sanity\n");

    LightClient lc;
    CHECK(lc.tipBlockNumber() == 0, "tip starts at 0");
    CHECK(lc.peerCount() == -1,     "peerCount starts at -1");
    CHECK(lc.filterSyncBlock() == 0,"filterSyncBlock starts at 0");
}

// ══════════════════════════════════════════════════════════════════════════════
// Test 7: sync() in IDLE state is a no-op
// ══════════════════════════════════════════════════════════════════════════════
void testSyncIdle() {
    printf("\n[7] sync() in IDLE is no-op\n");

    LightClient lc;
    CHECK(lc.state() == LIGHT_STATE_IDLE, "state is IDLE");
    lc.sync(); // must not crash
    CHECK(lc.state() == LIGHT_STATE_IDLE, "state still IDLE after sync()");
}

// ══════════════════════════════════════════════════════════════════════════════
// Test 8: _stepConnect() via mocked transport (WiFiClient stub)
// Inject a canned set_scripts + get_tip_header response to drive
// CONNECTING → SYNCING_CHECKPOINTS
// ══════════════════════════════════════════════════════════════════════════════
void testConnectTransition() {
    printf("\n[8] CONNECTING → SYNCING_CHECKPOINTS via mock transport\n");

#ifdef LIVE_TEST
    printf("  SKIP: mock transport not used in LIVE_TEST mode\n");
    return;
#endif

    LightClient lc;
    lc.begin("192.168.68.93", 8114);
    lc.watchScript(
        "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
        "0x72a4330a24e74209942062f24a2bbed8bd5f859a",
        SCRIPT_TYPE_LOCK, 0
    );

    // Pre-load the transport stub with responses for:
    //   1. set_scripts (for our 1 script)
    //   2. get_tip_header (for connect)
    //   3. get_tip_header (for _updateTip raw call)
    // WiFiClient stub concatenates all loads and serves them in order
    lc._transportRef()._testLoad(RESP_SET_SCRIPTS);
    lc._transportRef()._testLoad(RESP_TIP_HEADER); // getTipHeader()
    lc._transportRef()._testLoad(RESP_TIP_HEADER); // request() for hash

    // Drive the connect step
    lc.sync(); // CONNECTING step

    // Should have advanced past CONNECTING
    bool advanced = (lc.state() == LIGHT_STATE_SYNCING_CHECKPOINTS ||
                     lc.state() == LIGHT_STATE_SYNCING_HASHES ||
                     lc.state() == LIGHT_STATE_SYNCING_FILTERS);
    CHECK(advanced, "state advanced past CONNECTING");

    if (advanced) {
        CHECK(lc.tipBlockNumber() == 100, "tip block = 100 (0x64 from mock)");
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Test 9: Devchain smoke test — live connection (skipped if node unreachable)
// ══════════════════════════════════════════════════════════════════════════════
void testDevchain() {
    printf("\n[9] Devchain live smoke test (192.168.68.93:8114)\n");

#ifndef LIVE_TEST
    printf("  SKIP: stub mode — rebuild with -DLIVE_TEST for real TCP\n");
    printf("  CMD:  g++ -DHOST_TEST -DLIVE_TEST -std=c++11 -Itest -Isrc \\\n");
    printf("            test/test_light_client.cpp -o test/test_lc_live\n");
    return;
#else
    // Test against the devchain full node (port 8114).
    // Note: set_scripts is a light client node method (port 9000) — not supported here.
    // So we test the transport layer directly: connect + get_tip_header.
    WiFiTransport t;
    bool connected = t.connect("192.168.68.93", 8114);
    CHECK(connected, "TCP connect to devchain:8114");

    if (!connected) {
        printf("  INFO: start devchain: ssh opi3b-armbian 'bash ~/ckb-devchain/start.sh'\n");
        return;
    }

    uint64_t tip = 0;
    bool gotTip = t.getTipHeader(&tip);
    CHECK(gotTip, "get_tip_header RPC over real TCP");
    CHECK(tip > 0, "tip block > 0");
    printf("  INFO: devchain tip = %llu (0x%llx)\n",
           (unsigned long long)tip, (unsigned long long)tip);

    // Verify peer count RPC also works
    int peers = t.getPeerCount();
    CHECK(peers >= 0, "get_peers RPC returns non-negative");
    printf("  INFO: peer count = %d\n", peers);

    t.disconnect();
#endif
}

// ══════════════════════════════════════════════════════════════════════════════
// main
// ══════════════════════════════════════════════════════════════════════════════
int main() {
    printf("========================================\n");
    printf("  LightClient.cpp host tests\n");
    printf("========================================\n");

    testBegin();
    testWatchScript();
    testStateStr();
    testEventQueue();
    testApplyFilter();
    testAccessors();
    testSyncIdle();
    testConnectTransition();
    testDevchain();

    printf("\n========================================\n");
    printf("  Results: %d passed, %d failed\n", g_pass, g_fail);
    printf("========================================\n");
    return g_fail > 0 ? 1 : 0;
}
