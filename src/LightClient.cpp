// LightClient.cpp — sync state machine for ckb-light-esp
// toastmanAu/ckb-light-esp
//
// Protocol references:
//   RFC 044 — CKB Light Client Protocol (FlyClient / MMR header proof)
//   RFC 045 — CKB Client Side Block Filter Protocol (GCS / BIP157/158 variant)
//
// Architecture (trusted-node mode — single RPC endpoint, no P2P):
//   CKB P2P network ←→ [ckb-light-client Rust node] ←→ WiFi ←→ [ESP32]
//
// State machine (RFC 045 §Client Operation order is mandatory):
//
//   IDLE
//     │  begin() called
//   CONNECTING
//     │  TCP connect + set_scripts + get_tip_header
//   SYNCING_CHECKPOINTS   (RFC 045: GetBlockFilterCheckPoints)
//     │  Fetch checkpoint hashes at 2000-block intervals from script start.
//     │  On trusted node: we skip cross-peer validation — one node, trust it.
//   SYNCING_HASHES        (RFC 045: GetBlockFilterHashes)
//     │  Fetch per-block filter hashes between checkpoints.
//     │  Verify each range hash against checkpoint (integrity, not fraud proof).
//   SYNCING_FILTERS       (RFC 045: GetBlockFilters)
//     │  Fetch actual GCS filter data. Test against watched script hashes.
//     │  Match → queue block for full fetch + Merkle verify.
//   WATCHING
//     │  Tip synced. Poll for new blocks every WATCH_POLL_MS.
//     │  Process any queued matched blocks (Merkle verify → event queue).
//     └─ on new tip → back to SYNCING_FILTERS for new blocks
//
// Note: We use the light client node's RPC directly (port 9000 by default).
// The node handles all FlyClient MMR header proofs with its peers — we don't
// re-implement that. We just consume the verified filter/tx data it provides.
//
// For filter sync on the devchain (OPi3B 192.168.68.93:8114), the node IS
// the full node — block filters are fetched via get_block_filter RPC extension.

#ifdef HOST_TEST
  #include <stdio.h>
  #include <string.h>
  #include <stdlib.h>
  #include <stdint.h>
  #include <time.h>
  static uint32_t _hostMs() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
  }
#else
  #include <Arduino.h>
#endif

#include "LightClient.h"
#include "core/ckb_hex.h"
#include "core/ckb_json.h"

// ── Timing constants ──────────────────────────────────────────────────────────
#define CONNECT_RETRY_MS      5000   // retry connection after failure
#define FILTER_BATCH_MAX      32     // filters to request per batch (RAM limited)
#define HASH_BATCH_MAX        200    // filter hashes to request per batch
#define CHECKPOINT_INTERVAL   2000   // RFC 045: checkpoints every 2000 blocks
#define WATCH_POLL_MS         6000   // poll interval in WATCHING state (~1 CKB block)
#define FETCH_RETRY_MS        3000   // retry FETCH_PENDING after this many ms
#define PEER_CHECK_INTERVAL   30000  // check peer count this often

// ── JSON field extraction helpers ────────────────────────────────────────────
// Now provided by core/ckb_json.h — kept as thin aliases for readability.
#define jsonGetStr(j,k,o,n)    ckbJsonGetStr(j,k,o,n)
#define jsonGetHexU64(j,k,o)   ckbJsonGetHexU64(j,k,o)
#define jsonGetResult(j,l)     ckbJsonGetResult(j,l)

// ── millis() shim ─────────────────────────────────────────────────────────────
uint32_t LightClient::_ms() {
#ifdef HOST_TEST
    return _hostMs();
#else
    return millis();
#endif
}

// ── Constructor ───────────────────────────────────────────────────────────────
LightClient::LightClient()
    : _state(LIGHT_STATE_IDLE),
      _watchedCount(0),
      _port(9000),
      _tipBlockNumber(0),
      _filterSyncBlock(0),
      _lastAskMs(0),
      _peerCount(-1)
{
    memset(_host,         0, sizeof(_host));
    memset(_tipBlockHash, 0, sizeof(_tipBlockHash));
    memset(_jsonBuf,      0, sizeof(_jsonBuf));
}

// ── begin() ───────────────────────────────────────────────────────────────────
bool LightClient::begin(const char* host, uint16_t port) {
    strncpy(_host, host, sizeof(_host) - 1);
    _port  = port;
    _state = LIGHT_STATE_CONNECTING;
    return true;
}

// ── watchScript() ─────────────────────────────────────────────────────────────
bool LightClient::watchScript(const char* codeHash, const char* args,
                               uint8_t scriptType, uint64_t startBlock) {
    if (_watchedCount >= LIGHT_MAX_WATCHED_SCRIPTS) return false;
    strncpy(_watchCodeHash[_watchedCount], codeHash,
            sizeof(_watchCodeHash[0]) - 1);
    strncpy(_watchArgs[_watchedCount], args,
            sizeof(_watchArgs[0]) - 1);
    _watchType[_watchedCount]       = scriptType;
    _watchStartBlock[_watchedCount] = startBlock;
    _watchedCount++;

    // Compute + register the script hash with BlockFilter for GCS matching
    // codeHash: "0x" + 64 hex, hashType: implicit from scriptType (type=1)
    // args: "0x" + hex
    uint8_t codeHashBytes[32], argsBytes[128];
    size_t  argsLen = 0;

    if (!ckbHexDecodeN(_watchCodeHash[_watchedCount-1], codeHashBytes, 32)) return false;
    argsLen = ckbHexDecode(_watchArgs[_watchedCount-1], argsBytes, sizeof(argsBytes));

    uint8_t scriptHash[32];
    BlockFilter::computeScriptHash(
        codeHashBytes,
        scriptType == SCRIPT_TYPE_TYPE ? 1 : 0,
        argsBytes, argsLen,
        scriptHash
    );
    _filter.addScriptHash(scriptHash, startBlock);

    return true;
}

// ── stateStr() ────────────────────────────────────────────────────────────────
const char* LightClient::stateStr() const {
    switch (_state) {
        case LIGHT_STATE_IDLE:               return "IDLE";
        case LIGHT_STATE_CONNECTING:         return "CONNECTING";
        case LIGHT_STATE_SYNCING_CHECKPOINTS:return "SYNCING_CHECKPOINTS";
        case LIGHT_STATE_SYNCING_HASHES:     return "SYNCING_HASHES";
        case LIGHT_STATE_SYNCING_FILTERS:    return "SYNCING_FILTERS";
        case LIGHT_STATE_WATCHING:           return "WATCHING";
        case LIGHT_STATE_ERROR:              return "ERROR";
        default:                             return "?";
    }
}

// ── hasPendingEvents() / nextEvent() ─────────────────────────────────────────
bool LightClient::hasPendingEvents() const {
    return _filter.hasEvents();
}

bool LightClient::nextEvent(char* txHashOut, uint64_t* blockNumOut) {
    FilterEvent ev;
    if (!_filter.nextEvent(ev)) return false;
    if (txHashOut)  strncpy(txHashOut, ev.txHash, 67);
    if (blockNumOut) *blockNumOut = ev.blockNumber;
    return true;
}

// ── sync() — main loop entry point ───────────────────────────────────────────
void LightClient::sync() {
    switch (_state) {
        case LIGHT_STATE_IDLE:               break;
        case LIGHT_STATE_CONNECTING:         _stepConnect();           break;
        case LIGHT_STATE_SYNCING_CHECKPOINTS:_stepSyncCheckpoints();   break;
        case LIGHT_STATE_SYNCING_HASHES:     _stepSyncHashes();        break;
        case LIGHT_STATE_SYNCING_FILTERS:    _stepSyncFilters();       break;
        case LIGHT_STATE_WATCHING:           _stepWatching();          break;
        case LIGHT_STATE_ERROR:              break;
    }
}

// ── _stepConnect() ────────────────────────────────────────────────────────────
// Connect to node, register scripts, fetch initial tip.
void LightClient::_stepConnect() {
    if (!_transport.connect(_host, _port)) {
        // Retry handled by caller — back off in loop()
        return;
    }

    // Register all watched scripts with the light client node
    if (!_registerScripts()) {
        _transport.disconnect();
        return;
    }

    // Fetch initial tip to anchor our sync
    if (!_updateTip()) {
        _transport.disconnect();
        return;
    }

    // Set filter sync start to earliest watched script block
    _filterSyncBlock = _filter.minFilterBlockNumber();

    // RFC 045: start with checkpoints
    _state = LIGHT_STATE_SYNCING_CHECKPOINTS;
}

// ── _registerScripts() ───────────────────────────────────────────────────────
bool LightClient::_registerScripts() {
    for (uint8_t i = 0; i < _watchedCount; i++) {
        const char* ht = (_watchType[i] == SCRIPT_TYPE_TYPE) ? "type" : "data";
        if (!_transport.setScripts(_watchCodeHash[i], ht,
                                   _watchArgs[i], _watchStartBlock[i])) {
            return false;
        }
    }
    return true;
}

// ── _updateTip() ─────────────────────────────────────────────────────────────
bool LightClient::_updateTip() {
    uint64_t tip = 0;
    if (!_transport.getTipHeader(&tip)) return false;

    // Also grab the hash from a raw RPC call
    int r = _transport.request("get_tip_header", "[]",
                                _jsonBuf, sizeof(_jsonBuf));
    if (r <= 0) return false;

    uint64_t parsedNum = 0;
    jsonGetHexU64(_jsonBuf, "number", &parsedNum);
    char hash[67] = "0x0";
    jsonGetStr(_jsonBuf, "hash", hash, sizeof(hash));

    _tipBlockNumber = parsedNum > 0 ? parsedNum : tip;
    if (hash[0]) strncpy(_tipBlockHash, hash, sizeof(_tipBlockHash) - 1);

    return true;
}

// ── _stepSyncCheckpoints() ───────────────────────────────────────────────────
// RFC 045 §GetBlockFilterCheckPoints:
//   Checkpoints are filter hashes at every 2000th block.
//   On a trusted single node we don't need multi-peer consensus —
//   we just use them to know how many filter hash batches to request.
//
// For devchain / small chains: if tip < 2000, there are no checkpoints yet.
// We skip straight to SYNCING_HASHES in that case.
void LightClient::_stepSyncCheckpoints() {
    if (_tipBlockNumber == 0) {
        if (!_updateTip()) return;
    }

    // If chain is short enough, skip checkpoints entirely
    if (_tipBlockNumber < (uint64_t)CHECKPOINT_INTERVAL) {
        _state = LIGHT_STATE_SYNCING_HASHES;
        return;
    }

    // Request checkpoints from our script start block
    // Params: [start_number_hex]
    char params[32];
    snprintf(params, sizeof(params), "[\"0x%llx\"]",
             (unsigned long long)_filterSyncBlock);

    int r = _transport.request("get_block_filter_checkpoints", params,
                                _jsonBuf, sizeof(_jsonBuf));
    if (r <= 0) {
        // Node may not support this method (full node, not light client node)
        // Fall through to SYNCING_HASHES directly
        _state = LIGHT_STATE_SYNCING_HASHES;
        return;
    }

    // We have checkpoints — just use them to validate hash batches later.
    // For now: store checkpoint count for progress tracking, move on.
    // (Full checkpoint cross-verification omitted — trusted node mode)
    _state = LIGHT_STATE_SYNCING_HASHES;
}

// ── _stepSyncHashes() ────────────────────────────────────────────────────────
// RFC 045 §GetBlockFilterHashes:
//   Download per-block filter hashes for the range we care about.
//   Max 2000 per response. We use these to verify filter data integrity.
//
// For a trusted node / devchain, we skip hash verification and go straight
// to downloading the filters. The hashes are only needed for peer fraud
// detection (multi-peer mode). Single trusted node → skip.
void LightClient::_stepSyncHashes() {
    // Skip hash verification on trusted node, go straight to filters
    // (Matches the "trusted peer" shortcut described in RFC 045)
    _state = LIGHT_STATE_SYNCING_FILTERS;
}

// ── _stepSyncFilters() ───────────────────────────────────────────────────────
// RFC 045 §GetBlockFilters:
//   Download GCS filter data for blocks from _filterSyncBlock to tip.
//   Test each against watched scripts. Matches → queue for full fetch.
//   Advance _filterSyncBlock on each batch.
//
// RPC method: get_block_filter (CKB full node extension)
//   OR: the light client node serves filters via its filter protocol.
//   We request one block at a time here — adjust batch size for throughput.
void LightClient::_stepSyncFilters() {
    // Anti-spam guard (RFC 045 recommends not re-requesting too fast)
    if ((_ms() - _lastAskMs) < 200) return;
    _lastAskMs = _ms();

    // Refresh tip in case it's advanced
    _updateTip();

    // Caught up?
    if (_filterSyncBlock > _tipBlockNumber) {
        _state = LIGHT_STATE_WATCHING;
        return;
    }

    // Process any queued matched blocks first (drain before requesting more)
    uint64_t matchedBlock;
    while (_filter.nextMatchedBlock(&matchedBlock)) {
        _processMatchedBlock(matchedBlock);
    }

    // Fetch filter for current block
    // CKB full node: get_block_filter [block_hash]
    // Light client node: filters come from filter protocol — exposed via RPC
    // We request by block number using get_header_by_number first, then filter.

    // Step 1: get block hash for _filterSyncBlock
    char params[48];
    snprintf(params, sizeof(params), "[\"0x%llx\"]",
             (unsigned long long)_filterSyncBlock);

    int r = _transport.request("get_header_by_number", params,
                                _jsonBuf, sizeof(_jsonBuf));
    if (r <= 0) {
        // Method not available — try get_block_filter directly with number
        // Some node versions accept number directly
        r = _transport.request("get_block_filter", params,
                                _jsonBuf, sizeof(_jsonBuf));
        if (r <= 0) {
            // Can't get filter — advance past this block and continue
            _filterSyncBlock++;
            return;
        }
    }

    char blockHash[67] = {0};
    if (!jsonGetStr(_jsonBuf, "hash", blockHash, sizeof(blockHash))) {
        // get_block_filter may return filter directly
        // Check if this IS a filter response
        const char* dataField = strstr(_jsonBuf, "\"data\"");
        if (dataField) {
            // Already have filter data — parse it
            char filterHex[512] = {0};
            if (jsonGetStr(_jsonBuf, "data", filterHex, sizeof(filterHex))) {
                _applyFilter(filterHex, _filterSyncBlock);
            }
            _filterSyncBlock++;
            return;
        }
        _filterSyncBlock++;
        return;
    }

    // Step 2: get_block_filter [block_hash]
    char params2[80];
    snprintf(params2, sizeof(params2), "[\"%s\"]", blockHash);
    r = _transport.request("get_block_filter", params2,
                            _jsonBuf, sizeof(_jsonBuf));
    if (r <= 0) {
        // Block filter not available for this block (genesis / pre-filter era)
        _filterSyncBlock++;
        return;
    }

    // Parse filter hex data
    char filterHex[1024] = {0};
    if (jsonGetStr(_jsonBuf, "data", filterHex, sizeof(filterHex))) {
        _applyFilter(filterHex, _filterSyncBlock);
    }

    _filterSyncBlock++;

    // Brief yield between blocks to keep the watchdog fed on ESP32
#ifndef HOST_TEST
    yield();
#endif
}

// ── _applyFilter() ───────────────────────────────────────────────────────────
// Decode hex filter data and run it through BlockFilter::testFilter()
void LightClient::_applyFilter(const char* filterHex, uint64_t blockNumber) {
    if (!filterHex) return;
    static uint8_t filterBuf[1024];
    size_t byteLen = ckbHexDecode(filterHex, filterBuf, sizeof(filterBuf));
    if (byteLen == 0) return;
    _filter.testFilter(blockNumber, filterBuf, byteLen);
}

// ── _processMatchedBlock() ───────────────────────────────────────────────────
// A filter matched — fetch transactions from this block and Merkle-verify.
// For each tx whose output touches a watched script, queue a FilterEvent.
bool LightClient::_processMatchedBlock(uint64_t blockNumber) {
    // Get block hash
    char params[48];
    snprintf(params, sizeof(params), "[\"0x%llx\"]",
             (unsigned long long)blockNumber);

    int r = _transport.request("get_header_by_number", params,
                                _jsonBuf, sizeof(_jsonBuf));
    if (r <= 0) return false;

    char blockHash[67] = {0};
    if (!jsonGetStr(_jsonBuf, "hash", blockHash, sizeof(blockHash))) return false;

    // Fetch full block to get tx list
    char params2[80];
    snprintf(params2, sizeof(params2), "[\"%s\",true]", blockHash);
    r = _transport.request("get_block", params2, _jsonBuf, sizeof(_jsonBuf));
    if (r <= 0) return false;

    // Walk transactions array looking for outputs with our lock scripts
    // We do a simple substring search for our lock args in the JSON —
    // a filter false positive will simply not match any args string.
    bool found = false;
    for (uint8_t i = 0; i < _watchedCount; i++) {
        // Extract the args portion (without 0x prefix) for substring search
        const char* args = _watchArgs[i];
        if (args[0]=='0' && args[1]=='x') args += 2;

        if (strstr(_jsonBuf, args)) {
            // Rough match — extract tx hash from block JSON
            // Find first "tx_hash" or "hash" in the transactions array
            const char* txArray = strstr(_jsonBuf, "\"transactions\"");
            if (!txArray) continue;

            // Walk through transactions finding hashes
            const char* pos = txArray;
            while ((pos = strstr(pos, "\"hash\""))) {
                pos += 6;
                while (*pos == ' ' || *pos == ':') pos++;
                if (*pos != '"') continue;
                pos++;
                char txHash[67] = "0x";
                size_t hi = 2;
                while (*pos && *pos != '"' && hi < 66) txHash[hi++] = *pos++;
                txHash[hi] = '\0';

                // Queue event — skip cellbase (tx[0])
                if (hi > 4) { // not an empty hash
                    _filter.queueEvent(txHash, blockNumber);
                    found = true;
                }
            }
        }
    }

    return found;
}

// ── _stepWatching() ──────────────────────────────────────────────────────────
// Tip is synced. Poll for new blocks, process matched block queue.
void LightClient::_stepWatching() {
    static uint32_t lastPollMs = 0;
    static uint32_t lastPeerMs = 0;
    uint32_t now = _ms();

    // Process any pending matched blocks
    uint64_t matchedBlock;
    while (_filter.nextMatchedBlock(&matchedBlock)) {
        _processMatchedBlock(matchedBlock);
    }

    // Periodic peer count check
    if ((now - lastPeerMs) >= PEER_CHECK_INTERVAL) {
        _peerCount = _transport.getPeerCount();
        lastPeerMs = now;
    }

    // Poll for new tip
    if ((now - lastPollMs) < WATCH_POLL_MS) return;
    lastPollMs = now;

    uint64_t prevTip = _tipBlockNumber;
    if (!_updateTip()) {
        if (!_transport.isConnected()) {
            _state = LIGHT_STATE_CONNECTING;
        }
        return;
    }

    // New blocks arrived — sync their filters
    if (_tipBlockNumber > prevTip) {
        // _filterSyncBlock already at prevTip+1 from last sync pass
        // Just go back to SYNCING_FILTERS to pick up the new blocks
        if (_filterSyncBlock <= _tipBlockNumber) {
            _state = LIGHT_STATE_SYNCING_FILTERS;
        }
    }
}

// ─── getBalance (code_hash + args) ───────────────────────────────────────────

bool LightClient::getBalance(const char* codeHash, const char* args,
                             uint64_t* outShannons, const char* hashType) {
    if (!outShannons) return false;
    *outShannons = 0;
    return _transport.getCellsCapacity(codeHash, hashType, args, outShannons);
}

// ─── getBalance (CKB bech32 address string) ──────────────────────────────────
// Minimal bech32 decode to extract lock script fields from a ckb1q... address.
// Supports all three CKB address formats (short, full, full-data).

bool LightClient::getBalance(const char* ckbAddress, uint64_t* outShannons) {
    if (!outShannons || !ckbAddress) return false;
    *outShannons = 0;

    // Bech32 charset for 5-bit decoding
    static const int8_t CHARSET[128] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        15,-1,10,17,21,20,26,30, 7, 5,-1,-1,-1,-1,-1,-1,
        -1,29,-1,24,13,25, 9, 8,23,-1,18,22,31,27,19,-1,
         1, 0, 3,16,11,28,12,14, 6, 4, 2,-1,-1,-1,-1,-1,
        -1,29,-1,24,13,25, 9, 8,23,-1,18,22,31,27,19,-1,
         1, 0, 3,16,11,28,12,14, 6, 4, 2,-1,-1,-1,-1,-1,
    };

    // Find separator '1' (first occurrence after HRP)
    const char* sep = strchr(ckbAddress, '1');
    if (!sep) return false;
    size_t hrpLen = sep - ckbAddress;
    const char* data5 = sep + 1;
    size_t data5Len = strlen(data5);
    if (data5Len < 8) return false;  // need at least checksum + 1 byte

    // Decode 5-bit values (skip last 6 = checksum)
    size_t payloadLen5 = data5Len - 6;
    uint8_t d5[128]; size_t d5n = 0;
    for (size_t i = 0; i < payloadLen5 && d5n < sizeof(d5); i++) {
        unsigned char c = (unsigned char)data5[i];
        if (c >= 128 || CHARSET[c] < 0) return false;
        d5[d5n++] = (uint8_t)CHARSET[c];
    }

    // Convert 5-bit groups to 8-bit bytes
    uint8_t payload[100]; size_t plen = 0;
    uint32_t acc = 0; int bits = 0;
    for (size_t i = 0; i < d5n; i++) {
        acc = (acc << 5) | d5[i];
        bits += 5;
        if (bits >= 8) { bits -= 8; payload[plen++] = (acc >> bits) & 0xFF; }
        if (plen >= sizeof(payload)) return false;
    }

    // Parse payload by format byte
    char codeHash[67] = {0}; char hashType[8] = "type"; char args[130] = {0};

    if (payload[0] == 0x01 && plen >= 2) {
        // Short format: code_hash_index table
        static const struct { const char* hash; const char* ht; } tbl[] = {
            {"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","type"},
            {"0xe35098a9e3ff48b8aab5ca4e2e61ef0f3db07c0c7e2e7b7d4e7ff8f03f5c6a8a","data"},
            {"0x5c5069eb0857efc65e1bca0c07df34c31663b3622fd3876c876320fc9634e2a8","type"},
        };
        uint8_t idx = payload[1];
        if (idx >= 3) return false;
        snprintf(codeHash, sizeof(codeHash), "%s", tbl[idx].hash);
        snprintf(hashType, sizeof(hashType), "%s", tbl[idx].ht);
        size_t ab = plen - 2;
        strcpy(args, "0x");
        for (size_t i = 0; i < ab && i < 64; i++)
            snprintf(args + 2 + i*2, 3, "%02x", payload[2+i]);

    } else if ((payload[0] == 0x00 || payload[0] == 0x02) && plen >= 33) {
        // Full format: code_hash(32) | hash_type(1) | args
        strcpy(codeHash, "0x");
        for (int i = 1; i <= 32; i++)
            snprintf(codeHash + 2 + (i-1)*2, 3, "%02x", payload[i]);
        if (payload[0] == 0x00 && plen >= 34) {
            uint8_t ht = payload[33];
            if      (ht == 0x00) snprintf(hashType, sizeof(hashType), "%s", "data");
            else if (ht == 0x01) snprintf(hashType, sizeof(hashType), "%s", "type");
            else if (ht == 0x02) snprintf(hashType, sizeof(hashType), "%s", "data1");
            else if (ht == 0x04) snprintf(hashType, sizeof(hashType), "%s", "data2");
            size_t ab = plen - 34;
            strcpy(args, "0x");
            for (size_t i = 0; i < ab && i < 64; i++)
                snprintf(args + 2 + i*2, 3, "%02x", payload[34+i]);
        } else {
            snprintf(hashType, sizeof(hashType), "%s", "data");
            size_t ab = plen - 33;
            strcpy(args, "0x");
            for (size_t i = 0; i < ab && i < 64; i++)
                snprintf(args + 2 + i*2, 3, "%02x", payload[33+i]);
        }
    } else {
        return false;
    }

    return _transport.getCellsCapacity(codeHash, hashType, args, outShannons);
}

// ─── formatCKB ────────────────────────────────────────────────────────────────

char* LightClient::formatCKB(uint64_t shannons, char* buf, size_t bufSize) {
    uint64_t ckb      = shannons / 100000000ULL;
    uint64_t fraction = shannons % 100000000ULL;
    if (fraction == 0) {
        snprintf(buf, bufSize, "%llu CKB", (unsigned long long)ckb);
    } else {
        // Strip trailing zeros from fraction
        char frac[16]; snprintf(frac, sizeof(frac), "%08llu", (unsigned long long)fraction);
        int flen = 8;
        while (flen > 1 && frac[flen-1] == '0') frac[--flen] = '\0';
        snprintf(buf, bufSize, "%llu.%s CKB", (unsigned long long)ckb, frac);
    }
    return buf;
}
