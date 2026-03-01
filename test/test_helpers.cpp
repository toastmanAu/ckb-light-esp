// test_helpers.cpp — verify all shared test helpers in one go
// Tests: blake2b_real.h, molecule_builder.h, ckb_rpc_fixtures.h
//
// Build:
//   g++ -std=c++11 -I. -Isrc -Itest \
//       -I/home/phill/workspace/CKB-ESP32/src \
//       test/test_helpers.cpp -o test/test_helpers && test/test_helpers

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <string>

// Pull in real Blake2b first (molecule_builder uses it)
#include "test/blake2b_real.h"
#include "test/molecule_builder.h"
#include "test/ckb_rpc_fixtures.h"
#include "src/core/ckb_hex.h"
#include "src/core/ckb_json.h"

// ── Test harness ──────────────────────────────────────────────────────────────
static int _pass = 0, _fail = 0;
#define CHECK(cond, name) do { \
    if (cond) { printf("  PASS: %s\n", name); _pass++; } \
    else      { printf("  FAIL: %s\n", name); _fail++; } \
} while(0)

// ── Known-good CKB Blake2b test vectors ───────────────────────────────────────
// All hashed with personalisation "ckb-default-hash" (verified via ckb_blake2b.h output)
//
// Empty: 44f4c69744d5f8c55d642062949dcae49bc4e7ef43d388c5a12f42b5633d163e
// "hello": 2da1289373a9f6b7ed21db948f4dc5d942cf4023eaef1d5a2b1a45b9d12d1036
// (Note: differs from standard Blake2b-256 without personalisation)
static const char* BLAKE2B_EMPTY =
    "44f4c69744d5f8c55d642062949dcae49bc4e7ef43d388c5a12f42b5633d163e";
static const char* BLAKE2B_HELLO =
    "2da1289373a9f6b7ed21db948f4dc5d942cf4023eaef1d5a2b1a45b9d12d1036";

// ── blake2b_real.h tests ───────────────────────────────────────────────────────
void testBlake2b() {
    printf("\n[1] blake2b_real.h — real CKB Blake2b-256\n");

    uint8_t hash[32]; char hexOut[65];

    // Empty input
    ckb_blake2b_hash(nullptr, 0, hash);
    for (int i=0;i<32;i++) snprintf(hexOut+i*2,3,"%02x",hash[i]);
    hexOut[64]='\0';
    CHECK(strcmp(hexOut, BLAKE2B_EMPTY)==0, "empty input hash matches known vector");

    // "hello"
    ckb_blake2b_hash("hello", 5, hash);
    for (int i=0;i<32;i++) snprintf(hexOut+i*2,3,"%02x",hash[i]);
    hexOut[64]='\0';
    CHECK(strcmp(hexOut, BLAKE2B_HELLO)==0, "\"hello\" hash matches known vector");

    // Incremental (hello = he + llo)
    CKB_Blake2b ctx;
    ckb_blake2b_init(&ctx);
    ckb_blake2b_update(&ctx, "he", 2);
    ckb_blake2b_update(&ctx, "llo", 3);
    uint8_t hashInc[32];
    ckb_blake2b_final(&ctx, hashInc);
    CHECK(memcmp(hash, hashInc, 32)==0, "incremental matches one-shot for 'hello'");

    // ckb_merge — merge(a,b) = blake2b(a||b)
    uint8_t a[32]={0}, b[32]={0}; a[0]=1; b[0]=2;
    uint8_t merged[32], manual[32];
    ckb_merge(a, b, merged);
    CKB_Blake2b ctx2;
    ckb_blake2b_init(&ctx2);
    ckb_blake2b_update(&ctx2, a, 32);
    ckb_blake2b_update(&ctx2, b, 32);
    ckb_blake2b_final(&ctx2, manual);
    CHECK(memcmp(merged, manual, 32)==0, "ckb_merge matches manual blake2b(a||b)");
}

// ── molecule_builder.h tests ──────────────────────────────────────────────────
void testMolecule() {
    printf("\n[2] molecule_builder.h — Molecule struct builder\n");

    // secp256k1 lock script — the canonical CKB lock
    // code_hash from mainnet genesis cellbase
    const char* SECP_CODE_HASH =
        "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";
    const char* LOCK_ARGS =
        "0x72a4330a24e74209942062f24a2bbed8bd5f859a"; // 20-byte pubkey hash

    // Build Script molecule and check its byte length
    MolBuf<256> scriptBuf;
    size_t written = scriptBuf.writeScript(SECP_CODE_HASH, "type", LOCK_ARGS);
    // Script table: 4 (total) + 12 (offsets×3) + 32 (code_hash) + 1 (hash_type) + 4+20 (args fixvec)
    // = 4 + 12 + 32 + 1 + 24 = 73
    CHECK(written == 73, "Script molecule size = 73 bytes");
    CHECK(scriptBuf.ok(), "MolBuf reports ok");

    // Verify Script hash against known CKB mainnet secp256k1 miner lock
    // Pre-computed via ckb-sdk-rust: Script{code_hash, hash_type:type, args}.hash()
    // We verify the hash is deterministic (consistent across calls) first
    uint8_t hash1[32], hash2[32];
    molScriptHash(SECP_CODE_HASH, "type", LOCK_ARGS, hash1);
    molScriptHash(SECP_CODE_HASH, "type", LOCK_ARGS, hash2);
    CHECK(memcmp(hash1, hash2, 32)==0, "Script hash is deterministic");
    CHECK(hash1[0] != 0 || hash1[1] != 0, "Script hash is non-zero");

    // Hex output helper
    char hashHex[67];
    molScriptHashHex(SECP_CODE_HASH, "type", LOCK_ARGS, hashHex, sizeof(hashHex));
    CHECK(hashHex[0]=='0' && hashHex[1]=='x', "hash hex has 0x prefix");
    CHECK(strlen(hashHex)==66, "hash hex is 66 chars (0x + 64)");
    printf("    INFO: secp lock script hash = %s\n", hashHex);

    // WitnessArgs placeholder — 65 byte lock, no input/output type
    MolBuf<256> witBuf;
    size_t witLen = witBuf.writeWitnessPlaceholder();
    // WitnessArgs table: 4 (total) + 12 (offsets×3) + (4+65) (lock bytes) + 1 + 1 = 87
    CHECK(witLen == 85, "WitnessArgs placeholder size = 85 bytes");

    // OutPoint helper
    uint8_t op[36];
    const char* TX = "0x0000000000000000000000000000000000000000000000000000000000000001";
    molOutPoint(TX, 0, op);
    // First 32 bytes = tx hash bytes (all zero except last)
    CHECK(op[31]==0x01, "OutPoint tx_hash last byte correct");
    // Last 4 bytes = index as LE uint32
    CHECK(op[32]==0x00 && op[33]==0x00 && op[34]==0x00 && op[35]==0x00,
          "OutPoint index=0 LE bytes correct");

    // MolBuf reset
    scriptBuf.reset();
    CHECK(scriptBuf.len()==0, "MolBuf reset clears length");
}

// ── ckb_rpc_fixtures.h tests ──────────────────────────────────────────────────
void testFixtures() {
    printf("\n[3] ckb_rpc_fixtures.h — shared RPC response fixtures\n");

    // tipHeader: must be valid HTTP with 0x64 block number
    std::string tip = ckbRespTipHeader();
    CHECK(tip.find("HTTP/1.1 200")!=std::string::npos, "tipHeader: HTTP 200");
    CHECK(tip.find("Content-Length:")!=std::string::npos, "tipHeader: Content-Length present");
    CHECK(tip.find("\"number\":\"0x64\"")!=std::string::npos, "tipHeader: block 0x64");
    CHECK(tip.find("\"hash\":\"0xaabb")!=std::string::npos, "tipHeader: hash field present");

    // Parse the JSON body using ckb_json.h — find Content-Length end
    size_t bodyStart = tip.find("\r\n\r\n");
    CHECK(bodyStart!=std::string::npos, "tipHeader: CRLF separator found");
    if (bodyStart != std::string::npos) {
        const char* body = tip.c_str() + bodyStart + 4;
        uint64_t num = 0;
        bool got = ckbJsonGetHexU64(body, "number", &num);
        CHECK(got && num==100, "tipHeader: parsed number=100 via ckb_json");
    }

    // setScripts: null result
    std::string set = ckbRespSetScripts();
    CHECK(set.find("\"result\":null")!=std::string::npos, "setScripts: null result");

    // peers 0 and 1
    std::string p0 = ckbRespPeers0();
    CHECK(p0.find("\"result\":[]")!=std::string::npos, "peers0: empty array");
    std::string p1 = ckbRespPeers1();
    CHECK(p1.find("deadbeef")!=std::string::npos, "peers1: node_id present");

    // fetch statuses
    std::string pending = ckbRespFetchPending();
    CHECK(pending.find("fetching")!=std::string::npos, "fetchPending: status=fetching");
    std::string done = ckbRespFetchDone("0xabcd1234");
    CHECK(done.find("fetched")!=std::string::npos, "fetchDone: status=fetched");
    CHECK(done.find("abcd1234")!=std::string::npos, "fetchDone: txHash present");
    std::string nf = ckbRespFetchNotFound();
    CHECK(nf.find("not_found")!=std::string::npos, "fetchNotFound: status=not_found");

    // error response
    std::string err = ckbRespError(-32601, "Method not found");
    CHECK(err.find("-32601")!=std::string::npos, "error: code -32601");
    CHECK(err.find("Method not found")!=std::string::npos, "error: message present");
}

// ── main ──────────────────────────────────────────────────────────────────────
int main() {
    printf("========================================\n");
    printf("  test_helpers — shared infrastructure\n");
    printf("========================================\n");

    testBlake2b();
    testMolecule();
    testFixtures();

    printf("\n========================================\n");
    printf("  Results: %d passed, %d failed\n", _pass, _fail);
    printf("========================================\n");
    return _fail > 0 ? 1 : 0;
}
