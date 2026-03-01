// test_native_locks.cpp — host tests for native_locks.cpp
//
// Uses libsecp256k1 (system library) for key generation and signing.
// native_locks.cpp uses trezor_crypto for device builds — this doesn't affect
// what we're testing, which is the VERIFICATION logic in native_locks.cpp.
// The sig format [recid|r|s] is identical between both libs.
//
// Build:
//   g++ -DHOST_TEST -std=c++11 \
//       -I. -Isrc -Isrc/vm -Isrc/core -Itest \
//       -I/home/phill/workspace/CKB-ESP32/src \
//       test/test_native_locks.cpp \
//       src/vm/native_locks.cpp \
//       /home/phill/workspace/CKB-ESP32/src/trezor_crypto/ecdsa.c \
//       /home/phill/workspace/CKB-ESP32/src/trezor_crypto/secp256k1.c \
//       /home/phill/workspace/CKB-ESP32/src/trezor_crypto/bignum.c \
//       /home/phill/workspace/CKB-ESP32/src/trezor_crypto/hmac.c \
//       /home/phill/workspace/CKB-ESP32/src/trezor_crypto/rfc6979.c \
//       /home/phill/workspace/CKB-ESP32/src/trezor_crypto/memzero.c \
//       /home/phill/workspace/CKB-ESP32/src/trezor_crypto/hasher.c \
//       /home/phill/workspace/CKB-ESP32/src/trezor_crypto/sha2.c \
//       /home/phill/workspace/CKB-ESP32/src/trezor_crypto/ripemd160.c \
//       /home/phill/workspace/CKB-ESP32/src/trezor_crypto/sha3.c \
//       /tmp/random_stub.o \
//       -lsecp256k1 \
//       -o test/test_nl && test/test_nl

#define HOST_TEST
#include "blake2b_real.h"
#include "molecule_builder.h"
#include "ckb_hex.h"
#include "ckb_json.h"
#include "native_locks.h"

// System libsecp256k1 — fast, aarch64-native, used for signing in tests only
#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

// ── Test harness ──────────────────────────────────────────────────────────────
static int _pass = 0, _fail = 0;
#define CHECK(cond, name) do { \
    if (cond) { printf("  PASS: %s\n", name); _pass++; } \
    else      { printf("  FAIL: %s (line %d)\n", name, __LINE__); _fail++; } \
} while(0)

// ── libsecp256k1 context (for signing in tests) ───────────────────────────────
static secp256k1_context* _sctx = nullptr;

static void initSecp256k1() {
    _sctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    assert(_sctx != nullptr);
}

// ── Known test private key ────────────────────────────────────────────────────
// Private key: all bytes 0x01 (test only — never use in production)
static const uint8_t TEST_PRIVKEY[32] = {
    0x01,0x01,0x01,0x01, 0x01,0x01,0x01,0x01,
    0x01,0x01,0x01,0x01, 0x01,0x01,0x01,0x01,
    0x01,0x01,0x01,0x01, 0x01,0x01,0x01,0x01,
    0x01,0x01,0x01,0x01, 0x01,0x01,0x01,0x01
};

// Derive compressed pubkey (33 bytes) and blake160 lock args (20 bytes)
static void deriveTestKey(uint8_t pubkey33[33], uint8_t lockArgs20[20]) {
    secp256k1_pubkey pub;
    assert(secp256k1_ec_pubkey_create(_sctx, &pub, TEST_PRIVKEY));
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(_sctx, pubkey33, &len, &pub,
                                   SECP256K1_EC_COMPRESSED);
    NativeLocks::blake160(pubkey33, 33, lockArgs20);
}

// Sign a 32-byte digest. Returns 65-byte [recid|r|s] in CKB format.
static bool signDigest(const uint8_t privkey[32], const uint8_t digest[32],
                        uint8_t sigOut[65]) {
    secp256k1_ecdsa_recoverable_signature rsig;
    if (!secp256k1_ecdsa_sign_recoverable(_sctx, &rsig, digest, privkey,
                                           nullptr, nullptr)) return false;
    int recid = 0;
    secp256k1_ecdsa_recoverable_signature_serialize_compact(
        _sctx, sigOut + 1, &recid, &rsig);
    sigOut[0] = (uint8_t)recid;
    return true;
}

// ── WitnessArgs builders ──────────────────────────────────────────────────────

static void buildWitness(const uint8_t lockData[], size_t lockLen,
                          uint8_t* out, size_t* outLen) {
    // WitnessArgs Table: total(4) + offsets(3*4) + length(4) + lockData
    size_t total = 16 + 4 + lockLen;
    auto w32 = [](uint8_t* p, uint32_t v) {
        p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8);
        p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24);
    };
    w32(out+0,  (uint32_t)total);
    w32(out+4,  16);                   // lock at offset 16
    w32(out+8,  (uint32_t)total);      // input_type absent
    w32(out+12, (uint32_t)total);      // output_type absent
    w32(out+16, (uint32_t)lockLen);    // lock field length
    memcpy(out+20, lockData, lockLen);
    *outLen = total;
}

static void buildWitnessSig(const uint8_t sig65[65],
                              uint8_t out[85], size_t* outLen) {
    buildWitness(sig65, 65, out, outLen);
}

static void buildWitnessEmpty(uint8_t out[16], size_t* outLen) {
    // WitnessArgs with ABSENT lock field (Option::None).
    // Molecule table: offset[0] == offset[1] means zero bytes for lock = None.
    // total=16, lock at offset 16, lock end at offset 16 (0 bytes), same for others.
    auto w32 = [](uint8_t* p, uint32_t v) {
        p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8);
        p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24);
    };
    w32(out+0,  16);  // total = 16 (header only)
    w32(out+4,  16);  // offset[0]: lock starts at 16 (end of header)
    w32(out+8,  16);  // offset[1]: lock ends at 16 = 0 bytes = absent
    w32(out+12, 16);  // offset[2]: same
    *outLen = 16;
}

// CKB signing hash: blake2b_ckb(tx_hash || witness_len_u64le || witness_placeholder)
// The placeholder is an 85-byte WitnessArgs with 65 zeroed lock bytes — NOT absent.
static void computeSigningHash(const uint8_t txHash[32], uint8_t out[32]) {
    // Build 85-byte placeholder with zeroed sig (Option::Some(0x00*65))
    uint8_t placeholder[85];
    uint8_t zeros[65] = {0};
    size_t pLen;
    buildWitness(zeros, 65, placeholder, &pLen); // pLen == 85

    CKB_Blake2b ctx;
    ckb_blake2b_init(&ctx);
    ckb_blake2b_update(&ctx, txHash, 32);
    uint8_t lenBuf[8] = {85,0,0,0,0,0,0,0}; // 85 as LE uint64
    ckb_blake2b_update(&ctx, lenBuf, 8);
    ckb_blake2b_update(&ctx, placeholder, 85);
    ckb_blake2b_final(&ctx, out);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

void testIdentifyLock() {
    printf("\n[1] identifyLock() — code hash recognition\n");

    uint8_t secp[32], multi[32], acp[32], unknown[32];
    memset(unknown, 0xAB, 32);

    ckbHexDecodeN(SECP256K1_BLAKE160_CODE_HASH, secp,  32);
    ckbHexDecodeN(SECP256K1_MULTISIG_CODE_HASH, multi, 32);
    // ACP: concatenated define needs joining
    const char* ACP = "0xd369597ff47f29fbb0d1f65a1f5482a8b02653168e8e83ed7f0b6c1e7e83c50c";
    ckbHexDecodeN(ACP, acp, 32);

    CHECK(NativeLocks::identifyLock(secp)    == LOCK_TYPE_SECP256K1, "secp256k1 identified");
    CHECK(NativeLocks::identifyLock(multi)   == LOCK_TYPE_MULTISIG,  "multisig identified");
    CHECK(NativeLocks::identifyLock(acp)     == LOCK_TYPE_ACP,       "ACP identified");
    CHECK(NativeLocks::identifyLock(unknown) == LOCK_TYPE_UNKNOWN,   "unknown rejected");
    CHECK(NativeLocks::identifyLock(nullptr) == LOCK_TYPE_UNKNOWN,   "null returns UNKNOWN");
}

void testBlake160() {
    printf("\n[2] blake160() — first 20 bytes of CKB Blake2b\n");

    uint8_t out[20];
    NativeLocks::blake160((const uint8_t*)"hello", 5, out);
    // blake2b_ckb("hello") = 2da1289373a9f6b7ed21db948f4dc5d942cf4023...
    uint8_t expected[20];
    ckbHexDecodeN("0x2da1289373a9f6b7ed21db948f4dc5d942cf4023", expected, 20);
    CHECK(memcmp(out, expected, 20) == 0, "blake160('hello') matches known value");

    NativeLocks::blake160(nullptr, 0, out);
    // blake2b_ckb("") = 44f4c697...
    ckbHexDecodeN("0x44f4c69744d5f8c55d642062949dcae49bc4e7ef", expected, 20);
    CHECK(memcmp(out, expected, 20) == 0, "blake160(empty) matches known value");
}

void testExtractWitnessLock() {
    printf("\n[3] extractWitnessLock() — WitnessArgs molecule parsing\n");

    uint8_t witness[85]; size_t wLen;
    uint8_t fakeSig[65]; memset(fakeSig, 0xCC, 65);
    buildWitnessSig(fakeSig, witness, &wLen);

    size_t lockLen = 0;
    const uint8_t* lock = NativeLocks::extractWitnessLock(witness, wLen, &lockLen);
    CHECK(lock != nullptr, "lock field found");
    CHECK(lockLen == 65, "lock field is 65 bytes");
    CHECK(lock[0] == 0xCC && lock[64] == 0xCC, "lock bytes match input");

    lock = NativeLocks::extractWitnessLock(witness, 10, &lockLen);
    CHECK(lock == nullptr, "truncated witness rejected");

    lock = NativeLocks::extractWitnessLock(nullptr, 85, &lockLen);
    CHECK(lock == nullptr, "null witness returns nullptr");

    // Corrupt total_size
    uint8_t bad[85]; memcpy(bad, witness, 85); bad[0] = 0xFF;
    lock = NativeLocks::extractWitnessLock(bad, 85, &lockLen);
    CHECK(lock == nullptr, "corrupt total_size rejected");
}

void testVerifySecp256k1() {
    printf("\n[4] verifySecp256k1() — full sign+verify round-trip\n");

    uint8_t pubkey33[33], lockArgs[20];
    deriveTestKey(pubkey33, lockArgs);

    char laHex[43] = "0x";
    for (int i=0;i<20;i++) snprintf(laHex+2+i*2,3,"%02x",lockArgs[i]);
    printf("  INFO: lock args = %s\n", laHex);

    uint8_t txHash[32]; memset(txHash, 0x42, 32);
    uint8_t signingHash[32];
    computeSigningHash(txHash, signingHash);

    uint8_t sig[65];
    CHECK(signDigest(TEST_PRIVKEY, signingHash, sig), "test sign succeeded");

    uint8_t witness[85]; size_t wLen;
    buildWitnessSig(sig, witness, &wLen);

    NativeLockCtx ctx;
    ctx.txSigningHash = signingHash;
    ctx.witness       = witness;
    ctx.witnessLen    = wLen;
    ctx.lockArgs      = lockArgs;
    ctx.lockArgsLen   = 20;

    CHECK(NativeLocks::verifySecp256k1(ctx), "valid sig verifies");

    // Wrong lock args
    uint8_t wrongArgs[20]; memset(wrongArgs, 0xFF, 20);
    NativeLockCtx badCtx = ctx; badCtx.lockArgs = wrongArgs;
    CHECK(!NativeLocks::verifySecp256k1(badCtx), "wrong lockArgs rejected");

    // Corrupt sig r byte
    uint8_t badWitness[85]; memcpy(badWitness, witness, 85);
    badWitness[21] ^= 0x01;
    NativeLockCtx corruptCtx = ctx; corruptCtx.witness = badWitness;
    CHECK(!NativeLocks::verifySecp256k1(corruptCtx), "corrupt sig rejected");

    // Wrong signing hash
    uint8_t wrongHash[32]; memset(wrongHash, 0x00, 32);
    NativeLockCtx wrongHashCtx = ctx; wrongHashCtx.txSigningHash = wrongHash;
    CHECK(!NativeLocks::verifySecp256k1(wrongHashCtx), "wrong signing hash rejected");
}

void testParseMultisigArgs() {
    printf("\n[5] parseMultisigArgs() — lockArgs header parsing\n");

    uint8_t args[4 + 3*20];
    args[0]=0; args[1]=0; args[2]=2; args[3]=3;
    memset(args+4, 0xAA, 60);

    uint8_t res, rfn, thr, kc;
    CHECK(NativeLocks::parseMultisigArgs(args, sizeof(args), &res, &rfn, &thr, &kc),
          "2-of-3 parses ok");
    CHECK(thr==2, "threshold=2");
    CHECK(kc==3,  "keyCount=3");
    CHECK(rfn==0, "requiredFirstN=0");

    // threshold > keyCount
    args[2]=4; args[3]=3;
    CHECK(!NativeLocks::parseMultisigArgs(args, sizeof(args), &res, &rfn, &thr, &kc),
          "threshold>keyCount rejected");

    // threshold=0
    args[2]=0; args[3]=3;
    CHECK(!NativeLocks::parseMultisigArgs(args, sizeof(args), &res, &rfn, &thr, &kc),
          "threshold=0 rejected");

    // too short
    CHECK(!NativeLocks::parseMultisigArgs(args, 3, &res, &rfn, &thr, &kc),
          "too short lockArgs rejected");
}

void testVerifyMultisig() {
    printf("\n[6] verifyMultisig() — 2-of-3 signature verification\n");

    // 3 distinct privkeys
    uint8_t privkeys[3][32];
    for (int i=0;i<3;i++) { memset(privkeys[i], i+1, 32); }

    // Derive compressed pubkeys + blake160 hashes
    uint8_t pkHashes[3][20];
    for (int i=0;i<3;i++) {
        secp256k1_pubkey pub;
        secp256k1_ec_pubkey_create(_sctx, &pub, privkeys[i]);
        uint8_t pub33[33]; size_t len=33;
        secp256k1_ec_pubkey_serialize(_sctx, pub33, &len, &pub, SECP256K1_EC_COMPRESSED);
        NativeLocks::blake160(pub33, 33, pkHashes[i]);
    }

    // lockArgs: 2-of-3
    uint8_t lockArgs[4+3*20];
    lockArgs[0]=0; lockArgs[1]=0; lockArgs[2]=2; lockArgs[3]=3;
    for (int i=0;i<3;i++) memcpy(lockArgs+4+i*20, pkHashes[i], 20);

    uint8_t txHash[32]; memset(txHash, 0x55, 32);
    uint8_t signingHash[32];
    computeSigningHash(txHash, signingHash);

    uint8_t sig0[65], sig1[65];
    signDigest(privkeys[0], signingHash, sig0);
    signDigest(privkeys[1], signingHash, sig1);

    // witness lock = header(4) + sig0(65) + sig1(65)
    uint8_t lockData[4+65+65];
    memcpy(lockData, lockArgs, 4);
    memcpy(lockData+4, sig0, 65);
    memcpy(lockData+4+65, sig1, 65);

    uint8_t witness[256]; size_t wLen;
    buildWitness(lockData, sizeof(lockData), witness, &wLen);

    NativeLockCtx ctx;
    ctx.txSigningHash = signingHash;
    ctx.witness       = witness;
    ctx.witnessLen    = wLen;
    ctx.lockArgs      = lockArgs;
    ctx.lockArgsLen   = sizeof(lockArgs);

    CHECK(NativeLocks::verifyMultisig(ctx), "2-of-3 verifies with sigs 0+1");

    // Corrupt sig0
    uint8_t badW[256]; memcpy(badW, witness, wLen);
    badW[21] ^= 0xFF;
    NativeLockCtx badCtx = ctx; badCtx.witness = badW;
    CHECK(!NativeLocks::verifyMultisig(badCtx), "corrupt sig rejected");
}

void testVerifyACP() {
    printf("\n[7] verifyACP() — anyone-can-pay verification\n");

    uint8_t pubkey33[33], lockArgs[20];
    deriveTestKey(pubkey33, lockArgs);

    uint8_t txHash[32]; memset(txHash, 0x77, 32);
    uint8_t signingHash[32];
    computeSigningHash(txHash, signingHash);
    uint8_t sig[65]; signDigest(TEST_PRIVKEY, signingHash, sig);

    uint8_t witness[85]; size_t wLen;
    buildWitnessSig(sig, witness, &wLen);

    NativeLockCtx ctx;
    ctx.txSigningHash = signingHash;
    ctx.witness       = witness;
    ctx.witnessLen    = wLen;
    ctx.lockArgs      = lockArgs;
    ctx.lockArgsLen   = 20;

    CHECK(NativeLocks::verifyACP(ctx, 0, 0), "ACP: valid sig path");

    // Capacity-increase path
    uint8_t emptyW[85]; size_t emptyWLen;
    buildWitnessEmpty(emptyW, &emptyWLen);
    NativeLockCtx capCtx = ctx;
    capCtx.witness = emptyW; capCtx.witnessLen = emptyWLen;

    CHECK(NativeLocks::verifyACP(capCtx, 100000000, 200000000),
          "ACP: capacity increase passes");
    CHECK(!NativeLocks::verifyACP(capCtx, 200000000, 100000000),
          "ACP: capacity decrease rejected");
    CHECK(NativeLocks::verifyACP(capCtx, 100000000, 100000000),
          "ACP: equal capacity passes (no minimum)");

    // With minimum: lockArgs[20] = 2 → 10^2 = 100 shannons
    uint8_t laWithMin[21];
    memcpy(laWithMin, lockArgs, 20);
    laWithMin[20] = 2;
    NativeLockCtx minCtx = capCtx;
    minCtx.lockArgs = laWithMin; minCtx.lockArgsLen = 21;

    CHECK(!NativeLocks::verifyACP(minCtx, 100000000, 100000050),
          "ACP: 50 shannon < 100 minimum rejected");
    CHECK(NativeLocks::verifyACP(minCtx, 100000000, 100000100),
          "ACP: 100 shannon = minimum accepted");
    CHECK(NativeLocks::verifyACP(minCtx, 100000000, 100001000),
          "ACP: 1000 shannon > minimum accepted");
}

void testDispatch() {
    printf("\n[8] verify() dispatch\n");

    uint8_t pubkey33[33], lockArgs[20];
    deriveTestKey(pubkey33, lockArgs);

    uint8_t txHash[32]; memset(txHash, 0x88, 32);
    uint8_t signingHash[32]; computeSigningHash(txHash, signingHash);
    uint8_t sig[65]; signDigest(TEST_PRIVKEY, signingHash, sig);
    uint8_t witness[85]; size_t wLen;
    buildWitnessSig(sig, witness, &wLen);

    NativeLockCtx ctx;
    ctx.txSigningHash = signingHash;
    ctx.witness       = witness;
    ctx.witnessLen    = wLen;
    ctx.lockArgs      = lockArgs;
    ctx.lockArgsLen   = 20;

    uint8_t secp32[32], acp32[32], unknown32[32];
    ckbHexDecodeN(SECP256K1_BLAKE160_CODE_HASH, secp32, 32);
    ckbHexDecodeN("0xd369597ff47f29fbb0d1f65a1f5482a8b02653168e8e83ed7f0b6c1e7e83c50c",
                   acp32, 32);
    memset(unknown32, 0xAB, 32);

    CHECK(NativeLocks::verify(secp32,    ctx), "dispatch: secp256k1 verifies");
    CHECK(NativeLocks::verify(acp32,     ctx), "dispatch: ACP (sig path) verifies");
    CHECK(!NativeLocks::verify(unknown32, ctx), "dispatch: unknown returns false");
}

// ── main ──────────────────────────────────────────────────────────────────────
int main() {
    printf("========================================\n");
    printf("  native_locks.cpp host tests\n");
    printf("========================================\n");

    initSecp256k1();

    testIdentifyLock();
    testBlake160();
    testExtractWitnessLock();
    testVerifySecp256k1();
    testParseMultisigArgs();
    testVerifyMultisig();
    testVerifyACP();
    testDispatch();

    secp256k1_context_destroy(_sctx);

    printf("\n========================================\n");
    printf("  Results: %d passed, %d failed\n", _pass, _fail);
    printf("========================================\n");
    return _fail > 0 ? 1 : 0;
}
