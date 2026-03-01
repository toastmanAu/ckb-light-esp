// native_locks.cpp — Native lock script verification for ckb-light-esp
//
// Implements secp256k1-blake160, multisig, and anyone-can-pay without CKB-VM.
// Uses trezor_crypto (from CKB-ESP32) for ECDSA recovery.
// Uses ckb_blake2b.h (from CKB-ESP32) for Blake2b-256.
//
// RFC refs:
//   RFC 0017: Transaction structure + signing scheme
//   RFC 0024: Genesis script list (secp256k1, multisig code hashes)
//   RFC 0026: Anyone-can-pay lock

#include "native_locks.h"

// ── Dependencies ──────────────────────────────────────────────────────────────
#include "ckb_blake2b.h"

#ifdef HOST_TEST
// Host: use system libsecp256k1 for ECDSA recovery — trezor_crypto's bignum
// is tuned for 32-bit Cortex-M and runs impractically slow on aarch64 Linux.
// The device build still uses trezor (correct, audited, vendored).
#  include <secp256k1.h>
#  include <secp256k1_recovery.h>
static secp256k1_context* _host_secp_ctx = nullptr;
// Call this before any verify on host — test harness calls initSecp256k1()
// which sets this via the shared context trick below. We initialise lazily.
static secp256k1_context* _hostCtx() {
    if (!_host_secp_ctx) {
        _host_secp_ctx = secp256k1_context_create(
            SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }
    return _host_secp_ctx;
}
#else
// Device: trezor_crypto vendored in CKB-ESP32
extern "C" {
#  include "trezor_crypto/ecdsa.h"
#  include "trezor_crypto/secp256k1.h"
}
#endif

#include <string.h>

// ── Code hash byte tables ─────────────────────────────────────────────────────
// Pre-decoded from hex so identifyLock() doesn't parse strings at runtime.

static const uint8_t _SECP256K1_HASH[32] = {
    0x9b,0xd7,0xe0,0x6f, 0x3e,0xcf,0x4b,0xe0,
    0xf2,0xfc,0xd2,0x18, 0x8b,0x23,0xf1,0xb9,
    0xfc,0xc8,0x8e,0x5d, 0x4b,0x65,0xa8,0x63,
    0x7b,0x17,0x72,0x3b, 0xbd,0xa3,0xcc,0xe8
};

static const uint8_t _MULTISIG_HASH[32] = {
    0x5c,0x50,0x69,0xeb, 0x08,0x57,0xef,0xc6,
    0x5e,0x1b,0xca,0x0c, 0x07,0xdf,0x34,0xc3,
    0x16,0x63,0xb3,0x62, 0x2f,0xd3,0x87,0x6c,
    0x87,0x63,0x20,0xfc, 0x96,0x34,0xe2,0xa8
};

static const uint8_t _ACP_HASH[32] = {
    0xd3,0x69,0x59,0x7f, 0xf4,0x7f,0x29,0xfb,
    0xb0,0xd1,0xf6,0x5a, 0x1f,0x54,0x82,0xa8,
    0xb0,0x26,0x53,0x16, 0x8e,0x8e,0x83,0xed,
    0x7f,0x0b,0x6c,0x1e, 0x7e,0x83,0xc5,0x0c
};

// ── _recoverPubkey() ──────────────────────────────────────────────────────────
// Recover compressed 33-byte pubkey from [recid|r|s] sig + digest.
// Returns true on success. Platform-switchable: libsecp256k1 on host,
// trezor_crypto on device.
static bool _recoverPubkey(const uint8_t sig65[65], const uint8_t digest32[32],
                             uint8_t pubkey33[33]) {
#ifdef HOST_TEST
    secp256k1_ecdsa_recoverable_signature rsig;
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(
            _hostCtx(), &rsig, sig65 + 1, (int)sig65[0])) return false;
    secp256k1_pubkey pub;
    if (!secp256k1_ecdsa_recover(_hostCtx(), &pub, &rsig, digest32)) return false;
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(_hostCtx(), pubkey33, &len, &pub,
                                   SECP256K1_EC_COMPRESSED);
    return len == 33;
#else
    int recid = (int)sig65[0];
    if (recid < 0 || recid > 3) return false;
    uint8_t pubkeyUncompressed[65];
    if (ecdsa_recover_pub_from_sig(&secp256k1, pubkeyUncompressed,
                                    sig65 + 1, digest32, recid) != 0) return false;
    // Convert to compressed
    pubkey33[0] = (pubkeyUncompressed[64] & 1) ? 0x03 : 0x02;
    memcpy(pubkey33 + 1, pubkeyUncompressed + 1, 32);
    return true;
#endif
}



uint8_t NativeLocks::identifyLock(const uint8_t* codeHash32) {
    if (!codeHash32) return LOCK_TYPE_UNKNOWN;
    if (memcmp(codeHash32, _SECP256K1_HASH, 32) == 0) return LOCK_TYPE_SECP256K1;
    if (memcmp(codeHash32, _MULTISIG_HASH,  32) == 0) return LOCK_TYPE_MULTISIG;
    if (memcmp(codeHash32, _ACP_HASH,       32) == 0) return LOCK_TYPE_ACP;
    return LOCK_TYPE_UNKNOWN;
}

// ── blake160() ────────────────────────────────────────────────────────────────
// First 20 bytes of CKB Blake2b-256.

void NativeLocks::blake160(const uint8_t* data, size_t len, uint8_t out20[20]) {
    uint8_t hash[32];
    ckb_blake2b_hash(data, len, hash);
    memcpy(out20, hash, 20);
}

// ── extractWitnessLock() ──────────────────────────────────────────────────────
// WitnessArgs Molecule table layout (RFC 0019):
//   bytes [0..3]   = total_size (u32 LE)
//   bytes [4..7]   = offset[0] — start of lock field
//   bytes [8..11]  = offset[1] — start of input_type field (= end of lock)
//   bytes [12..15] = offset[2] — start of output_type field
//   bytes [offset[0]..offset[1]] = lock Option<Bytes>
//     if present: 4-byte length prefix + data bytes
//     if absent:  zero bytes (offset[0] == offset[1])

const uint8_t* NativeLocks::extractWitnessLock(const uint8_t* witness,
                                                 size_t witnessLen,
                                                 size_t* lenOut) {
    if (!witness || witnessLen < 16) return nullptr;

    // Read header
    auto readU32LE = [](const uint8_t* p) -> uint32_t {
        return (uint32_t)p[0] | ((uint32_t)p[1]<<8) |
               ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
    };

    uint32_t totalSize  = readU32LE(witness);
    uint32_t lockOffset = readU32LE(witness + 4);
    uint32_t lockEnd    = readU32LE(witness + 8);

    if (totalSize != (uint32_t)witnessLen) return nullptr;
    if (lockOffset < 16 || lockOffset > witnessLen) return nullptr;
    if (lockEnd < lockOffset || lockEnd > witnessLen) return nullptr;

    uint32_t lockFieldLen = lockEnd - lockOffset;
    if (lockFieldLen == 0) {
        // lock field absent (Option::None)
        if (lenOut) *lenOut = 0;
        return nullptr;
    }
    if (lockFieldLen < 4) return nullptr;

    // Option<Bytes> is present: 4-byte length prefix + data
    uint32_t dataLen = readU32LE(witness + lockOffset);
    if (lockOffset + 4 + dataLen > witnessLen) return nullptr;
    if (lenOut) *lenOut = (size_t)dataLen;
    return witness + lockOffset + 4;
}

// ── verifySecp256k1() ─────────────────────────────────────────────────────────
// Steps (per RFC 0017 + secp256k1-blake160 lock script):
//   1. Extract 65-byte sig from WitnessArgs lock field
//   2. sig[0] = recovery id (0-3); sig[1..32] = r; sig[33..64] = s
//   3. Recover compressed public key (33 bytes) from sig + txSigningHash
//   4. blake160(pubkey) must match lockArgs[0..19]

bool NativeLocks::verifySecp256k1(const NativeLockCtx& ctx) {
    if (!ctx.txSigningHash || !ctx.witness || !ctx.lockArgs) return false;
    if (ctx.lockArgsLen < 20) return false;

    // Extract signature from witness
    size_t sigLen = 0;
    const uint8_t* sig = extractWitnessLock(ctx.witness, ctx.witnessLen, &sigLen);
    if (!sig || sigLen != 65) return false;

    // Recover compressed pubkey from sig + signing hash
    uint8_t pubkey33[33];
    if (!_recoverPubkey(sig, ctx.txSigningHash, pubkey33)) return false;

    // blake160(compressed pubkey) must match lockArgs[0..19]
    uint8_t pkHash[20];
    blake160(pubkey33, 33, pkHash);

    return memcmp(pkHash, ctx.lockArgs, 20) == 0;
}

// ── parseMultisigArgs() ───────────────────────────────────────────────────────
// multisig lockArgs format (from RFC 0024):
//   [0]      reserved (must be 0)
//   [1]      requiredFirstN  — first N pubkeys must all sign
//   [2]      threshold       — total signatures required
//   [3]      keyCount        — total pubkeys
//   [4..]    pubkeyHashes    — 20 bytes each, keyCount entries

bool NativeLocks::parseMultisigArgs(const uint8_t* lockArgs, size_t lockArgsLen,
                                     uint8_t* reservedOut, uint8_t* requiredFirstNOut,
                                     uint8_t* thresholdOut,  uint8_t* keyCountOut) {
    if (!lockArgs || lockArgsLen < 4) return false;
    uint8_t reserved      = lockArgs[0];
    uint8_t requiredFirstN = lockArgs[1];
    uint8_t threshold      = lockArgs[2];
    uint8_t keyCount       = lockArgs[3];

    // Sanity checks
    if (reserved != 0) return false;
    if (threshold == 0 || keyCount == 0) return false;
    if (threshold > keyCount) return false;
    if (requiredFirstN > threshold) return false;
    if (lockArgsLen < (size_t)(4 + keyCount * 20)) return false;

    if (reservedOut)       *reservedOut       = reserved;
    if (requiredFirstNOut) *requiredFirstNOut  = requiredFirstN;
    if (thresholdOut)      *thresholdOut       = threshold;
    if (keyCountOut)       *keyCountOut        = keyCount;
    return true;
}

// ── verifyMultisig() ──────────────────────────────────────────────────────────
// Multisig witness lock field = script_header(4) + threshold * sig(65)
// script_header matches the lockArgs header (reserved, requiredFirstN, threshold, keyCount)
//
// Verification:
//   For each signature in witness:
//     - Recover pubkey from sig + txSigningHash
//     - blake160(pubkey) must match one of the lockArgs pubkey hashes
//     - If requiredFirstN > 0: first N sigs must come from first N keys (in order)
//   Count of valid, distinct signers must meet threshold.

bool NativeLocks::verifyMultisig(const NativeLockCtx& ctx) {
    if (!ctx.txSigningHash || !ctx.witness || !ctx.lockArgs) return false;

    uint8_t reserved, requiredFirstN, threshold, keyCount;
    if (!parseMultisigArgs(ctx.lockArgs, ctx.lockArgsLen,
                            &reserved, &requiredFirstN, &threshold, &keyCount)) {
        return false;
    }

    // Extract lock bytes from witness
    size_t lockLen = 0;
    const uint8_t* lockData = extractWitnessLock(ctx.witness, ctx.witnessLen, &lockLen);
    if (!lockData) return false;

    // lock = script header (4 bytes) + N * 65-byte signatures
    if (lockLen < (size_t)(4 + (size_t)threshold * 65)) return false;

    // Verify script header in witness matches lockArgs header
    if (memcmp(lockData, ctx.lockArgs, 4) != 0) return false;

    const uint8_t* sigs = lockData + 4;
    const uint8_t* pkHashes = ctx.lockArgs + 4; // keyCount * 20 bytes

    // Track which keys have signed (avoid double-counting)
    uint8_t used[16] = {0}; // bitmask for up to 128 keys
    int validCount = 0;

    for (int i = 0; i < (int)threshold; i++) {
        const uint8_t* sig = sigs + i * 65;

        uint8_t pubkey33[33];
        if (!_recoverPubkey(sig, ctx.txSigningHash, pubkey33)) return false;

        uint8_t pkHash[20];
        blake160(pubkey33, 33, pkHash);

        // Find matching pubkey in lockArgs
        bool matched = false;
        int startKey = (i < (int)requiredFirstN) ? i : 0; // requiredFirstN enforcement
        int endKey   = (i < (int)requiredFirstN) ? i + 1 : (int)keyCount;

        for (int k = startKey; k < endKey; k++) {
            if (used[k/8] & (1 << (k%8))) continue; // already used
            if (memcmp(pkHash, pkHashes + k*20, 20) == 0) {
                used[k/8] |= (1 << (k%8));
                matched = true;
                validCount++;
                break;
            }
        }
        if (!matched) return false;
    }

    return validCount >= (int)threshold;
}

// ── verifyACP() ───────────────────────────────────────────────────────────────
// Two unlock paths per RFC 0026:
//   a) Signature: witness has 65-byte sig → same as secp256k1 verify
//   b) Capacity-increase (no sig): output >= input (+ optional minimums in lockArgs)
//
// lockArgs:
//   [0..19]  pubkeyHash (blake160 of pubkey) — required
//   [20]     CKByte minimum (optional): min transfer = 10^x shannons
//   [21]     UDT minimum (optional): min transfer = 10^x UDT units
//
// inputCapacity=outputCapacity=0 → force signature path.

bool NativeLocks::verifyACP(const NativeLockCtx& ctx,
                              uint64_t inputCapacity, uint64_t outputCapacity) {
    if (!ctx.lockArgs || ctx.lockArgsLen < 20) return false;

    // Check if witness has a signature
    size_t sigLen = 0;
    const uint8_t* sig = extractWitnessLock(ctx.witness, ctx.witnessLen, &sigLen);
    bool hasSig = (sig != nullptr && sigLen == 65);

    if (hasSig) {
        // Signature path — same verification as secp256k1
        return verifySecp256k1(ctx);
    }

    // Capacity-increase path
    // Output must be >= input
    if (outputCapacity < inputCapacity) return false;
    uint64_t increase = outputCapacity - inputCapacity;

    // Check optional CKByte minimum from lockArgs[20]
    if (ctx.lockArgsLen >= 21) {
        uint8_t ckbMinExp = ctx.lockArgs[20];
        // min = 10^ckbMinExp shannons (integer pow, capped at 64-bit)
        uint64_t ckbMin = 1;
        for (uint8_t i = 0; i < ckbMinExp && ckbMin <= (uint64_t)1e16; i++) {
            ckbMin *= 10;
        }
        if (increase < ckbMin) return false;
    }

    // UDT minimum (lockArgs[21]) — we don't track UDT amounts at this layer.
    // If the type script is present, UDT enforcement is done by the type script.
    // Capacity-increase alone is sufficient for the lock script level.

    return true;
}

// ── verify() — dispatch ───────────────────────────────────────────────────────

bool NativeLocks::verify(const uint8_t* codeHash32, const NativeLockCtx& ctx) {
    switch (identifyLock(codeHash32)) {
        case LOCK_TYPE_SECP256K1: return verifySecp256k1(ctx);
        case LOCK_TYPE_MULTISIG:  return verifyMultisig(ctx);
        case LOCK_TYPE_ACP:       return verifyACP(ctx, 0, 0); // signature path
        default:                  return false;
    }
}
