#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// =============================================================================
// native_locks.h — Native C implementations of common CKB lock scripts
//
// Avoids CKB-VM entirely for well-known lock scripts.
// Covers ~99% of real-world CKB transactions.
// Much faster and lower RAM than running the VM interpreter.
//
// Supported locks:
//   - SECP256K1_BLAKE160_SIGHASH_ALL  (default lock, most wallets)
//   - SECP256K1_BLAKE160_MULTISIG     (multisig, threshold-of-N)
//   - ANYONE_CAN_PAY                  (ACP — sig OR capacity-increase)
//
// All code hashes are mainnet values (type hash_type).
// RFC references:
//   - secp256k1: https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0024-ckb-genesis-script-list
//   - multisig:  https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0024-ckb-genesis-script-list
//   - ACP:       https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0026-anyone-can-pay
// =============================================================================

// ── Lock type constants ───────────────────────────────────────────────────────
#define LOCK_TYPE_UNKNOWN   0x00
#define LOCK_TYPE_SECP256K1 0x01
#define LOCK_TYPE_MULTISIG  0x02
#define LOCK_TYPE_ACP       0x03

// ── Well-known mainnet code hashes ───────────────────────────────────────────

// secp256k1-blake160-sighash-all (hash_type: type)
// Source: CKB genesis block, genesis cellbase tx output[1]
#define SECP256K1_BLAKE160_CODE_HASH \
    "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"

// secp256k1-blake160-multisig (hash_type: type)
// Source: CKB genesis block, genesis cellbase tx output[4]
#define SECP256K1_MULTISIG_CODE_HASH \
    "0x5c5069eb0857efc65e1bca0c07df34c31663b3622fd3876c876320fc9634e2a8"

// anyone-can-pay (hash_type: type)
// Source: RFC 0026, mainnet deployment
// https://explorer.nervos.org/transaction/0x04b88...
#define ANYONE_CAN_PAY_CODE_HASH \
    "0xd369597ff47f29fbb0d1f65a1f5482a8b026531" \
    "68e8e83ed7f0b6c1e7e83c50c"

// ── NativeLockCtx — input context for verification ───────────────────────────
//
// The caller (LightClient) builds this from the transaction being verified.
//
// For secp256k1 and multisig:
//   txSigningHash = blake2b_ckb(tx_hash || witness_len_u64le || witness_placeholder)
//   witness       = raw WitnessArgs bytes (85 bytes for single secp256k1)
//   lockArgs      = script.args bytes (20 bytes = blake160(pubkey))
//
// For ACP with no signature (capacity-increase path):
//   txSigningHash may be zeroed — it won't be used
//   inputCapacity / outputCapacity must be set for the cell pair
typedef struct {
    const uint8_t* txSigningHash;  // 32-byte CKB signing hash
    const uint8_t* witness;        // raw WitnessArgs molecule bytes
    size_t         witnessLen;
    const uint8_t* lockArgs;       // script.args bytes
    size_t         lockArgsLen;
} NativeLockCtx;

// ── NativeLocks ───────────────────────────────────────────────────────────────
class NativeLocks {
public:
    // Identify lock type from 32-byte code_hash.
    // Returns LOCK_TYPE_* constant, or LOCK_TYPE_UNKNOWN.
    static uint8_t identifyLock(const uint8_t* codeHash32);

    // Verify secp256k1-blake160-sighash-all.
    // 1. Extract 65-byte signature from WitnessArgs lock field
    // 2. Recover public key from sig + txSigningHash
    // 3. blake160(pubkey) must match lockArgs[0..19]
    // Returns true if valid.
    static bool verifySecp256k1(const NativeLockCtx& ctx);

    // Verify secp256k1-blake160-multisig.
    // lockArgs = reserved(1) + threshold(1) + requiredFirstN(1) + keyCount(1) + pubkeyHashes(20*N)
    // witness lock field = multisig script header + threshold * 65-byte signatures
    // Returns true if threshold satisfied.
    static bool verifyMultisig(const NativeLockCtx& ctx);

    // Verify anyone-can-pay.
    // Two unlock paths per RFC 0026:
    //   a) Signature path: same as secp256k1, lockArgs[0..19] = pubkey hash
    //   b) Capacity-increase path (no sig): output capacity >= input capacity
    //      + optional minimum enforced from lockArgs[20] (CKB) and lockArgs[21] (UDT)
    // inputCapacity/outputCapacity in shannons; set both to 0 for signature path.
    static bool verifyACP(const NativeLockCtx& ctx,
                           uint64_t inputCapacity, uint64_t outputCapacity);

    // Dispatch: identify lock from codeHash32 and call appropriate verifier.
    // For ACP, uses signature path (inputCapacity=outputCapacity=0).
    static bool verify(const uint8_t* codeHash32, const NativeLockCtx& ctx);

    // ── Helpers (public for testing) ─────────────────────────────────────────

    // Extract lock bytes from WitnessArgs molecule.
    // WitnessArgs = Table{lock: Option<Bytes>, ...}
    // Returns pointer into witness buffer at lock data, sets *lenOut.
    // Returns nullptr if malformed or lock field absent.
    static const uint8_t* extractWitnessLock(const uint8_t* witness,
                                               size_t witnessLen,
                                               size_t* lenOut);

    // blake160: first 20 bytes of blake2b_ckb(data, len)
    static void blake160(const uint8_t* data, size_t len, uint8_t out20[20]);

    // Parse multisig lockArgs header. Returns false if malformed.
    // lockArgs[0] = reserved (must be 0)
    // lockArgs[1] = requiredFirstN
    // lockArgs[2] = threshold
    // lockArgs[3] = keyCount
    // lockArgs[4..4+20*keyCount] = pubkeyHashes
    static bool parseMultisigArgs(const uint8_t* lockArgs, size_t lockArgsLen,
                                   uint8_t* reservedOut, uint8_t* requiredFirstNOut,
                                   uint8_t* thresholdOut,  uint8_t* keyCountOut);
};
