#pragma once
#include <stdint.h>
#include <stdbool.h>

// =============================================================================
// native_locks.h — Native C implementations of common CKB lock scripts
//
// Avoids CKB-VM entirely for well-known lock scripts.
// Covers ~99% of real-world CKB transactions.
// Much faster and lower RAM than running the VM interpreter.
//
// Supported locks:
//   - SECP256K1_BLAKE160_SIGHASH_ALL  (default lock, most wallets)
//   - SECP256K1_BLAKE160_MULTISIG     (multisig)
//   - ANYONE_CAN_PAY                  (ACP)
// =============================================================================

// Well-known lock script code hashes (mainnet)
#define SECP256K1_BLAKE160_CODE_HASH \
  "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"

#define SECP256K1_MULTISIG_CODE_HASH \
  "0x5c5069eb0857efc65e1bca0c07df34c31663b3622fd3876c876320fc9634e2a8"

#define ANYONE_CAN_PAY_CODE_HASH \
  "0xd369597ff47f29febb9b5e3a bind this properly when implementing"

// Signature context for native verification
typedef struct {
  const uint8_t* txHash;        // 32-byte signing hash (Blake2b of tx)
  const uint8_t* witness;       // raw WitnessArgs bytes
  size_t         witnessLen;
  const uint8_t* lockArgs;      // script.args (20-byte pubkey hash for secp256k1)
  size_t         lockArgsLen;
} NativeLockCtx;

class NativeLocks {
public:
  // Identify lock type from code_hash
  // Returns one of LOCK_TYPE_* constants, or LOCK_TYPE_UNKNOWN
  static uint8_t identifyLock(const uint8_t* codeHash32);

  // Verify secp256k1-blake160-sighash-all lock
  // Returns true if witness signature is valid for txHash + lockArgs pubkey hash
  static bool verifySecp256k1(const NativeLockCtx& ctx);

  // Verify secp256k1-blake160-multisig lock
  // threshold and required signers parsed from lockArgs
  static bool verifyMultisig(const NativeLockCtx& ctx);

  // Verify anyone-can-pay lock (always true for receiving, amount check for spending)
  static bool verifyACP(const NativeLockCtx& ctx, uint64_t inputCapacity, uint64_t outputCapacity);

  // Dispatch to correct verifier based on code_hash
  static bool verify(const uint8_t* codeHash32, const NativeLockCtx& ctx);

#define LOCK_TYPE_UNKNOWN   0x00
#define LOCK_TYPE_SECP256K1 0x01
#define LOCK_TYPE_MULTISIG  0x02
#define LOCK_TYPE_ACP       0x03
};
