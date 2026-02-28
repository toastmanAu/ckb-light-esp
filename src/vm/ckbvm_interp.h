#pragma once
#include <stdint.h>
#include <stdbool.h>

// =============================================================================
// ckbvm_interp.h — Minimal CKB-VM RISC-V interpreter
//
// CKB-VM executes RISC-V (RV64IMC) bytecode for lock/type script validation.
// This interpreter targets ESP32-P4 and ESP32-S3 with PSRAM.
//
// For most transactions (secp256k1 locks), use native_locks.h instead —
// it's orders of magnitude faster and uses far less RAM.
//
// This interpreter is for non-standard or custom lock scripts.
//
// Requires: LIGHT_WITH_VM + PSRAM
//           (bytecode loaded into PSRAM, not IRAM)
//
// Limitations (v0.1):
//   - RV64IMC only (no F/D float extensions — CKB-VM doesn't need them)
//   - Syscalls: ckb_load_tx_hash, ckb_load_script, ckb_load_cell_data (basic set)
//   - Max script size: 128KB
//   - Max cycles: configurable (default 70M — matches CKB consensus limit)
// =============================================================================

#ifdef LIGHT_WITH_VM

#define CKBVM_MAX_SCRIPT_SIZE   (128 * 1024)   // 128KB
#define CKBVM_MAX_CYCLES        70000000ULL     // CKB consensus limit
#define CKBVM_REG_COUNT         32
#define CKBVM_STACK_SIZE        (64 * 1024)     // 64KB stack in PSRAM

// VM exit codes (mirrors CKB-VM)
#define CKBVM_EXIT_SUCCESS      0
#define CKBVM_EXIT_FAILURE      1
#define CKBVM_EXIT_CYCLES       (-1)   // cycle limit exceeded
#define CKBVM_EXIT_INVALID_OP   (-2)   // illegal instruction
#define CKBVM_EXIT_SYSCALL_ERR  (-3)   // syscall failed

// Context passed to syscall handlers
typedef struct {
  const uint8_t* txHash;      // 32 bytes
  const uint8_t* scriptArgs;  // variable
  size_t         scriptArgsLen;
  const uint8_t* witness;     // raw witness bytes for this input
  size_t         witnessLen;
} CKBVMContext;

class CKBVMInterp {
public:
  CKBVMInterp();

  // Load RISC-V ELF bytecode into PSRAM
  // Returns false if too large or PSRAM unavailable
  bool loadScript(const uint8_t* elfData, size_t elfLen);

  // Execute the loaded script with the given context
  // Returns CKBVM_EXIT_* code
  int execute(const CKBVMContext& ctx, uint64_t* cyclesUsed = nullptr);

  // Reset interpreter state (keep loaded script)
  void reset();

  // Unload script, free PSRAM
  void unload();

  const char* lastError() const { return _lastError; }

private:
  uint64_t  _regs[CKBVM_REG_COUNT];
  uint64_t  _pc;
  uint64_t  _cycles;

  uint8_t*  _mem;          // PSRAM allocation for script + stack + heap
  size_t    _memSize;
  bool      _loaded;

  char      _lastError[64];

  // Instruction decode + execute (one step)
  int  _step();

  // Syscall dispatch
  int  _syscall(uint64_t id, const CKBVMContext& ctx);

  // Memory access helpers
  bool _memRead(uint64_t addr, void* out, size_t len);
  bool _memWrite(uint64_t addr, const void* in, size_t len);
};

#endif // LIGHT_WITH_VM
