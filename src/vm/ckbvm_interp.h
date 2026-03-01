#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// =============================================================================
// ckbvm_interp.h — Minimal CKB-VM RISC-V interpreter for ckb-light-esp
//
// CKB-VM executes RV64IMC ELF binaries for lock/type script validation.
// This interpreter targets ESP32-P4 and ESP32-S3 with PSRAM.
//
// For standard transactions (secp256k1/multisig/ACP locks), use native_locks.h
// instead — it's orders of magnitude faster and uses far less RAM.
// This interpreter handles custom or non-standard lock scripts.
//
// ISA: RV64IMC (no F/D float — CKB-VM doesn't need them per RFC 0003)
// ELF: ELFCLASS64, EM_RISCV, statically linked (no dynamic linking)
// Syscalls: core set per RFC 0009 (pre-ckb2021 Spawn additions)
//
// Memory model (flat, in PSRAM):
//   [0x00000000 .. 0x00000FFF] unmapped (null page trap)
//   [0x00010000 .. 0x00010000+scriptSize] ELF PT_LOAD segments
//   [heapBase .. stackBase]    heap (grows up)
//   [stackBase .. memTop]      stack (grows down, 64KB)
//
// Requires: LIGHT_WITH_VM define + PSRAM (ESP32-P4 or S3 with 8MB+ PSRAM)
//
// Cycle limit: 70,000,000 (matches CKB consensus limit)
// Max script: 512KB loaded into PSRAM
// =============================================================================

#ifdef LIGHT_WITH_VM

// ── Constants ─────────────────────────────────────────────────────────────────
#define CKBVM_MAX_SCRIPT_SIZE   (512 * 1024)    // 512KB ELF in PSRAM
#define CKBVM_MAX_CYCLES        70000000ULL     // CKB consensus limit
#define CKBVM_REG_COUNT         32
#define CKBVM_STACK_SIZE        (64  * 1024)    // 64KB stack
#define CKBVM_HEAP_SIZE         (128 * 1024)    // 128KB heap
#define CKBVM_LOAD_BASE         0x00010000ULL   // ELF load address

// ── Exit codes ────────────────────────────────────────────────────────────────
#define CKBVM_EXIT_SUCCESS      0
#define CKBVM_EXIT_FAILURE      1
#define CKBVM_EXIT_CYCLES       (-1)   // cycle limit exceeded
#define CKBVM_EXIT_INVALID_OP   (-2)   // illegal instruction
#define CKBVM_EXIT_SYSCALL_ERR  (-3)   // syscall failed
#define CKBVM_EXIT_LOAD_ERR     (-4)   // ELF load error
#define CKBVM_EXIT_MEM_FAULT    (-5)   // memory access fault
// Internal sentinel: exit(0) called — distinguish from "continue" (also 0)
#define CKBVM_INTERNAL_EXIT0    (-100)

// ── Syscall numbers (RFC 0009) ────────────────────────────────────────────────
#define CKB_SYSCALL_EXIT           93
#define CKB_SYSCALL_LOAD_TX_HASH   2061
#define CKB_SYSCALL_LOAD_SCRIPT_HASH 2062
#define CKB_SYSCALL_LOAD_TX        2051
#define CKB_SYSCALL_LOAD_SCRIPT    2052
#define CKB_SYSCALL_LOAD_CELL      2071
#define CKB_SYSCALL_LOAD_HEADER    2072
#define CKB_SYSCALL_LOAD_INPUT     2073
#define CKB_SYSCALL_LOAD_WITNESS   2074
#define CKB_SYSCALL_LOAD_CELL_DATA 2069
#define CKB_SYSCALL_DEBUG          2177

// Syscall return codes
#define SYSCALL_SUCCESS            0
#define SYSCALL_ITEM_MISSING       1   // requested item doesn't exist
#define SYSCALL_INDEX_OUT_OF_BOUND 1   // index too large
#define SYSCALL_ENCODING           2   // encoding error

// ── Source constants (for Load* syscalls) ────────────────────────────────────
#define SOURCE_INPUT               1
#define SOURCE_OUTPUT              2
#define SOURCE_CELL_DEP            3
#define SOURCE_HEADER_DEP          4
// ckb2021 group sources
#define SOURCE_GROUP_INPUT         0x0100000000000001ULL
#define SOURCE_GROUP_OUTPUT        0x0100000000000002ULL

// ── CKBVMContext — data available to the running script ───────────────────────
// Caller (LightClient) fills this before calling execute().
// All pointers remain valid for the duration of execution.
typedef struct {
    // Transaction identity
    const uint8_t* txHash;          // 32 bytes — blake2b of serialised tx
    size_t         txHashLen;       // always 32

    // Current script being executed
    const uint8_t* scriptHash;      // 32 bytes — blake2b of Molecule Script
    size_t         scriptHashLen;   // always 32
    const uint8_t* script;          // Molecule-encoded Script bytes
    size_t         scriptLen;

    // Witness for this input (Molecule WitnessArgs)
    const uint8_t* witness;
    size_t         witnessLen;

    // Cell data for this input (raw bytes)
    const uint8_t* cellData;
    size_t         cellDataLen;
} CKBVMContext;

// ── CKBVMInterp ───────────────────────────────────────────────────────────────
class CKBVMInterp {
public:
    CKBVMInterp();
    ~CKBVMInterp();

    // Load a statically-linked RV64IMC ELF binary into PSRAM.
    // Must be called before execute(). Returns false on error.
    bool loadScript(const uint8_t* elfData, size_t elfLen);

    // Execute the loaded script with the given context.
    // Returns CKBVM_EXIT_* code; cyclesUsed is optional output.
    int execute(const CKBVMContext& ctx, uint64_t* cyclesUsed = nullptr);

    // Reset register + PC state (keep loaded script + PSRAM).
    void reset();

    // Unload script and free PSRAM.
    void unload();

    bool        isLoaded()  const { return _loaded; }
    uint64_t    lastCycles() const { return _cycles; }
    const char* lastError()  const { return _lastError; }

#ifdef HOST_TEST
    // Expose internals for unit tests
    uint64_t  _pc;
    uint64_t  _entryPc;
    uint64_t  _regs[CKBVM_REG_COUNT];
    uint64_t  _cycles;
    uint8_t*  _mem;
    size_t    _memSize;
    uint64_t  _stackBase;
    uint64_t  _heapBase;

    int  stepPub(const CKBVMContext& ctx) { return _step(ctx); }
    bool memReadPub(uint64_t a, void* o, size_t n) { return _memRead(a,o,n); }
    bool memWritePub(uint64_t a, const void* i, size_t n) { return _memWrite(a,i,n); }
#else
    uint64_t  _pc;
    uint64_t  _entryPc;
    uint64_t  _regs[CKBVM_REG_COUNT];
    uint64_t  _cycles;
    uint8_t*  _mem;
    size_t    _memSize;
    uint64_t  _stackBase;
    uint64_t  _heapBase;
#endif

    bool      _loaded;
    char      _lastError[80];

    // One-step decode+execute. Returns CKBVM_EXIT_* or 0 to continue.
    int  _step(const CKBVMContext& ctx);

    // Syscall dispatch (ecall/scall — same opcode in RISC-V)
    int  _syscall(const CKBVMContext& ctx);

    // Partial-load helper (RFC 0009 §Partial Loading)
    int  _partialLoad(uint64_t addrReg, uint64_t lenPtrReg, uint64_t offsetReg,
                       const uint8_t* data, size_t dataLen);

    // Memory helpers (bounds-checked)
    bool _memRead(uint64_t addr, void* out, size_t len);
    bool _memWrite(uint64_t addr, const void* in, size_t len);

    // ELF loader
    bool _loadElf(const uint8_t* elf, size_t elfLen);

    // Allocate PSRAM (or malloc on host)
    bool _allocMem(size_t size);
    void _freeMem();

    void _setError(const char* msg);
};

#endif // LIGHT_WITH_VM
