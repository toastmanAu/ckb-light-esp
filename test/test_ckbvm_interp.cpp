// test_ckbvm_interp.cpp — host tests for ckbvm_interp.cpp
//
// Tests use hand-assembled RV64IMC ELF binaries — no riscv-gcc needed.
// ELF builder helpers construct minimal valid executables from raw instruction bytes.
//
// Build:
//   g++ -DHOST_TEST -DLIGHT_WITH_VM -std=c++11 \
//       -I. -Isrc -Isrc/vm -Isrc/core -Itest \
//       -I/home/phill/workspace/CKB-ESP32/src \
//       test/test_ckbvm_interp.cpp src/vm/ckbvm_interp.cpp \
//       -o test/test_vm && test/test_vm

#define HOST_TEST
#define LIGHT_WITH_VM
#include "blake2b_real.h"
#include "ckb_hex.h"
#include "ckbvm_interp.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <vector>

// ── Test harness ──────────────────────────────────────────────────────────────
static int _pass = 0, _fail = 0;
#define CHECK(cond, name) do { \
    if (cond) { printf("  PASS: %s\n", name); _pass++; } \
    else      { printf("  FAIL: %s (line %d)\n", name, __LINE__); _fail++; } \
} while(0)

// ── Minimal ELF64 builder ─────────────────────────────────────────────────────
// Constructs a valid ELF64 RISC-V executable with one PT_LOAD segment
// containing the supplied instruction bytes.
// Entry point = CKBVM_LOAD_BASE (0x00010000).

#define ELF_LOAD_BASE CKBVM_LOAD_BASE

static std::vector<uint8_t> makeElf(const uint8_t* code, size_t codeLen) {
    // ELF header = 64 bytes, one Program Header = 56 bytes
    size_t phOff    = 64;
    size_t dataOff  = phOff + 56;
    size_t fileSize = dataOff + codeLen;

    std::vector<uint8_t> elf(fileSize, 0);

    auto w16 = [&](size_t off, uint16_t v) { memcpy(&elf[off], &v, 2); };
    auto w32 = [&](size_t off, uint32_t v) { memcpy(&elf[off], &v, 4); };
    auto w64 = [&](size_t off, uint64_t v) { memcpy(&elf[off], &v, 8); };

    // ELF ident
    elf[0]=0x7F; elf[1]='E'; elf[2]='L'; elf[3]='F';
    elf[4]=2;    // ELFCLASS64
    elf[5]=1;    // ELFDATA2LSB
    elf[6]=1;    // EV_CURRENT
    // e_type=ET_EXEC(2), e_machine=EM_RISCV(243)
    w16(16, 2); w16(18, 243);
    w32(20, 1); // e_version
    w64(24, ELF_LOAD_BASE + dataOff); // e_entry
    w64(32, phOff);  // e_phoff
    w64(40, 0);      // e_shoff
    w32(48, 0);      // e_flags
    w16(52, 64);     // e_ehsize
    w16(54, 56);     // e_phentsize
    w16(56, 1);      // e_phnum
    w16(58, 64); w16(60, 0); w16(62, 0); // shentsize, shnum, shstrndx

    // Program header (PT_LOAD)
    w32(phOff+0,  1);                        // p_type = PT_LOAD
    w32(phOff+4,  5);                        // p_flags = R|X
    w64(phOff+8,  dataOff);                  // p_offset
    w64(phOff+16, ELF_LOAD_BASE + dataOff);  // p_vaddr
    w64(phOff+24, ELF_LOAD_BASE + dataOff);  // p_paddr
    w64(phOff+32, codeLen);                  // p_filesz
    w64(phOff+40, codeLen);                  // p_memsz
    w64(phOff+48, 0x1000);                   // p_align

    memcpy(&elf[dataOff], code, codeLen);
    return elf;
}

// ── Instruction encoders ──────────────────────────────────────────────────────
// RV64I encoding helpers (all return 4-byte little-endian uint32_t)

// ADDI rd, rs1, imm12
static uint32_t ADDI(int rd, int rs1, int32_t imm) {
    return (uint32_t)(((imm&0xFFF)<<20)|(rs1<<15)|(0<<12)|(rd<<7)|0x13);
}
// LI rd, imm12 = ADDI rd, x0, imm
static uint32_t LI(int rd, int32_t imm) { return ADDI(rd, 0, imm); }

// ADD rd, rs1, rs2
static uint32_t ADD(int rd, int rs1, int rs2) {
    return (uint32_t)((rs2<<20)|(rs1<<15)|(0<<12)|(rd<<7)|0x33);
}
// SUB rd, rs1, rs2
static uint32_t SUB(int rd, int rs1, int rs2) {
    return (uint32_t)((0x20<<25)|(rs2<<20)|(rs1<<15)|(0<<12)|(rd<<7)|0x33);
}
// MUL rd, rs1, rs2
static uint32_t MUL(int rd, int rs1, int rs2) {
    return (uint32_t)((0x01<<25)|(rs2<<20)|(rs1<<15)|(0<<12)|(rd<<7)|0x33);
}
// XOR rd, rs1, rs2
static uint32_t XOR_R(int rd, int rs1, int rs2) {
    return (uint32_t)((rs2<<20)|(rs1<<15)|(4<<12)|(rd<<7)|0x33);
}
// ECALL (syscall)
static uint32_t ECALL() { return 0x73; }

// BEQ rs1, rs2, offset13 (offset relative to instruction)
static uint32_t BEQ(int rs1, int rs2, int32_t off) {
    uint32_t imm12 = (off>>12)&1, imm11 = (off>>11)&1;
    uint32_t imm10_5 = (off>>5)&0x3F, imm4_1 = (off>>1)&0xF;
    return (uint32_t)((imm12<<31)|(imm10_5<<25)|(rs2<<20)|(rs1<<15)|(0<<12)|
                       (imm4_1<<8)|(imm11<<7)|0x63);
}
// JAL x0, offset — unconditional jump
static uint32_t JAL_0(int32_t off) {
    uint32_t imm20=(off>>20)&1, imm10_1=(off>>1)&0x3FF;
    uint32_t imm11=(off>>11)&1, imm19_12=(off>>12)&0xFF;
    return (uint32_t)((imm20<<31)|(imm19_12<<12)|(imm11<<20)|(imm10_1<<21)|0x6F);
}
// SD rs2, imm(rs1)
static uint32_t SD(int rs1, int rs2, int32_t imm) {
    uint32_t imm11_5=(imm>>5)&0x7F, imm4_0=imm&0x1F;
    return (uint32_t)((imm11_5<<25)|(rs2<<20)|(rs1<<15)|(3<<12)|(imm4_0<<7)|0x23);
}
// LD rd, imm(rs1)
static uint32_t LD(int rd, int rs1, int32_t imm) {
    return (uint32_t)(((imm&0xFFF)<<20)|(rs1<<15)|(3<<12)|(rd<<7)|0x03);
}
// LUI rd, imm20 (upper 20 bits)
static uint32_t LUI(int rd, uint32_t imm20) {
    return (uint32_t)((imm20<<12)|(rd<<7)|0x37);
}

// ── Syscall helpers ───────────────────────────────────────────────────────────
// Build code that: loads syscall number into a7, args into a0-a5, then ECALL.
// All values are 12-bit immediates for simplicity.

// Exit with code in a0 (caller sets a0 before this)
static void emitExit(std::vector<uint32_t>& code, int8_t exitCode) {
    code.push_back(LI(10, exitCode));   // a0 = exitCode
    code.push_back(LI(17, 93));         // a7 = CKB_SYSCALL_EXIT
    code.push_back(ECALL());
}

// Load 64-bit immediate into register (LUI + ADDI, handles >12-bit values)
static void emitLI64(std::vector<uint32_t>& c, int rd, int64_t val) {
    if (val >= -2048 && val <= 2047) {
        c.push_back(LI(rd, (int32_t)val));
    } else {
        // LUI loads upper 20 bits; ADDI adds lower 12 (sign-extended)
        int32_t lo12 = (int32_t)(val & 0xFFF);
        if (lo12 > 2047) lo12 -= 4096; // sign adjust
        int32_t hi20 = (int32_t)((val - lo12) >> 12);
        c.push_back(LUI(rd, (uint32_t)hi20));
        if (lo12 != 0) c.push_back(ADDI(rd, rd, lo12));
    }
}

// Convert vector<uint32_t> to bytes
static std::vector<uint8_t> toBytes(const std::vector<uint32_t>& code) {
    std::vector<uint8_t> out(code.size() * 4);
    for (size_t i = 0; i < code.size(); i++)
        memcpy(&out[i*4], &code[i], 4);
    return out;
}

// ── Shared context ────────────────────────────────────────────────────────────
static CKBVMContext makeCtx() {
    static uint8_t txHash[32]     = {0xAA};
    static uint8_t scriptHash[32] = {0xBB};
    static uint8_t script[8]      = {0x08,0x00,0x00,0x00,0x10,0x00,0x00,0x00}; // minimal
    static uint8_t witness[85]    = {0};
    static uint8_t cellData[4]    = {0x01,0x02,0x03,0x04};

    CKBVMContext ctx = {};
    ctx.txHash       = txHash;       ctx.txHashLen     = 32;
    ctx.scriptHash   = scriptHash;   ctx.scriptHashLen = 32;
    ctx.script       = script;       ctx.scriptLen     = 8;
    ctx.witness      = witness;      ctx.witnessLen    = 85;
    ctx.cellData     = cellData;     ctx.cellDataLen   = 4;
    return ctx;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

void testElfLoad() {
    printf("\n[1] ELF loading\n");

    // Minimal valid ELF: just ECALL exit(0)
    std::vector<uint32_t> code;
    emitExit(code, 0);
    auto bytes = toBytes(code);
    auto elf   = makeElf(bytes.data(), bytes.size());

    CKBVMInterp vm;
    CHECK(vm.loadScript(elf.data(), elf.size()), "load valid ELF");
    CHECK(vm.isLoaded(), "isLoaded() true");
    CHECK(vm._pc == ELF_LOAD_BASE + 64 + 56, "PC at entry point (past headers)");
    CHECK(vm._regs[2] != 0, "stack pointer initialised");
    printf("  INFO: entry PC=0x%llx  sp=0x%llx\n",
           (unsigned long long)vm._pc, (unsigned long long)vm._regs[2]);

    // Reject non-ELF
    uint8_t garbage[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    CHECK(!vm.loadScript(garbage, sizeof(garbage)), "garbage rejected");
    CHECK(strlen(vm.lastError()) > 0, "error message set");

    // Reject too small
    uint8_t tiny[] = {0x7F, 'E', 'L', 'F'};
    CHECK(!vm.loadScript(tiny, sizeof(tiny)), "tiny ELF rejected");
}

void testExecuteExit() {
    printf("\n[2] execute() — exit codes\n");

    auto ctx = makeCtx();

    // exit(0)
    {
        std::vector<uint32_t> code; emitExit(code, 0);
        auto b = toBytes(code); auto e = makeElf(b.data(), b.size());
        CKBVMInterp vm; vm.loadScript(e.data(), e.size());
        uint64_t cycles = 0;
        int r = vm.execute(ctx, &cycles);
        CHECK(r == CKBVM_EXIT_SUCCESS, "exit(0) returns SUCCESS");
        CHECK(cycles > 0, "cycles consumed > 0");
        printf("  INFO: exit(0) used %llu cycles\n", (unsigned long long)cycles);
    }

    // exit(1)
    {
        std::vector<uint32_t> code; emitExit(code, 1);
        auto b = toBytes(code); auto e = makeElf(b.data(), b.size());
        CKBVMInterp vm; vm.loadScript(e.data(), e.size());
        int r = vm.execute(ctx);
        CHECK(r == CKBVM_EXIT_FAILURE, "exit(1) returns FAILURE");
    }

    // exit(-1) via int8 wrapping
    {
        std::vector<uint32_t> code; emitExit(code, -1);
        auto b = toBytes(code); auto e = makeElf(b.data(), b.size());
        CKBVMInterp vm; vm.loadScript(e.data(), e.size());
        int r = vm.execute(ctx);
        CHECK(r == -1, "exit(-1) returns -1");
    }
}

void testALU() {
    printf("\n[3] ALU — RV64I + M extension\n");

    auto ctx = makeCtx();

    // x10 = 3 + 4 = 7; exit(x10 - 7) → exit(0)
    {
        std::vector<uint32_t> c;
        c.push_back(LI(10, 3));
        c.push_back(LI(11, 4));
        c.push_back(ADD(10, 10, 11));  // x10 = 7
        c.push_back(LI(11, 7));
        c.push_back(SUB(10, 10, 11));  // x10 = 0
        c.push_back(LI(17, 93)); c.push_back(ECALL());
        auto b=toBytes(c); auto e=makeElf(b.data(),b.size());
        CKBVMInterp vm; vm.loadScript(e.data(),e.size());
        CHECK(vm.execute(ctx)==0, "ADD/SUB: 3+4-7=0 → exit(0)");
    }

    // MUL: x10 = 6 * 7 = 42, exit(42)
    {
        std::vector<uint32_t> c;
        c.push_back(LI(10, 6));
        c.push_back(LI(11, 7));
        c.push_back(MUL(10, 10, 11)); // x10 = 42
        c.push_back(LI(17, 93)); c.push_back(ECALL());
        auto b=toBytes(c); auto e=makeElf(b.data(),b.size());
        CKBVMInterp vm; vm.loadScript(e.data(),e.size());
        CHECK(vm.execute(ctx)==42, "MUL: 6*7=42 → exit(42)");
    }

    // XOR: exit(0xFF ^ 0xFF) → exit(0)
    {
        std::vector<uint32_t> c;
        c.push_back(LI(10, 0xFF));
        c.push_back(LI(11, 0xFF));
        c.push_back(XOR_R(10, 10, 11));
        c.push_back(LI(17, 93)); c.push_back(ECALL());
        auto b=toBytes(c); auto e=makeElf(b.data(),b.size());
        CKBVMInterp vm; vm.loadScript(e.data(),e.size());
        CHECK(vm.execute(ctx)==0, "XOR: 0xFF^0xFF=0 → exit(0)");
    }
}

void testMemory() {
    printf("\n[4] Memory — load/store round-trip\n");

    auto ctx = makeCtx();

    // Store 0xDEAD to stack, load it back, exit(loaded - 0xDEAD)
    // sp is at _stackBase + 64KB - 16
    // We'll use: SD x10, -8(sp); LD x11, -8(sp); exit(x11 - x10)
    {
        std::vector<uint32_t> c;
        c.push_back(LI(10, 42));        // value to store
        c.push_back(SD(2, 10, -8));     // mem[sp-8] = 42
        c.push_back(LD(11, 2, -8));     // x11 = mem[sp-8]
        c.push_back(SUB(10, 11, 10));   // x10 = x11 - 42 = 0
        c.push_back(LI(17, 93)); c.push_back(ECALL());
        auto b=toBytes(c); auto e=makeElf(b.data(),b.size());
        CKBVMInterp vm; vm.loadScript(e.data(),e.size());
        CHECK(vm.execute(ctx)==0, "SD/LD round-trip: store 42, load, subtract = 0");
    }
}

void testBranch() {
    printf("\n[5] Branch — BEQ + JAL\n");

    auto ctx = makeCtx();

    // Loop: x10 counts 0→3, exit when done
    // x10 = 0
    // loop: if x10 == 3 → exit(0)
    //       x10 = x10 + 1
    //       jump back to loop
    {
        std::vector<uint32_t> c;
        c.push_back(LI(10, 0));          // [0] x10 = 0
        c.push_back(LI(11, 3));          // [1] x11 = 3 (target)
        // [2] BEQ x10,x11, +12 → jump to exit (3 instructions ahead = +12)
        c.push_back(BEQ(10, 11, 12));
        c.push_back(ADDI(10, 10, 1));    // [3] x10++
        c.push_back(JAL_0(-8));          // [4] jump back to [2] (offset -8)
        // [5] exit(0)
        c.push_back(LI(10, 0));
        c.push_back(LI(17, 93)); c.push_back(ECALL());
        auto b=toBytes(c); auto e=makeElf(b.data(),b.size());
        CKBVMInterp vm; vm.loadScript(e.data(),e.size());
        uint64_t cycles = 0;
        int r = vm.execute(ctx, &cycles);
        CHECK(r == 0, "loop 0..3: BEQ exits when x10==3");
        printf("  INFO: loop used %llu cycles\n", (unsigned long long)cycles);
    }
}

void testSyscallLoadTxHash() {
    printf("\n[6] Syscall — LoadTxHash\n");

    auto ctx = makeCtx();
    // txHash[0] = 0xAA (from makeCtx)
    // Stack layout: buf at sp-64, len ptr at sp-8
    // After syscall: LBU x10, 0(buf) should be 0xAA → exit(0xAA-0xAA)=exit(0)

    {
        std::vector<uint32_t> c;
        c.push_back(ADDI(5, 2, -64));      // x5 = sp-64 (buf)
        c.push_back(ADDI(6, 2, -8));       // x6 = sp-8  (len ptr)
        c.push_back(LI(10, 32));
        c.push_back(SD(6, 10, 0));         // mem[x6] = 32 (buf size)

        c.push_back(ADDI(10, 5, 0));       // a0 = buf
        c.push_back(ADDI(11, 6, 0));       // a1 = &len
        c.push_back(LI(12, 0));            // a2 = offset 0
        emitLI64(c, 17, CKB_SYSCALL_LOAD_TX_HASH); // a7 = 2061 (>12-bit, needs LUI+ADDI)
        c.push_back(ECALL());

        // LBU x10, 0(x5) — load unsigned byte from buf[0]
        uint32_t lbu = (uint32_t)((0<<20)|(5<<15)|(4<<12)|(10<<7)|0x03);
        c.push_back(lbu);

        c.push_back(LI(11, 0xAA));
        c.push_back(SUB(10, 10, 11));      // x10 = 0xAA - 0xAA = 0
        c.push_back(LI(17, 93));
        c.push_back(ECALL());

        auto b=toBytes(c); auto e=makeElf(b.data(),b.size());
        CKBVMInterp vm; vm.loadScript(e.data(),e.size());
        int r = vm.execute(ctx);
        CHECK(r == 0, "LoadTxHash: buf[0]=0xAA, exit(0xAA-0xAA=0)");
    }
}

void testSyscallDebug() {
    printf("\n[7] Syscall — Debug (2177)\n");

    auto ctx = makeCtx();
    // Write "OK" to stack, call Debug, then exit(0)
    // String at sp-16: 'O','K',0

    {
        std::vector<uint32_t> c;
        // Store "OK\0" at sp-16
        // 'O'=0x4F, 'K'=0x4B, null=0
        // Pack as 64-bit LE: 0x00000000004B4F
        // Use LUI+ADDI to build the immediate — simpler: store byte by byte
        // Actually, just store the constant as a 32-bit word: 0x00004B4F
        c.push_back(ADDI(5, 2, -16));      // x5 = sp-16 (string base)
        // LUI x6, 0 then ADDI x6, x6, 0x4F → x6 = 'O'
        c.push_back(LI(6, 0x4F));          // 'O'
        uint32_t sb_O = (uint32_t)((0<<25)|(6<<20)|(5<<15)|(0<<12)|(0<<7)|0x23); // SB x6, 0(x5)
        c.push_back(sb_O);
        c.push_back(LI(6, 0x4B));          // 'K'
        uint32_t sb_K = (uint32_t)((0<<25)|(6<<20)|(5<<15)|(0<<12)|(1<<7)|0x23); // SB x6, 1(x5)
        c.push_back(sb_K);
        c.push_back(LI(6, 0));             // null
        uint32_t sb_N = (uint32_t)((0<<25)|(6<<20)|(5<<15)|(0<<12)|(2<<7)|0x23); // SB x6, 2(x5)
        c.push_back(sb_N);

        c.push_back(ADDI(10, 5, 0));       // a0 = string ptr
        c.push_back(LI(17, 2177));         // a7 = Debug
        c.push_back(ECALL());              // prints "[CKB-VM] OK"

        emitExit(c, 0);

        auto b=toBytes(c); auto e=makeElf(b.data(),b.size());
        CKBVMInterp vm; vm.loadScript(e.data(),e.size());
        int r = vm.execute(ctx);
        CHECK(r == 0, "Debug syscall: prints OK, exit(0)");
    }
}

void testCycleLimitBlocked() {
    printf("\n[8] Cycle limit enforcement\n");

    auto ctx = makeCtx();

    // Infinite loop: JAL x0, 0 (jump to self)
    {
        std::vector<uint32_t> c;
        c.push_back(JAL_0(0)); // infinite self-jump

        auto b=toBytes(c); auto e=makeElf(b.data(),b.size());
        CKBVMInterp vm; vm.loadScript(e.data(),e.size());
        uint64_t cycles = 0;
        int r = vm.execute(ctx, &cycles);
        CHECK(r == CKBVM_EXIT_CYCLES, "infinite loop hits cycle limit");
        CHECK(cycles >= CKBVM_MAX_CYCLES, "cycle count at limit");
        printf("  INFO: hit limit at %llu cycles\n", (unsigned long long)cycles);
    }
}

void testMemFault() {
    printf("\n[9] Memory fault — null page access\n");

    auto ctx = makeCtx();

    // Try to load from address 0x00 (null page — unmapped below CKBVM_LOAD_BASE)
    {
        std::vector<uint32_t> c;
        c.push_back(LI(5, 0));           // x5 = 0
        c.push_back(LD(10, 5, 0));       // LD x10, 0(x5) — should fault
        emitExit(c, 0);
        auto b=toBytes(c); auto e=makeElf(b.data(),b.size());
        CKBVMInterp vm; vm.loadScript(e.data(),e.size());
        int r = vm.execute(ctx);
        CHECK(r == CKBVM_EXIT_MEM_FAULT, "load from addr 0 causes MEM_FAULT");
    }
}

void testResetAndReuse() {
    printf("\n[10] reset() — reuse VM between executions\n");

    auto ctx = makeCtx();

    std::vector<uint32_t> code; emitExit(code, 0);
    auto b=toBytes(code); auto e=makeElf(b.data(),b.size());

    CKBVMInterp vm;
    vm.loadScript(e.data(), e.size());
    int r1 = vm.execute(ctx);
    CHECK(r1 == 0, "first execute: exit(0)");

    vm.reset();
    CHECK(vm.isLoaded(), "still loaded after reset");
    int r2 = vm.execute(ctx);
    CHECK(r2 == 0, "second execute after reset: exit(0)");
}

// ── main ──────────────────────────────────────────────────────────────────────
int main() {
    printf("========================================\n");
    printf("  ckbvm_interp.cpp host tests\n");
    printf("========================================\n");

    testElfLoad();
    testExecuteExit();
    testALU();
    testMemory();
    testBranch();
    testSyscallLoadTxHash();
    testSyscallDebug();
    testCycleLimitBlocked();
    testMemFault();
    testResetAndReuse();

    printf("\n========================================\n");
    printf("  Results: %d passed, %d failed\n", _pass, _fail);
    printf("========================================\n");
    return _fail > 0 ? 1 : 0;
}
