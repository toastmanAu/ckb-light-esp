// ckbvm_interp.cpp — Minimal CKB-VM RV64IMC interpreter
//
// ISA: RV64IMC per RFC 0003
// Syscalls: core set per RFC 0009
// ELF: ELFCLASS64 EM_RISCV statically linked PT_LOAD segments

#define LIGHT_WITH_VM
#include "ckbvm_interp.h"
#include "ckb_blake2b.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// ── Memory allocator ──────────────────────────────────────────────────────────
#ifdef HOST_TEST
#  define VM_MALLOC(n)   malloc(n)
#  define VM_FREE(p)     free(p)
#else
extern "C" {
#  include "esp_heap_caps.h"
}
#  define VM_MALLOC(n)   heap_caps_malloc((n), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT)
#  define VM_FREE(p)     heap_caps_free(p)
#endif

// ── ELF constants ─────────────────────────────────────────────────────────────
#define ELF_MAGIC    0x464C457F
#define ELFCLASS64   2
#define ELFDATA2LSB  1
#define EM_RISCV     243
#define ET_EXEC      2
#define PT_LOAD      1

struct Elf64Hdr {
    uint8_t  e_ident[16];
    uint16_t e_type, e_machine;
    uint32_t e_version;
    uint64_t e_entry, e_phoff, e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize, e_phentsize, e_phnum;
    uint16_t e_shentsize, e_shnum, e_shstrndx;
} __attribute__((packed));

struct Elf64Phdr {
    uint32_t p_type, p_flags;
    uint64_t p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align;
} __attribute__((packed));

// ── Helpers ───────────────────────────────────────────────────────────────────
static inline int64_t  signext(uint64_t v, int bits) {
    int s = 64 - bits;
    return (int64_t)(v << s) >> s;
}
static inline uint64_t u64(int64_t v) { return (uint64_t)v; }

// ── Constructor / Destructor ──────────────────────────────────────────────────
CKBVMInterp::CKBVMInterp()
    : _pc(0), _entryPc(0), _cycles(0), _mem(nullptr), _memSize(0),
      _stackBase(0), _heapBase(0), _loaded(false) {
    memset(_regs, 0, sizeof(_regs));
    memset(_lastError, 0, sizeof(_lastError));
}
CKBVMInterp::~CKBVMInterp() { _freeMem(); }

void CKBVMInterp::_setError(const char* m) {
    strncpy(_lastError, m, sizeof(_lastError)-1);
    _lastError[sizeof(_lastError)-1] = '\0';
}

// ── Memory ────────────────────────────────────────────────────────────────────
bool CKBVMInterp::_allocMem(size_t sz) {
    _freeMem();
    _mem = (uint8_t*)VM_MALLOC(sz);
    if (!_mem) { _setError("alloc failed"); return false; }
    memset(_mem, 0, sz);
    _memSize = sz;
    return true;
}
void CKBVMInterp::_freeMem() {
    if (_mem) { VM_FREE(_mem); _mem = nullptr; }
    _memSize = 0;
}

bool CKBVMInterp::_memRead(uint64_t addr, void* out, size_t len) {
    if (addr < CKBVM_LOAD_BASE) return false;
    uint64_t off = addr - CKBVM_LOAD_BASE;
    if (off + len > _memSize) return false;
    memcpy(out, _mem + off, len);
    return true;
}
bool CKBVMInterp::_memWrite(uint64_t addr, const void* in, size_t len) {
    if (addr < CKBVM_LOAD_BASE) return false;
    uint64_t off = addr - CKBVM_LOAD_BASE;
    if (off + len > _memSize) return false;
    memcpy(_mem + off, in, len);
    return true;
}

// ── ELF Loader ────────────────────────────────────────────────────────────────
bool CKBVMInterp::_loadElf(const uint8_t* elf, size_t elfLen) {
    if (elfLen < sizeof(Elf64Hdr)) { _setError("ELF too small"); return false; }
    const Elf64Hdr* h = (const Elf64Hdr*)elf;
    if (*(uint32_t*)h->e_ident != ELF_MAGIC)  { _setError("not ELF");      return false; }
    if (h->e_ident[4] != ELFCLASS64)           { _setError("not ELF64");    return false; }
    if (h->e_ident[5] != ELFDATA2LSB)          { _setError("not LE ELF");   return false; }
    if (h->e_machine != EM_RISCV)              { _setError("not RISC-V");   return false; }
    if (h->e_type != ET_EXEC)                  { _setError("not exec ELF"); return false; }

    // Compute total VM address range from PT_LOAD segments
    const Elf64Phdr* phdrs = (const Elf64Phdr*)(elf + h->e_phoff);
    uint64_t maxVaddr = 0;
    for (int i = 0; i < h->e_phnum; i++) {
        if (phdrs[i].p_type != PT_LOAD) continue;
        uint64_t end = phdrs[i].p_vaddr + phdrs[i].p_memsz;
        if (end > maxVaddr) maxVaddr = end;
    }
    if (maxVaddr == 0) { _setError("no PT_LOAD"); return false; }

    size_t totalMem = (maxVaddr - CKBVM_LOAD_BASE) + CKBVM_HEAP_SIZE + CKBVM_STACK_SIZE;
    if (!_allocMem(totalMem)) return false;

    for (int i = 0; i < h->e_phnum; i++) {
        const Elf64Phdr* ph = &phdrs[i];
        if (ph->p_type != PT_LOAD) continue;
        if (ph->p_offset + ph->p_filesz > elfLen) { _setError("seg past EOF"); return false; }
        uint64_t off = ph->p_vaddr - CKBVM_LOAD_BASE;
        memcpy(_mem + off, elf + ph->p_offset, ph->p_filesz);
        if (ph->p_memsz > ph->p_filesz)
            memset(_mem + off + ph->p_filesz, 0, ph->p_memsz - ph->p_filesz);
    }

    _heapBase  = maxVaddr;
    _stackBase = CKBVM_LOAD_BASE + totalMem - CKBVM_STACK_SIZE;
    _pc        = h->e_entry;
    _entryPc   = h->e_entry; // save for reset()
    return true;
}

bool CKBVMInterp::loadScript(const uint8_t* elfData, size_t elfLen) {
    _loaded = false;
    memset(_regs, 0, sizeof(_regs));
    _cycles = 0; _lastError[0] = '\0';
    if (!_loadElf(elfData, elfLen)) return false;
    _regs[2] = _stackBase + CKBVM_STACK_SIZE - 16; // sp
    _loaded = true;
    return true;
}

void CKBVMInterp::reset() {
    memset(_regs, 0, sizeof(_regs));
    _cycles = 0; _lastError[0] = '\0';
    _pc = _entryPc; // restore entry point
    if (_loaded && _mem) {
        uint64_t heapOff = _heapBase - CKBVM_LOAD_BASE;
        if (heapOff < _memSize) memset(_mem + heapOff, 0, _memSize - heapOff);
        _regs[2] = _stackBase + CKBVM_STACK_SIZE - 16;
    }
}

void CKBVMInterp::unload() {
    _freeMem(); _loaded = false;
    _pc = _cycles = 0;
    memset(_regs, 0, sizeof(_regs));
}

// ── Partial-load (RFC 0009) ───────────────────────────────────────────────────
int CKBVMInterp::_partialLoad(uint64_t addr, uint64_t lenPtr, uint64_t offset,
                                const uint8_t* data, size_t dataLen) {
    uint64_t bufSize = 0;
    if (!_memRead(lenPtr, &bufSize, 8)) return SYSCALL_ITEM_MISSING;
    uint64_t fullSize = (offset < (uint64_t)dataLen) ? (dataLen - offset) : 0;
    uint64_t realSize = (bufSize < fullSize) ? bufSize : fullSize;
    if (addr != 0 && realSize > 0)
        if (!_memWrite(addr, data + offset, (size_t)realSize)) return SYSCALL_ITEM_MISSING;
    if (!_memWrite(lenPtr, &fullSize, 8)) return SYSCALL_ITEM_MISSING;
    return SYSCALL_SUCCESS;
}

// ── Syscall dispatch ──────────────────────────────────────────────────────────
int CKBVMInterp::_syscall(const CKBVMContext& ctx) {
    uint64_t num = _regs[17]; // a7
    uint64_t a0  = _regs[10];
    uint64_t a1  = _regs[11];
    uint64_t a2  = _regs[12];
    int ret = SYSCALL_SUCCESS;

    switch (num) {
    case CKB_SYSCALL_EXIT: {
        int8_t code = (int8_t)(uint8_t)a0;
        // Use sentinel for exit(0) so execute() can distinguish "exited" from "continue"
        return (code == 0) ? CKBVM_INTERNAL_EXIT0 : (int)code;
    }

    case CKB_SYSCALL_LOAD_TX_HASH:
        ret = _partialLoad(a0, a1, a2, ctx.txHash, ctx.txHashLen); break;

    case CKB_SYSCALL_LOAD_SCRIPT_HASH:
        ret = _partialLoad(a0, a1, a2, ctx.scriptHash, ctx.scriptHashLen); break;

    case CKB_SYSCALL_LOAD_SCRIPT:
        ret = _partialLoad(a0, a1, a2, ctx.script, ctx.scriptLen); break;

    case CKB_SYSCALL_LOAD_WITNESS:
        if (_regs[13] == 0) // index 0 only in light client context
            ret = _partialLoad(a0, a1, a2, ctx.witness, ctx.witnessLen);
        else
            ret = SYSCALL_ITEM_MISSING;
        break;

    case CKB_SYSCALL_LOAD_CELL_DATA:
        if (_regs[13] == 0)
            ret = _partialLoad(a0, a1, a2, ctx.cellData, ctx.cellDataLen);
        else
            ret = SYSCALL_ITEM_MISSING;
        break;

    case CKB_SYSCALL_DEBUG: {
        char buf[128]; size_t i = 0;
        while (i < sizeof(buf)-1) {
            uint8_t c;
            if (!_memRead(a0+i, &c, 1) || c == 0) break;
            buf[i++] = (char)c;
        }
        buf[i] = '\0';
#ifdef HOST_TEST
        printf("[CKB-VM] %s\n", buf);
#endif
        ret = SYSCALL_SUCCESS; break;
    }

    default:
        ret = SYSCALL_ITEM_MISSING; break;
    }

    _regs[10] = (uint64_t)(int64_t)ret;
    return 0; // continue
}

// ── _step() — single instruction ─────────────────────────────────────────────
int CKBVMInterp::_step(const CKBVMContext& ctx) {
    _regs[0] = 0; // x0 always zero

    uint16_t lo = 0;
    if (!_memRead(_pc, &lo, 2)) { _setError("fetch fault"); return CKBVM_EXIT_MEM_FAULT; }

    bool is32 = (lo & 0x3) == 0x3;
    uint32_t ins = lo;
    if (is32) {
        uint16_t hi = 0;
        if (!_memRead(_pc+2, &hi, 2)) { _setError("fetch+2 fault"); return CKBVM_EXIT_MEM_FAULT; }
        ins = (uint32_t)lo | ((uint32_t)hi << 16);
    }

    _cycles++;
    if (_cycles > CKBVM_MAX_CYCLES) return CKBVM_EXIT_CYCLES;

    if (!is32) {
        // ── RV64C compressed 16-bit ──────────────────────────────────────────
        uint16_t c  = (uint16_t)ins;
        uint8_t  op = c & 0x3;
        uint8_t  f3 = (c >> 13) & 0x7;
        // Compressed register: c_rs' = x(8 + field)
        auto cr  = [&](int sh) -> int { return 8 + ((c >> sh) & 0x7); };
        int rd, rs1, rs2; int64_t imm;

        switch (op) {
        // ── Quadrant 0 ───────────────────────────────────────────────────────
        case 0:
            switch (f3) {
            case 0: { // C.ADDI4SPN
                rd = cr(2);
                imm = ((c>>6)&1)<<2 | ((c>>5)&1)<<3 | ((c>>11)&3)<<4 | ((c>>7)&15)<<6;
                if (!imm) { _setError("C.ADDI4SPN imm=0"); return CKBVM_EXIT_INVALID_OP; }
                _regs[rd] = _regs[2] + imm; break;
            }
            case 2: { // C.LW
                rd = cr(2); rs1 = cr(7);
                imm = ((c>>6)&1)<<2 | ((c>>10)&7)<<3 | ((c>>5)&1)<<6;
                uint32_t v = 0;
                if (!_memRead(_regs[rs1]+imm, &v, 4)) return CKBVM_EXIT_MEM_FAULT;
                _regs[rd] = u64(signext(v, 32)); break;
            }
            case 3: { // C.LD
                rd = cr(2); rs1 = cr(7);
                imm = ((c>>10)&7)<<3 | ((c>>5)&3)<<6;
                if (!_memRead(_regs[rs1]+imm, &_regs[rd], 8)) return CKBVM_EXIT_MEM_FAULT;
                break;
            }
            case 6: { // C.SW
                rs1 = cr(7); rs2 = cr(2);
                imm = ((c>>6)&1)<<2 | ((c>>10)&7)<<3 | ((c>>5)&1)<<6;
                uint32_t v = (uint32_t)_regs[rs2];
                if (!_memWrite(_regs[rs1]+imm, &v, 4)) return CKBVM_EXIT_MEM_FAULT;
                break;
            }
            case 7: { // C.SD
                rs1 = cr(7); rs2 = cr(2);
                imm = ((c>>10)&7)<<3 | ((c>>5)&3)<<6;
                if (!_memWrite(_regs[rs1]+imm, &_regs[rs2], 8)) return CKBVM_EXIT_MEM_FAULT;
                break;
            }
            default: _setError("Q0 unk"); return CKBVM_EXIT_INVALID_OP;
            }
            _pc += 2; return 0;

        // ── Quadrant 1 ───────────────────────────────────────────────────────
        case 1:
            switch (f3) {
            case 0: // C.NOP / C.ADDI
                rd = (c>>7)&0x1F;
                imm = signext(((c>>12)&1)<<5 | ((c>>2)&0x1F), 6);
                _regs[rd] += u64(imm); break;
            case 1: // C.ADDIW
                rd = (c>>7)&0x1F;
                if (!rd) { _setError("C.ADDIW rd=0"); return CKBVM_EXIT_INVALID_OP; }
                imm = signext(((c>>12)&1)<<5 | ((c>>2)&0x1F), 6);
                _regs[rd] = u64(signext(u64((int32_t)_regs[rd]+(int32_t)imm), 32)); break;
            case 2: // C.LI
                rd = (c>>7)&0x1F;
                _regs[rd] = u64(signext(((c>>12)&1)<<5 | ((c>>2)&0x1F), 6)); break;
            case 3:
                rd = (c>>7)&0x1F;
                if (rd == 2) { // C.ADDI16SP
                    imm = signext(((c>>12)&1)<<9|((c>>6)&1)<<4|((c>>5)&1)<<6|
                                   ((c>>3)&3)<<7|((c>>2)&1)<<5, 10);
                    if (!imm) { _setError("C.ADDI16SP 0"); return CKBVM_EXIT_INVALID_OP; }
                    _regs[2] += u64(imm);
                } else { // C.LUI
                    _regs[rd] = u64(signext(((c>>12)&1)<<17|((c>>2)&0x1F)<<12, 18));
                }
                break;
            case 4: { // C.ALU
                uint8_t f2 = (c>>10)&3;
                rd = cr(7);
                switch (f2) {
                case 0: _regs[rd] >>= ((c>>12)&1)<<5|((c>>2)&0x1F); break; // SRLI
                case 1: _regs[rd] = u64((int64_t)_regs[rd]>>(((c>>12)&1)<<5|((c>>2)&0x1F))); break; // SRAI
                case 2: _regs[rd] &= u64(signext(((c>>12)&1)<<5|((c>>2)&0x1F),6)); break; // ANDI
                case 3: {
                    rs2 = cr(2);
                    uint8_t f3b = ((c>>12)&1)<<2|((c>>5)&3);
                    switch (f3b) {
                    case 0: _regs[rd] -= _regs[rs2]; break; // SUB
                    case 1: _regs[rd] ^= _regs[rs2]; break; // XOR
                    case 2: _regs[rd] |= _regs[rs2]; break; // OR
                    case 3: _regs[rd] &= _regs[rs2]; break; // AND
                    case 4: _regs[rd]=u64(signext(_regs[rd]-_regs[rs2],32)); break; // SUBW
                    case 5: _regs[rd]=u64(signext(_regs[rd]+_regs[rs2],32)); break; // ADDW
                    default: _setError("Q1 ALU"); return CKBVM_EXIT_INVALID_OP;
                    }
                    break;
                }
                }
                break;
            }
            case 5: { // C.J
                imm = signext(((c>>12)&1)<<11|((c>>11)&1)<<4|((c>>9)&3)<<8|
                               ((c>>8)&1)<<10|((c>>7)&1)<<6|((c>>6)&1)<<7|
                               ((c>>3)&7)<<1|((c>>2)&1)<<5, 12);
                _pc += u64(imm); return 0;
            }
            case 6: { // C.BEQZ
                rs1 = cr(7);
                imm = signext(((c>>12)&1)<<8|((c>>10)&3)<<3|((c>>5)&3)<<6|
                               ((c>>3)&3)<<1|((c>>2)&1)<<5, 9);
                if (!_regs[rs1]) { _pc += u64(imm); return 0; } break;
            }
            case 7: { // C.BNEZ
                rs1 = cr(7);
                imm = signext(((c>>12)&1)<<8|((c>>10)&3)<<3|((c>>5)&3)<<6|
                               ((c>>3)&3)<<1|((c>>2)&1)<<5, 9);
                if (_regs[rs1]) { _pc += u64(imm); return 0; } break;
            }
            }
            _pc += 2; return 0;

        // ── Quadrant 2 ───────────────────────────────────────────────────────
        case 2:
            switch (f3) {
            case 0: // C.SLLI
                rd = (c>>7)&0x1F;
                _regs[rd] <<= ((c>>12)&1)<<5|((c>>2)&0x1F); break;
            case 2: { // C.LWSP
                rd = (c>>7)&0x1F;
                imm = ((c>>12)&1)<<5|((c>>4)&7)<<2|((c>>2)&3)<<6;
                uint32_t v=0;
                if (!_memRead(_regs[2]+imm,&v,4)) return CKBVM_EXIT_MEM_FAULT;
                _regs[rd]=u64(signext(v,32)); break;
            }
            case 3: { // C.LDSP
                rd = (c>>7)&0x1F;
                imm = ((c>>12)&1)<<5|((c>>5)&3)<<3|((c>>2)&3)<<6;
                if (!_memRead(_regs[2]+imm,&_regs[rd],8)) return CKBVM_EXIT_MEM_FAULT;
                break;
            }
            case 4:
                rd  = (c>>7)&0x1F;
                rs2 = (c>>2)&0x1F;
                if ((c>>12)&1) {
                    if (!rs2) { // C.JALR / C.EBREAK
                        if (!rd) { _setError("C.EBREAK"); return CKBVM_EXIT_INVALID_OP; }
                        uint64_t t=_regs[rd]&~1ULL; _regs[1]=_pc+2; _pc=t; return 0;
                    } else { _regs[rd]+=_regs[rs2]; } // C.ADD
                } else {
                    if (!rs2) { _pc=_regs[rd]&~1ULL; return 0; } // C.JR
                    else       { _regs[rd]=_regs[rs2]; }          // C.MV
                }
                break;
            case 6: { // C.SWSP
                imm = ((c>>9)&0xF)<<2|((c>>7)&3)<<6;
                rs2 = (c>>2)&0x1F;
                uint32_t v=(uint32_t)_regs[rs2];
                if (!_memWrite(_regs[2]+imm,&v,4)) return CKBVM_EXIT_MEM_FAULT;
                break;
            }
            case 7: { // C.SDSP
                imm = ((c>>10)&7)<<3|((c>>7)&7)<<6;
                rs2 = (c>>2)&0x1F;
                if (!_memWrite(_regs[2]+imm,&_regs[rs2],8)) return CKBVM_EXIT_MEM_FAULT;
                break;
            }
            default: _setError("Q2 unk"); return CKBVM_EXIT_INVALID_OP;
            }
            _pc += 2; return 0;

        default: _setError("C quadrant"); return CKBVM_EXIT_INVALID_OP;
        } // end compressed
    }

    // ── RV64I + M 32-bit instructions ─────────────────────────────────────────
    uint8_t  opc = ins & 0x7F;
    uint8_t  rd  = (ins >> 7)  & 0x1F;
    uint8_t  f3  = (ins >> 12) & 0x07;
    uint8_t  rs1 = (ins >> 15) & 0x1F;
    uint8_t  rs2 = (ins >> 20) & 0x1F;
    uint8_t  f7  = (ins >> 25) & 0x7F;

    int64_t  I = signext(ins >> 20, 12);
    int64_t  S = signext(((ins>>25)<<5)|(rd), 12);
    int64_t  B = signext(((ins>>31)<<12)|((ins>>7)&1)<<11|((ins>>25)&63)<<5|((ins>>8)&15)<<1, 13);
    int64_t  U = signext(ins & 0xFFFFF000, 32);
    int64_t  J = signext(((ins>>31)<<20)|((ins>>12)&0xFF)<<12|((ins>>20)&1)<<11|((ins>>21)&0x3FF)<<1, 21);

    uint64_t rs1v = _regs[rs1], rs2v = _regs[rs2];
    uint64_t nextpc = _pc + 4;

    switch (opc) {

    // ── LUI / AUIPC ───────────────────────────────────────────────────────────
    case 0x37: _regs[rd] = u64(U); break;                      // LUI
    case 0x17: _regs[rd] = _pc + u64(U); break;               // AUIPC

    // ── JAL / JALR ────────────────────────────────────────────────────────────
    case 0x6F: // JAL
        _regs[rd] = nextpc;
        nextpc = _pc + u64(J);
        break;
    case 0x67: // JALR
        { uint64_t t = (rs1v + u64(I)) & ~1ULL;
          _regs[rd] = nextpc;
          nextpc = t; }
        break;

    // ── Branch ────────────────────────────────────────────────────────────────
    case 0x63:
        { bool taken = false;
          switch (f3) {
          case 0: taken = rs1v == rs2v; break;               // BEQ
          case 1: taken = rs1v != rs2v; break;               // BNE
          case 4: taken = (int64_t)rs1v < (int64_t)rs2v; break; // BLT
          case 5: taken = (int64_t)rs1v >= (int64_t)rs2v; break; // BGE
          case 6: taken = rs1v < rs2v; break;                // BLTU
          case 7: taken = rs1v >= rs2v; break;               // BGEU
          default: _setError("branch f3"); return CKBVM_EXIT_INVALID_OP;
          }
          if (taken) nextpc = _pc + u64(B);
        }
        break;

    // ── Loads ─────────────────────────────────────────────────────────────────
    case 0x03: {
        uint64_t addr = rs1v + u64(I);
        switch (f3) {
        case 0: { uint8_t  v=0; if(!_memRead(addr,&v,1)) return CKBVM_EXIT_MEM_FAULT; _regs[rd]=u64(signext(v,8)); break; }  // LB
        case 1: { uint16_t v=0; if(!_memRead(addr,&v,2)) return CKBVM_EXIT_MEM_FAULT; _regs[rd]=u64(signext(v,16)); break; } // LH
        case 2: { uint32_t v=0; if(!_memRead(addr,&v,4)) return CKBVM_EXIT_MEM_FAULT; _regs[rd]=u64(signext(v,32)); break; } // LW
        case 3: { uint64_t v=0; if(!_memRead(addr,&v,8)) return CKBVM_EXIT_MEM_FAULT; _regs[rd]=v; break; }                  // LD
        case 4: { uint8_t  v=0; if(!_memRead(addr,&v,1)) return CKBVM_EXIT_MEM_FAULT; _regs[rd]=v; break; }                  // LBU
        case 5: { uint16_t v=0; if(!_memRead(addr,&v,2)) return CKBVM_EXIT_MEM_FAULT; _regs[rd]=v; break; }                  // LHU
        case 6: { uint32_t v=0; if(!_memRead(addr,&v,4)) return CKBVM_EXIT_MEM_FAULT; _regs[rd]=v; break; }                  // LWU
        default: _setError("load f3"); return CKBVM_EXIT_INVALID_OP;
        }
        break;
    }

    // ── Stores ────────────────────────────────────────────────────────────────
    case 0x23: {
        uint64_t addr = rs1v + u64(S);
        switch (f3) {
        case 0: { uint8_t  v=(uint8_t)rs2v;  if(!_memWrite(addr,&v,1)) return CKBVM_EXIT_MEM_FAULT; break; } // SB
        case 1: { uint16_t v=(uint16_t)rs2v; if(!_memWrite(addr,&v,2)) return CKBVM_EXIT_MEM_FAULT; break; } // SH
        case 2: { uint32_t v=(uint32_t)rs2v; if(!_memWrite(addr,&v,4)) return CKBVM_EXIT_MEM_FAULT; break; } // SW
        case 3: {                             if(!_memWrite(addr,&rs2v,8)) return CKBVM_EXIT_MEM_FAULT; break; } // SD
        default: _setError("store f3"); return CKBVM_EXIT_INVALID_OP;
        }
        break;
    }

    // ── ALU immediate (RV64I) ─────────────────────────────────────────────────
    case 0x13: {
        uint8_t shamt = (ins >> 20) & 0x3F;
        switch (f3) {
        case 0: _regs[rd] = rs1v + u64(I); break;                                // ADDI
        case 1: _regs[rd] = rs1v << shamt; break;                                // SLLI
        case 2: _regs[rd] = (int64_t)rs1v < (int64_t)I ? 1 : 0; break;          // SLTI
        case 3: _regs[rd] = rs1v < u64(I) ? 1 : 0; break;                       // SLTIU
        case 4: _regs[rd] = rs1v ^ u64(I); break;                                // XORI
        case 5:
            if (f7 >> 1 == 0x10) _regs[rd] = u64((int64_t)rs1v >> shamt);        // SRAI
            else                  _regs[rd] = rs1v >> shamt;                      // SRLI
            break;
        case 6: _regs[rd] = rs1v | u64(I); break;                                // ORI
        case 7: _regs[rd] = rs1v & u64(I); break;                                // ANDI
        default: _setError("alu-imm f3"); return CKBVM_EXIT_INVALID_OP;
        }
        break;
    }

    // ── ALU immediate word (RV64I W-variants) ────────────────────────────────
    case 0x1B: {
        uint8_t shamt = (ins >> 20) & 0x1F;
        int32_t w = (int32_t)rs1v;
        switch (f3) {
        case 0: _regs[rd] = u64(signext(u64((int32_t)(rs1v + u64(I))), 32)); break; // ADDIW
        case 1: _regs[rd] = u64(signext(u64(w << shamt), 32)); break;                // SLLIW
        case 5:
            if (f7 >> 1 == 0x10) _regs[rd] = u64(signext(u64(w >> shamt), 32));     // SRAIW
            else                  _regs[rd] = u64(signext(u64((uint32_t)w >> shamt),32)); // SRLIW
            break;
        default: _setError("aluW-imm"); return CKBVM_EXIT_INVALID_OP;
        }
        break;
    }

    // ── ALU register (RV64I + M extension) ───────────────────────────────────
    case 0x33: {
        switch (f3 | (f7 << 3)) {
        // RV64I base
        case 0|(0x00<<3): _regs[rd] = rs1v + rs2v; break;                                // ADD
        case 0|(0x20<<3): _regs[rd] = rs1v - rs2v; break;                                // SUB
        case 1|(0x00<<3): _regs[rd] = rs1v << (rs2v & 63); break;                        // SLL
        case 2|(0x00<<3): _regs[rd] = (int64_t)rs1v < (int64_t)rs2v ? 1 : 0; break;     // SLT
        case 3|(0x00<<3): _regs[rd] = rs1v < rs2v ? 1 : 0; break;                       // SLTU
        case 4|(0x00<<3): _regs[rd] = rs1v ^ rs2v; break;                                // XOR
        case 5|(0x00<<3): _regs[rd] = rs1v >> (rs2v & 63); break;                        // SRL
        case 5|(0x20<<3): _regs[rd] = u64((int64_t)rs1v >> (rs2v & 63)); break;          // SRA
        case 6|(0x00<<3): _regs[rd] = rs1v | rs2v; break;                                // OR
        case 7|(0x00<<3): _regs[rd] = rs1v & rs2v; break;                                // AND
        // RV64M multiply
        case 0|(0x01<<3): _regs[rd] = rs1v * rs2v; break;                                // MUL
        case 1|(0x01<<3): { // MULH (signed*signed, high 64 bits)
            __int128 r = (__int128)(int64_t)rs1v * (__int128)(int64_t)rs2v;
            _regs[rd] = (uint64_t)(r >> 64); break;
        }
        case 2|(0x01<<3): { // MULHSU
            __int128 r = (__int128)(int64_t)rs1v * (__uint128_t)rs2v;
            _regs[rd] = (uint64_t)(r >> 64); break;
        }
        case 3|(0x01<<3): { // MULHU
            __uint128_t r = (__uint128_t)rs1v * (__uint128_t)rs2v;
            _regs[rd] = (uint64_t)(r >> 64); break;
        }
        case 4|(0x01<<3): // DIV
            if (!rs2v) { _regs[rd] = UINT64_MAX; }
            else        { _regs[rd] = u64((int64_t)rs1v / (int64_t)rs2v); }
            break;
        case 5|(0x01<<3): // DIVU
            _regs[rd] = rs2v ? rs1v / rs2v : UINT64_MAX; break;
        case 6|(0x01<<3): // REM
            if (!rs2v) { _regs[rd] = rs1v; }
            else        { _regs[rd] = u64((int64_t)rs1v % (int64_t)rs2v); }
            break;
        case 7|(0x01<<3): // REMU
            _regs[rd] = rs2v ? rs1v % rs2v : rs1v; break;
        default: _setError("alu-reg f7/f3"); return CKBVM_EXIT_INVALID_OP;
        }
        break;
    }

    // ── ALU register word (RV64 W-variants + MW) ──────────────────────────────
    case 0x3B: {
        uint32_t a = (uint32_t)rs1v, b = (uint32_t)rs2v;
        switch (f3 | (f7 << 3)) {
        case 0|(0x00<<3): _regs[rd]=u64(signext(u64(a+b),32)); break;              // ADDW
        case 0|(0x20<<3): _regs[rd]=u64(signext(u64(a-b),32)); break;              // SUBW
        case 1|(0x00<<3): _regs[rd]=u64(signext(u64(a<<(b&31)),32)); break;        // SLLW
        case 5|(0x00<<3): _regs[rd]=u64(signext(u64(a>>(b&31)),32)); break;        // SRLW
        case 5|(0x20<<3): _regs[rd]=u64(signext(u64((int32_t)a>>(b&31)),32)); break; // SRAW
        case 0|(0x01<<3): _regs[rd]=u64(signext(u64(a*b),32)); break;              // MULW
        case 4|(0x01<<3): // DIVW
            if (!b) _regs[rd]=UINT64_MAX;
            else    _regs[rd]=u64(signext(u64((int32_t)a/(int32_t)b),32));
            break;
        case 5|(0x01<<3): // DIVUW
            _regs[rd]=b ? u64(signext(u64(a/b),32)) : UINT64_MAX; break;
        case 6|(0x01<<3): // REMW
            if (!b) _regs[rd]=u64(signext(u64(a),32));
            else    _regs[rd]=u64(signext(u64((int32_t)a%(int32_t)b),32));
            break;
        case 7|(0x01<<3): // REMUW
            _regs[rd]=b ? u64(signext(u64(a%b),32)) : u64(signext(u64(a),32)); break;
        default: _setError("aluW-reg"); return CKBVM_EXIT_INVALID_OP;
        }
        break;
    }

    // ── SYSTEM (ecall / ebreak) ───────────────────────────────────────────────
    case 0x73:
        if (f3 == 0) {
            if ((ins >> 20) == 0) { // ECALL
                int r = _syscall(ctx);
                if (r != 0) return r; // exit or error — stop execution
                _pc = nextpc; return 0;
            } else { // EBREAK
                _setError("EBREAK"); return CKBVM_EXIT_INVALID_OP;
            }
        }
        _setError("SYSTEM f3"); return CKBVM_EXIT_INVALID_OP;

    // ── FENCE (no-op in single-threaded VM) ───────────────────────────────────
    case 0x0F: break;

    default:
        _setError("unknown opcode");
        return CKBVM_EXIT_INVALID_OP;
    }

    _pc = nextpc;
    return 0;
}

// ── execute() — main run loop ──────────────────────────────────────────────────
int CKBVMInterp::execute(const CKBVMContext& ctx, uint64_t* cyclesUsed) {
    if (!_loaded) { _setError("not loaded"); return CKBVM_EXIT_LOAD_ERR; }

    int result = 0;
    while (true) {
        result = _step(ctx);
        if (result != 0) break;
    }

    if (cyclesUsed) *cyclesUsed = _cycles;

    // Translate internal sentinel back to public exit code
    if (result == CKBVM_INTERNAL_EXIT0) return CKBVM_EXIT_SUCCESS;
    return result;
}
