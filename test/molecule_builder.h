#pragma once
// molecule_builder.h — Host-side Molecule struct builder for ckb-light-esp tests
//
// Wraps CKB-ESP32's ckb_molecule.h with test-friendly C++ helpers.
// Handles all the buffer management boilerplate so tests stay readable.
//
// Used for: native_locks.cpp tests, tx signing test vectors, script hash checks.
//
// Include path: add -I/home/phill/workspace/CKB-ESP32/src to g++ flags.

#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <stdio.h>

// Pull in the portable Molecule helpers from CKB-ESP32
#if __has_include("ckb_molecule.h")
#  include "ckb_molecule.h"
#elif __has_include("../../CKB-ESP32/src/ckb_molecule.h")
#  include "../../CKB-ESP32/src/ckb_molecule.h"
#else
#  error "Cannot find ckb_molecule.h — add -I/home/phill/workspace/CKB-ESP32/src to compiler flags"
#endif

// ── MolBuf: stack-allocated buffer for building Molecule structs ──────────────
//
// Usage:
//   MolBuf<512> buf;
//   buf.writeScript("0x9bd7...", "type", "0xdeadbeef");
//   const uint8_t* data = buf.data();
//   size_t len = buf.len();

template<size_t CAP>
struct MolBuf {
    uint8_t _storage[CAP];
    CKBBuf  _b;

    MolBuf() { ckb_buf_init(&_b, _storage, CAP); }

    void reset() { _b.len = 0; }

    const uint8_t* data() const { return _storage; }
    size_t         len()  const { return _b.len; }
    bool           ok()   const { return _b.len > 0 && _b.len <= CAP; }

    // Write a Script table: code_hash + hash_type + args
    // hash_type: "data" | "type" | "data1" | "data2"
    size_t writeScript(const char* codeHash, const char* hashType, const char* args) {
        return mol_write_script(&_b, codeHash, hashType, args);
    }

    // Write a CellOutput (capacity + lock script, no type script for now)
    // Note: mol_write_celloutput in CKB-ESP32 doesn't support type script yet.
    size_t writeCellOutput(uint64_t capacity,
                           const char* lockCodeHash, const char* lockHashType,
                           const char* lockArgs) {
        return mol_write_celloutput(&_b, capacity,
                                    lockCodeHash, lockHashType, lockArgs);
    }

    // Write a WitnessArgs with 65-byte lock placeholder (for signing)
    size_t writeWitnessPlaceholder() {
        return mol_write_witness_placeholder(&_b);
    }

    // Write raw bytes as Molecule fixvec<byte>
    void writeBytes(const uint8_t* data, uint32_t len) {
        mol_write_bytes(&_b, data, len);
    }

    // Hex-dump the buffer (for test debugging)
    void print(const char* label = nullptr) const {
        if (label) printf("%s (%zu bytes): ", label, _b.len);
        printf("0x");
        for (size_t i = 0; i < _b.len; i++) printf("%02x", _storage[i]);
        printf("\n");
    }
};

// ── Free-standing helpers ─────────────────────────────────────────────────────

// Build a Script and return its 32-byte Blake2b-256 hash.
// This is the value used in GCS filter matching.
// Requires blake2b_real.h to be included before this header.
#ifdef CKB_BLAKE2B_OUTBYTES
static inline void molScriptHash(const char* codeHash, const char* hashType,
                                  const char* args, uint8_t out[32]) {
    MolBuf<256> buf;
    buf.writeScript(codeHash, hashType, args);
    ckb_blake2b_hash(buf.data(), buf.len(), out);
}

// Convenience: script hash → hex string (caller provides 67+ byte buf)
static inline void molScriptHashHex(const char* codeHash, const char* hashType,
                                     const char* args, char* hexOut, size_t hexSize) {
    uint8_t hash[32];
    molScriptHash(codeHash, hashType, args, hash);
    if (hexSize < 67) return;
    hexOut[0] = '0'; hexOut[1] = 'x';
    for (int i = 0; i < 32; i++)
        snprintf(hexOut + 2 + i*2, 3, "%02x", hash[i]);
}
#endif // CKB_BLAKE2B_OUTBYTES

// Build a minimal OutPoint struct (36 bytes: tx_hash + index)
static inline void molOutPoint(const char* txHash, uint32_t index, uint8_t out[36]) {
    uint8_t storage[36];
    CKBBuf b;
    ckb_buf_init(&b, storage, 36);
    mol_write_outpoint(&b, txHash, index);
    memcpy(out, storage, 36);
}

// Build a CellInput (44 bytes: since + out_point)
static inline void molCellInput(const char* txHash, uint32_t index,
                                 uint64_t since, uint8_t out[44]) {
    uint8_t storage[44];
    CKBBuf b;
    ckb_buf_init(&b, storage, 44);
    mol_write_cellinput(&b, txHash, index, since);
    memcpy(out, storage, 44);
}
