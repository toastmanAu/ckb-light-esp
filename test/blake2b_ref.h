// Stub — computeScriptHash host tests use pre-computed values
static inline void blake2b_256_stub(const uint8_t*, size_t, uint8_t* out) {
    memset(out, 0, 32);
}
