/**
 * ckb_address.h — CKB address → lock script parsing (RFC-0021, full format)
 * =========================================================================
 * Pure C, no dynamic allocation. Safe for ESP32/FreeRTOS.
 *
 * Decodes a ckb1q... (bech32m full-format) address into its lock script
 * components so they can be used in CKB RPC indexer queries.
 *
 * Shared by:
 *   - WyAuth CKBPaymentProvider (C++ Arduino)
 *   - wyEspAgentPay wy_auth_agentpay (ESP-IDF C)
 *   - ckb-light-esp protocol layer (future: local cell verification)
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CKB_ADDR_MAX_ARGS  64   /* bytes — standard lock args are 20 bytes */

typedef struct {
    uint8_t code_hash[32];
    uint8_t hash_type;          /* 0=data, 1=type, 2=data1 */
    uint8_t args[CKB_ADDR_MAX_ARGS];
    size_t  args_len;
} ckb_lock_script_t;

/**
 * @brief Parse a CKB full-format address (RFC-0021 bech32m) into a lock script.
 *
 * @param addr    Null-terminated CKB address string (e.g. "ckb1q...")
 * @param out     Populated on success
 * @return true on success, false if address is malformed or unsupported format
 */
static inline bool ckb_address_parse(const char *addr, ckb_lock_script_t *out)
{
    static const char CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    if (!addr || !out) return false;

    size_t alen = strlen(addr);

    /* Find HRP separator '1' — last occurrence */
    int sep = -1;
    for (int i = (int)alen - 1; i >= 0; i--) {
        if (addr[i] == '1') { sep = i; break; }
    }
    if (sep < 2) return false;

    /* Decode 5-bit data groups, strip 6-char bech32m checksum */
    const char *data = addr + sep + 1;
    int data_len = (int)strlen(data) - 6;
    if (data_len < 1) return false;

    uint8_t d5[128];
    for (int i = 0; i < data_len; i++) {
        char c = data[i];
        /* tolower inline */
        if (c >= 'A' && c <= 'Z') c += 32;
        const char *p = strchr(CHARSET, c);
        if (!p) return false;
        d5[i] = (uint8_t)(p - CHARSET);
    }

    /* Convert 5-bit groups → 8-bit bytes */
    uint8_t bytes[96];
    size_t  blen = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (int i = 0; i < data_len; i++) {
        acc = (acc << 5) | d5[i];
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (blen >= sizeof(bytes)) return false;
            bytes[blen++] = (acc >> bits) & 0xFF;
        }
    }

    /* Full format: bytes[0]=0x00, [1..32]=code_hash, [33]=hash_type, rest=args */
    if (blen < 34 || bytes[0] != 0x00) return false;

    memcpy(out->code_hash, bytes + 1, 32);
    out->hash_type = bytes[33];
    out->args_len  = blen - 34;
    if (out->args_len > CKB_ADDR_MAX_ARGS) out->args_len = CKB_ADDR_MAX_ARGS;
    if (out->args_len > 0) memcpy(out->args, bytes + 34, out->args_len);
    return true;
}

/**
 * @brief Write the lock script as a CKB RPC JSON fragment into buf.
 *
 * Produces:
 *   {"code_hash":"0x...","hash_type":"type","args":"0x..."}
 *
 * @param ls      Parsed lock script
 * @param buf     Output buffer
 * @param buf_len Buffer size
 * @return Number of bytes written (excluding null), or -1 if buf too small
 */
static inline int ckb_lock_script_to_json(const ckb_lock_script_t *ls,
                                           char *buf, size_t buf_len)
{
    if (!ls || !buf || buf_len < 4) return -1;

    const char *ht = (ls->hash_type == 0) ? "data"
                   : (ls->hash_type == 2) ? "data1"
                   : "type";

    /* code_hash hex */
    char ch[67] = "0x";
    for (int i = 0; i < 32; i++) {
        char b[3]; snprintf(b, 3, "%02x", ls->code_hash[i]);
        ch[2 + i*2]   = b[0];
        ch[2 + i*2+1] = b[1];
    }
    ch[66] = '\0';

    /* args hex */
    char ah[CKB_ADDR_MAX_ARGS * 2 + 3] = "0x";
    for (size_t i = 0; i < ls->args_len; i++) {
        snprintf(ah + 2 + i*2, 3, "%02x", ls->args[i]);
    }
    ah[2 + ls->args_len * 2] = '\0';

    return snprintf(buf, buf_len,
                    "{\"code_hash\":\"%s\",\"hash_type\":\"%s\",\"args\":\"%s\"}",
                    ch, ht, ah);
}

#ifdef __cplusplus
}
#endif
