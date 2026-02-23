/*
 * ckb_wifi.h — WiFi co-processor driver for ESP32-P4
 *
 * Communicates with an ESP32/C3 running wifi_coprocessor firmware
 * over SPI. Presents a simple BSD-socket-like API to the rest of
 * the light client code.
 *
 * SPI Wiring:
 *   P4 pin    → co-proc pin   Signal
 *   ─────────────────────────────────
 *   GPIO 15   → GPIO 11       MOSI
 *   GPIO 16   → GPIO 13       MISO
 *   GPIO 17   → GPIO 12       CLK
 *   GPIO 18   → GPIO 10       CS
 *   GPIO 19   ← GPIO 2        DATA_READY (interrupt input)
 *   GND       → GND
 *   3.3V      → 3.3V
 *
 * The DATA_READY line goes high when the co-proc has a response ready.
 * We can either poll it or wire it to a GPIO interrupt.
 */

#ifndef CKB_WIFI_H
#define CKB_WIFI_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Max connections */
#define CKB_WIFI_MAX_CONNS  4

/* Status codes */
#define CKB_WIFI_OK         0
#define CKB_WIFI_ERR_INIT  -1
#define CKB_WIFI_ERR_CONN  -2
#define CKB_WIFI_ERR_SEND  -3
#define CKB_WIFI_ERR_RECV  -4
#define CKB_WIFI_ERR_TIMEOUT -5

/**
 * Initialise the SPI master and co-processor interface.
 * Must be called once at startup before any other ckb_wifi_* calls.
 * Returns CKB_WIFI_OK or negative error.
 */
int ckb_wifi_init(void);

/**
 * Connect to a WiFi network.
 * Blocks until connected or timeout_ms elapses.
 * ip_out: 4-byte buffer for assigned IP (optional, pass NULL to ignore).
 * Returns CKB_WIFI_OK or negative error.
 */
int ckb_wifi_connect(const char *ssid, const char *password,
                     uint32_t timeout_ms, uint8_t ip_out[4]);

/**
 * Check if WiFi is connected.
 * Returns 1 if connected, 0 if not.
 */
int ckb_wifi_is_connected(void);

/**
 * Open a TCP connection.
 * ip: 4-byte big-endian IPv4 address.
 * port: host byte order.
 * Returns connection ID (0–3) on success, negative on error.
 */
int ckb_tcp_connect(const uint8_t ip[4], uint16_t port);

/**
 * Send data on an open TCP connection.
 * Returns bytes sent, or negative on error.
 */
int ckb_tcp_send(int conn_id, const uint8_t *data, uint16_t len);

/**
 * Receive data from an open TCP connection.
 * Non-blocking: returns 0 if no data available, negative on error.
 * Blocks up to timeout_ms milliseconds.
 */
int ckb_tcp_recv(int conn_id, uint8_t *buf, uint16_t buf_len, uint32_t timeout_ms);

/**
 * Close a TCP connection.
 */
int ckb_tcp_close(int conn_id);

/* ── Wiring reference (printed at init if log level >= INFO) ── */
void ckb_wifi_print_wiring(void);

#ifdef __cplusplus
}
#endif

#endif /* CKB_WIFI_H */
