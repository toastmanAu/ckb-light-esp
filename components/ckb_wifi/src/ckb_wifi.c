/*
 * ckb_wifi.c — WiFi co-processor SPI master driver (ESP32-P4 side)
 *
 * Uses ESP-IDF SPI master driver. Communicates with the ESP32/C3
 * running wifi_coprocessor firmware.
 */

#include "ckb_wifi.h"
#include "driver/spi_master.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>

static const char *TAG = "ckb-wifi";

/* ── SPI pin config (P4 side) ── */
#define SPI_HOST        SPI2_HOST
#define PIN_MOSI        15
#define PIN_MISO        16
#define PIN_CLK         17
#define PIN_CS          18
#define PIN_DATA_READY  19   /* input: co-proc signals data ready */

/* ── Protocol (mirrors wifi_coprocessor/main/main.c) ── */
#define MAGIC           0xCB
#define TRANSFER_SIZE   256
#define PAYLOAD_MAX     (TRANSFER_SIZE - 4)

#define CMD_WIFI_CONNECT  0x01
#define CMD_WIFI_STATUS   0x02
#define CMD_TCP_CONNECT   0x03
#define CMD_TCP_SEND      0x04
#define CMD_TCP_CLOSE     0x05
#define CMD_TCP_POLL      0x06

#define RSP_WIFI_CONNECT_OK 0x81
#define RSP_WIFI_STATUS     0x82
#define RSP_TCP_CONNECT_OK  0x83
#define RSP_TCP_SEND_OK     0x84
#define RSP_TCP_CLOSE_OK    0x85
#define RSP_TCP_DATA        0x86
#define RSP_ERROR           0xE0
#define RSP_IDLE            0x00

/* ── Driver state ── */
static spi_device_handle_t spi_dev;
static uint8_t initialized = 0;

/* Receive buffer per connection (ring buffer, simple) */
#define RX_BUF_SIZE 4096

typedef struct {
    uint8_t  buf[RX_BUF_SIZE];
    uint16_t head;
    uint16_t tail;
    uint8_t  in_use;
} rx_ring_t;

static rx_ring_t rx_rings[CKB_WIFI_MAX_CONNS];

/* ── Ring buffer helpers ── */
static void ring_reset(rx_ring_t *r) { r->head = r->tail = 0; }

static uint16_t ring_used(const rx_ring_t *r) {
    return (r->tail >= r->head) ? (r->tail - r->head)
                                 : (RX_BUF_SIZE - r->head + r->tail);
}

static void ring_push(rx_ring_t *r, const uint8_t *data, uint16_t len) {
    for (uint16_t i = 0; i < len; i++) {
        r->buf[r->tail] = data[i];
        r->tail = (r->tail + 1) % RX_BUF_SIZE;
        /* Drop oldest if full */
        if (r->tail == r->head)
            r->head = (r->head + 1) % RX_BUF_SIZE;
    }
}

static uint16_t ring_pop(rx_ring_t *r, uint8_t *out, uint16_t maxlen) {
    uint16_t n = 0;
    while (n < maxlen && r->head != r->tail) {
        out[n++] = r->buf[r->head];
        r->head = (r->head + 1) % RX_BUF_SIZE;
    }
    return n;
}

/* ── SPI transfer ── */

static int spi_transfer(const uint8_t *tx, uint8_t *rx) {
    spi_transaction_t t = {0};
    t.length    = TRANSFER_SIZE * 8;
    t.tx_buffer = tx;
    t.rx_buffer = rx;
    esp_err_t err = spi_device_transmit(spi_dev, &t);
    return (err == ESP_OK) ? 0 : -1;
}

/* Send a command and receive whatever the co-proc has queued */
static int do_cmd(const uint8_t *tx_frame, uint8_t *rx_frame) {
    return spi_transfer(tx_frame, rx_frame);
}

static void build_cmd(uint8_t *frame, uint8_t cmd, const uint8_t *payload, uint16_t plen) {
    memset(frame, 0, TRANSFER_SIZE);
    frame[0] = MAGIC;
    frame[1] = cmd;
    frame[2] = (uint8_t)(plen & 0xFF);
    frame[3] = (uint8_t)(plen >> 8);
    if (payload && plen) memcpy(frame + 4, payload, plen);
}

/* Drain any incoming data from co-proc into rx rings, return response type */
static uint8_t send_and_drain(uint8_t *tx_frame, uint8_t *rx_buf) {
    if (do_cmd(tx_frame, rx_buf) < 0) return RSP_ERROR;
    if (rx_buf[0] != MAGIC) return RSP_IDLE;

    uint8_t  rsp_type = rx_buf[1];
    uint16_t plen     = (uint16_t)rx_buf[2] | ((uint16_t)rx_buf[3] << 8);
    uint8_t  *payload = rx_buf + 4;

    if (rsp_type == RSP_TCP_DATA && plen >= 1) {
        uint8_t conn_id = payload[0];
        if (conn_id < CKB_WIFI_MAX_CONNS && rx_rings[conn_id].in_use) {
            ring_push(&rx_rings[conn_id], payload + 1, plen - 1);
        }
    }
    return rsp_type;
}

/* Poll co-proc for any unsolicited data (TCP receives) */
static void drain_unsolicited(void) {
    static WORD_ALIGNED_ATTR uint8_t idle_tx[TRANSFER_SIZE];
    static WORD_ALIGNED_ATTR uint8_t idle_rx[TRANSFER_SIZE];
    if (!gpio_get_level(PIN_DATA_READY)) return;

    memset(idle_tx, 0, TRANSFER_SIZE); /* send IDLE command (magic=0x00) */
    send_and_drain(idle_tx, idle_rx);
}

/* ── Public API ── */

int ckb_wifi_init(void) {
    if (initialized) return CKB_WIFI_OK;

    /* DATA_READY input */
    gpio_config_t io = {
        .pin_bit_mask = (1ULL << PIN_DATA_READY),
        .mode         = GPIO_MODE_INPUT,
        .pull_up_en   = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_ENABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&io);

    /* SPI master */
    spi_bus_config_t buscfg = {
        .mosi_io_num     = PIN_MOSI,
        .miso_io_num     = PIN_MISO,
        .sclk_io_num     = PIN_CLK,
        .quadwp_io_num   = -1,
        .quadhd_io_num   = -1,
        .max_transfer_sz = TRANSFER_SIZE,
    };
    spi_device_interface_config_t devcfg = {
        .clock_speed_hz = 10 * 1000 * 1000, /* 10 MHz — safe for jumper wires */
        .mode           = 0,
        .spics_io_num   = PIN_CS,
        .queue_size     = 1,
        .flags          = 0,
    };

    esp_err_t err = spi_bus_initialize(SPI_HOST, &buscfg, SPI_DMA_CH_AUTO);
    if (err != ESP_OK) return CKB_WIFI_ERR_INIT;

    err = spi_bus_add_device(SPI_HOST, &devcfg, &spi_dev);
    if (err != ESP_OK) return CKB_WIFI_ERR_INIT;

    memset(rx_rings, 0, sizeof(rx_rings));
    initialized = 1;

    ESP_LOGI(TAG, "WiFi co-processor driver initialised");
    ckb_wifi_print_wiring();
    return CKB_WIFI_OK;
}

int ckb_wifi_connect(const char *ssid, const char *password,
                     uint32_t timeout_ms, uint8_t ip_out[4]) {
    if (!initialized) return CKB_WIFI_ERR_INIT;

    uint8_t ssid_len = (uint8_t)strlen(ssid);
    uint8_t pass_len = (uint8_t)strlen(password);

    uint8_t payload[2 + 32 + 64];
    uint16_t plen = 0;
    payload[plen++] = ssid_len;
    memcpy(payload + plen, ssid, ssid_len); plen += ssid_len;
    payload[plen++] = pass_len;
    memcpy(payload + plen, password, pass_len); plen += pass_len;

    static WORD_ALIGNED_ATTR uint8_t tx[TRANSFER_SIZE];
    static WORD_ALIGNED_ATTR uint8_t rx[TRANSFER_SIZE];
    build_cmd(tx, CMD_WIFI_CONNECT, payload, plen);

    /* Send connect command */
    if (do_cmd(tx, rx) < 0) return CKB_WIFI_ERR_INIT;

    /* Poll for WIFI_CONNECT_OK */
    uint32_t elapsed = 0;
    const uint32_t poll_ms = 200;
    while (elapsed < timeout_ms) {
        vTaskDelay(pdMS_TO_TICKS(poll_ms));
        elapsed += poll_ms;

        if (!gpio_get_level(PIN_DATA_READY)) continue;

        static WORD_ALIGNED_ATTR uint8_t poll_tx[TRANSFER_SIZE];
        memset(poll_tx, 0, TRANSFER_SIZE);
        uint8_t rsp = send_and_drain(poll_tx, rx);

        if (rsp == RSP_WIFI_CONNECT_OK) {
            if (ip_out && rx[3] >= 4) memcpy(ip_out, rx + 4, 4);
            ESP_LOGI(TAG, "WiFi connected");
            return CKB_WIFI_OK;
        }
        if (rsp == RSP_ERROR) return CKB_WIFI_ERR_CONN;
    }
    return CKB_WIFI_ERR_TIMEOUT;
}

int ckb_wifi_is_connected(void) {
    if (!initialized) return 0;
    static WORD_ALIGNED_ATTR uint8_t tx[TRANSFER_SIZE];
    static WORD_ALIGNED_ATTR uint8_t rx[TRANSFER_SIZE];
    build_cmd(tx, CMD_WIFI_STATUS, NULL, 0);
    if (do_cmd(tx, rx) < 0) return 0;

    /* Wait briefly for response */
    vTaskDelay(pdMS_TO_TICKS(50));
    if (gpio_get_level(PIN_DATA_READY)) {
        memset(tx, 0, TRANSFER_SIZE);
        send_and_drain(tx, rx);
        if (rx[1] == RSP_WIFI_STATUS && rx[4] >= 1)
            return rx[4] == 1;
    }
    return 0;
}

int ckb_tcp_connect(const uint8_t ip[4], uint16_t port) {
    if (!initialized) return CKB_WIFI_ERR_INIT;

    uint8_t payload[6];
    payload[0] = ip[0]; payload[1] = ip[1];
    payload[2] = ip[2]; payload[3] = ip[3];
    payload[4] = (uint8_t)(port >> 8);
    payload[5] = (uint8_t)(port & 0xFF);

    static WORD_ALIGNED_ATTR uint8_t tx[TRANSFER_SIZE];
    static WORD_ALIGNED_ATTR uint8_t rx[TRANSFER_SIZE];
    build_cmd(tx, CMD_TCP_CONNECT, payload, 6);
    if (do_cmd(tx, rx) < 0) return CKB_WIFI_ERR_CONN;

    /* Wait for TCP_CONNECT_OK */
    uint32_t elapsed = 0;
    while (elapsed < 10000) {
        vTaskDelay(pdMS_TO_TICKS(100));
        elapsed += 100;
        if (!gpio_get_level(PIN_DATA_READY)) continue;
        memset(tx, 0, TRANSFER_SIZE);
        uint8_t rsp = send_and_drain(tx, rx);
        if (rsp == RSP_TCP_CONNECT_OK) {
            uint8_t conn_id = rx[4];
            if (conn_id < CKB_WIFI_MAX_CONNS) {
                rx_rings[conn_id].in_use = 1;
                ring_reset(&rx_rings[conn_id]);
                ESP_LOGI(TAG, "TCP connected, conn_id=%d", conn_id);
                return conn_id;
            }
        }
        if (rsp == RSP_ERROR) return CKB_WIFI_ERR_CONN;
    }
    return CKB_WIFI_ERR_TIMEOUT;
}

int ckb_tcp_send(int conn_id, const uint8_t *data, uint16_t len) {
    if (!initialized || conn_id < 0 || conn_id >= CKB_WIFI_MAX_CONNS) return CKB_WIFI_ERR_CONN;

    /* Send in PAYLOAD_MAX - 1 chunks (1 byte for conn_id) */
    const uint16_t chunk_max = PAYLOAD_MAX - 1;
    int total_sent = 0;

    while (len > 0) {
        uint16_t chunk = (len < chunk_max) ? len : chunk_max;
        uint8_t payload[PAYLOAD_MAX];
        payload[0] = (uint8_t)conn_id;
        memcpy(payload + 1, data, chunk);

        static WORD_ALIGNED_ATTR uint8_t tx[TRANSFER_SIZE];
        static WORD_ALIGNED_ATTR uint8_t rx[TRANSFER_SIZE];
        build_cmd(tx, CMD_TCP_SEND, payload, chunk + 1);
        if (do_cmd(tx, rx) < 0) return CKB_WIFI_ERR_SEND;

        /* Quick drain for send ack (don't block hard) */
        vTaskDelay(pdMS_TO_TICKS(10));
        drain_unsolicited();

        data       += chunk;
        len        -= chunk;
        total_sent += chunk;
    }
    return total_sent;
}

int ckb_tcp_recv(int conn_id, uint8_t *buf, uint16_t buf_len, uint32_t timeout_ms) {
    if (!initialized || conn_id < 0 || conn_id >= CKB_WIFI_MAX_CONNS) return CKB_WIFI_ERR_CONN;

    uint32_t elapsed = 0;
    const uint32_t poll_ms = 10;

    while (elapsed < timeout_ms) {
        drain_unsolicited();

        uint16_t avail = ring_used(&rx_rings[conn_id]);
        if (avail > 0) {
            uint16_t n = ring_pop(&rx_rings[conn_id], buf, buf_len);
            return (int)n;
        }
        vTaskDelay(pdMS_TO_TICKS(poll_ms));
        elapsed += poll_ms;
    }
    return 0; /* timeout, no data */
}

int ckb_tcp_close(int conn_id) {
    if (!initialized || conn_id < 0 || conn_id >= CKB_WIFI_MAX_CONNS) return CKB_WIFI_ERR_CONN;

    uint8_t payload[1] = {(uint8_t)conn_id};
    static WORD_ALIGNED_ATTR uint8_t tx[TRANSFER_SIZE];
    static WORD_ALIGNED_ATTR uint8_t rx[TRANSFER_SIZE];
    build_cmd(tx, CMD_TCP_CLOSE, payload, 1);
    do_cmd(tx, rx);

    rx_rings[conn_id].in_use = 0;
    ring_reset(&rx_rings[conn_id]);
    return CKB_WIFI_OK;
}

void ckb_wifi_print_wiring(void) {
    ESP_LOGI(TAG, "=== WiFi co-processor wiring ===");
    ESP_LOGI(TAG, "ESP32-P4 GPIO%d (MOSI)  → co-proc GPIO11", PIN_MOSI);
    ESP_LOGI(TAG, "ESP32-P4 GPIO%d (MISO)  ← co-proc GPIO13", PIN_MISO);
    ESP_LOGI(TAG, "ESP32-P4 GPIO%d (CLK)   → co-proc GPIO12", PIN_CLK);
    ESP_LOGI(TAG, "ESP32-P4 GPIO%d (CS)    → co-proc GPIO10", PIN_CS);
    ESP_LOGI(TAG, "ESP32-P4 GPIO%d (DR IN) ← co-proc GPIO2 (DATA_READY)", PIN_DATA_READY);
    ESP_LOGI(TAG, "GND ↔ GND,  3.3V ↔ 3.3V");
    ESP_LOGI(TAG, "================================");
}
