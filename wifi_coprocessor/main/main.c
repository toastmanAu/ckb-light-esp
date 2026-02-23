/*
 * CKB Light Client — WiFi Co-Processor Firmware
 *
 * Runs on an ESP32 or ESP32-C3. Acts as a SPI slave WiFi bridge
 * for the ESP32-P4 (which has no integrated WiFi).
 *
 * Protocol: simple TLV framing over SPI
 * ─────────────────────────────────────
 * The ESP32-P4 (master) sends commands; we (slave) respond.
 * All SPI transactions are fixed-size TRANSFER_SIZE bytes to keep
 * the SPI slave driver simple. Unused bytes are zero-padded.
 *
 * Frame format (both directions):
 *   [1] magic   = 0xCB
 *   [1] type    (cmd/resp type)
 *   [2] length  (LE, payload length, max PAYLOAD_MAX)
 *   [N] payload
 *   ... zero padding to TRANSFER_SIZE
 *
 * Command types (P4 → ESP32):
 *   0x01  WIFI_CONNECT    payload: ssid_len(1) + ssid + pass_len(1) + pass
 *   0x02  WIFI_STATUS     payload: none
 *   0x03  TCP_CONNECT     payload: ip(4, big-endian) + port(2, BE)
 *   0x04  TCP_SEND        payload: conn_id(1) + data
 *   0x05  TCP_CLOSE       payload: conn_id(1)
 *   0x06  TCP_POLL        payload: conn_id(1)
 *   0x07  WIFI_SCAN       payload: none
 *
 * Response types (ESP32 → P4):
 *   0x81  WIFI_CONNECT_OK  payload: ip(4)
 *   0x82  WIFI_STATUS_RSP  payload: status(1) + ip(4)   status: 0=disconnected 1=connected
 *   0x83  TCP_CONNECT_OK   payload: conn_id(1)
 *   0x84  TCP_SEND_OK      payload: conn_id(1) + bytes_sent(2 LE)
 *   0x85  TCP_CLOSE_OK     payload: conn_id(1)
 *   0x86  TCP_DATA         payload: conn_id(1) + data
 *   0x87  WIFI_SCAN_RSP    payload: count(1) + [ssid_len(1)+ssid+rssi(1)] * count
 *   0xE0  ERROR            payload: cmd_type(1) + error_code(1)
 *   0x00  IDLE             payload: none (nothing to report)
 *
 * SPI Wiring (6 wires):
 *   ESP32-P4 (master)          ESP32/C3 (slave)
 *   ─────────────────────────────────────────────
 *   GPIO XX  (MOSI)      →     GPIO 11  (MOSI)
 *   GPIO XX  (MISO)      ←     GPIO 13  (MISO)
 *   GPIO XX  (CLK)       →     GPIO 12  (CLK)
 *   GPIO XX  (CS)        →     GPIO 10  (CS)
 *   GPIO XX  (HANDSHAKE) ←     GPIO 2   (DATA_READY — slave pulls high when response ready)
 *   GND                  ─     GND
 *   3.3V                 ─     3.3V (or power from P4 if it can supply enough current)
 *
 * The HANDSHAKE/DATA_READY line lets the P4 know when to initiate
 * a SPI read — avoids the P4 having to poll constantly.
 */

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "driver/spi_slave.h"
#include "driver/gpio.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"

static const char *TAG = "ckb-wificp";

/* ── SPI pin config ── */
#define SPI_HOST        SPI2_HOST
#define PIN_MOSI        11
#define PIN_MISO        13
#define PIN_CLK         12
#define PIN_CS          10
#define PIN_DATA_READY  2    /* output: pulled high when slave has data for master */

/* ── Protocol ── */
#define MAGIC           0xCB
#define TRANSFER_SIZE   256
#define PAYLOAD_MAX     (TRANSFER_SIZE - 4)

/* Command types */
#define CMD_WIFI_CONNECT  0x01
#define CMD_WIFI_STATUS   0x02
#define CMD_TCP_CONNECT   0x03
#define CMD_TCP_SEND      0x04
#define CMD_TCP_CLOSE     0x05
#define CMD_TCP_POLL      0x06
#define CMD_WIFI_SCAN     0x07

/* Response types */
#define RSP_WIFI_CONNECT_OK 0x81
#define RSP_WIFI_STATUS     0x82
#define RSP_TCP_CONNECT_OK  0x83
#define RSP_TCP_SEND_OK     0x84
#define RSP_TCP_CLOSE_OK    0x85
#define RSP_TCP_DATA        0x86
#define RSP_WIFI_SCAN       0x87
#define RSP_ERROR           0xE0
#define RSP_IDLE            0x00

/* Error codes */
#define ERR_WIFI_FAIL       0x01
#define ERR_TCP_FAIL        0x02
#define ERR_NO_CONN         0x03
#define ERR_INVALID         0x04

/* ── TCP connection pool ── */
#define MAX_TCP_CONNS  4

typedef struct {
    int     fd;
    uint8_t in_use;
} tcp_conn_t;

static tcp_conn_t tcp_conns[MAX_TCP_CONNS];

/* ── Outbound response queue ── */
/* Responses are queued and served on the next SPI transfer */
#define RSP_QUEUE_SIZE  8

typedef struct {
    uint8_t buf[TRANSFER_SIZE];
} rsp_frame_t;

static QueueHandle_t rsp_queue;

/* ── WiFi state ── */
static volatile uint8_t wifi_connected = 0;
static uint8_t          wifi_ip[4]     = {0};

/* ── SPI DMA buffers (must be DMA-capable) ── */
static WORD_ALIGNED_ATTR uint8_t spi_rx_buf[TRANSFER_SIZE];
static WORD_ALIGNED_ATTR uint8_t spi_tx_buf[TRANSFER_SIZE];

/* ── Helpers ── */

static void build_rsp(uint8_t *frame, uint8_t type, const uint8_t *payload, uint16_t plen) {
    memset(frame, 0, TRANSFER_SIZE);
    frame[0] = MAGIC;
    frame[1] = type;
    frame[2] = (uint8_t)(plen & 0xFF);
    frame[3] = (uint8_t)(plen >> 8);
    if (payload && plen) memcpy(frame + 4, payload, plen);
}

static void queue_rsp(uint8_t type, const uint8_t *payload, uint16_t plen) {
    rsp_frame_t f;
    build_rsp(f.buf, type, payload, plen);
    if (xQueueSend(rsp_queue, &f, pdMS_TO_TICKS(100)) != pdTRUE)
        ESP_LOGW(TAG, "rsp_queue full, dropping response type 0x%02x", type);
}

static void queue_error(uint8_t cmd, uint8_t code) {
    uint8_t p[2] = {cmd, code};
    queue_rsp(RSP_ERROR, p, 2);
}

static void signal_data_ready(int level) {
    gpio_set_level(PIN_DATA_READY, level);
}

/* ── WiFi event handler ── */
static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                                int32_t event_id, void *event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        wifi_connected = 0;
        memset(wifi_ip, 0, 4);
        ESP_LOGI(TAG, "WiFi disconnected");
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *evt = (ip_event_got_ip_t *)event_data;
        wifi_connected = 1;
        wifi_ip[0] = (evt->ip_info.ip.addr >> 0)  & 0xFF;
        wifi_ip[1] = (evt->ip_info.ip.addr >> 8)  & 0xFF;
        wifi_ip[2] = (evt->ip_info.ip.addr >> 16) & 0xFF;
        wifi_ip[3] = (evt->ip_info.ip.addr >> 24) & 0xFF;
        ESP_LOGI(TAG, "WiFi connected, IP: %d.%d.%d.%d",
                 wifi_ip[0], wifi_ip[1], wifi_ip[2], wifi_ip[3]);

        uint8_t p[4];
        memcpy(p, wifi_ip, 4);
        queue_rsp(RSP_WIFI_CONNECT_OK, p, 4);
        signal_data_ready(1);
    }
}

/* ── Command handlers ── */

static void handle_wifi_connect(const uint8_t *payload, uint16_t plen) {
    if (plen < 2) { queue_error(CMD_WIFI_CONNECT, ERR_INVALID); return; }
    uint8_t ssid_len = payload[0];
    if (plen < 1 + ssid_len + 1) { queue_error(CMD_WIFI_CONNECT, ERR_INVALID); return; }
    uint8_t pass_len = payload[1 + ssid_len];

    char ssid[33] = {0};
    char pass[65] = {0};
    memcpy(ssid, payload + 1, ssid_len < 32 ? ssid_len : 32);
    memcpy(pass, payload + 2 + ssid_len, pass_len < 64 ? pass_len : 64);

    ESP_LOGI(TAG, "Connecting to SSID: %s", ssid);

    wifi_config_t cfg = {0};
    memcpy(cfg.sta.ssid,     ssid, strlen(ssid));
    memcpy(cfg.sta.password, pass, strlen(pass));
    cfg.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    esp_wifi_disconnect();
    esp_wifi_set_config(WIFI_IF_STA, &cfg);
    esp_wifi_connect();
    /* Response comes via IP_EVENT_STA_GOT_IP */
}

static void handle_wifi_status(void) {
    uint8_t p[5];
    p[0] = wifi_connected;
    memcpy(p + 1, wifi_ip, 4);
    queue_rsp(RSP_WIFI_STATUS, p, 5);
    signal_data_ready(1);
}

static void handle_tcp_connect(const uint8_t *payload, uint16_t plen) {
    if (plen < 6) { queue_error(CMD_TCP_CONNECT, ERR_INVALID); return; }
    if (!wifi_connected) { queue_error(CMD_TCP_CONNECT, ERR_WIFI_FAIL); return; }

    /* Find free slot */
    int slot = -1;
    for (int i = 0; i < MAX_TCP_CONNS; i++) {
        if (!tcp_conns[i].in_use) { slot = i; break; }
    }
    if (slot < 0) { queue_error(CMD_TCP_CONNECT, ERR_NO_CONN); return; }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ((uint32_t)payload[0])       |
                           ((uint32_t)payload[1] << 8)  |
                           ((uint32_t)payload[2] << 16) |
                           ((uint32_t)payload[3] << 24);
    addr.sin_port = htons(((uint16_t)payload[4] << 8) | payload[5]);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { queue_error(CMD_TCP_CONNECT, ERR_TCP_FAIL); return; }

    /* Set socket non-blocking after connect */
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        queue_error(CMD_TCP_CONNECT, ERR_TCP_FAIL);
        return;
    }

    /* Make non-blocking for future recv */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    tcp_conns[slot].fd     = fd;
    tcp_conns[slot].in_use = 1;

    uint8_t p[1] = {(uint8_t)slot};
    queue_rsp(RSP_TCP_CONNECT_OK, p, 1);
    signal_data_ready(1);
    ESP_LOGI(TAG, "TCP connected, conn_id=%d", slot);
}

static void handle_tcp_send(const uint8_t *payload, uint16_t plen) {
    if (plen < 2) { queue_error(CMD_TCP_SEND, ERR_INVALID); return; }
    uint8_t conn_id = payload[0];
    if (conn_id >= MAX_TCP_CONNS || !tcp_conns[conn_id].in_use) {
        queue_error(CMD_TCP_SEND, ERR_NO_CONN); return;
    }
    int sent = send(tcp_conns[conn_id].fd, payload + 1, plen - 1, 0);
    if (sent < 0) { queue_error(CMD_TCP_SEND, ERR_TCP_FAIL); return; }

    uint8_t p[3] = {conn_id, (uint8_t)(sent & 0xFF), (uint8_t)(sent >> 8)};
    queue_rsp(RSP_TCP_SEND_OK, p, 3);
    signal_data_ready(1);
}

static void handle_tcp_close(const uint8_t *payload, uint16_t plen) {
    if (plen < 1) { queue_error(CMD_TCP_CLOSE, ERR_INVALID); return; }
    uint8_t conn_id = payload[0];
    if (conn_id < MAX_TCP_CONNS && tcp_conns[conn_id].in_use) {
        close(tcp_conns[conn_id].fd);
        tcp_conns[conn_id].in_use = 0;
    }
    uint8_t p[1] = {conn_id};
    queue_rsp(RSP_TCP_CLOSE_OK, p, 1);
    signal_data_ready(1);
}

static void handle_tcp_poll(const uint8_t *payload, uint16_t plen) {
    if (plen < 1) { queue_error(CMD_TCP_POLL, ERR_INVALID); return; }
    uint8_t conn_id = payload[0];
    if (conn_id >= MAX_TCP_CONNS || !tcp_conns[conn_id].in_use) {
        queue_error(CMD_TCP_POLL, ERR_NO_CONN); return;
    }
    uint8_t tmp[PAYLOAD_MAX - 1];
    int n = recv(tcp_conns[conn_id].fd, tmp, sizeof(tmp), MSG_DONTWAIT);
    if (n > 0) {
        uint8_t p[PAYLOAD_MAX];
        p[0] = conn_id;
        memcpy(p + 1, tmp, n);
        queue_rsp(RSP_TCP_DATA, p, (uint16_t)(n + 1));
        signal_data_ready(1);
    } else if (n == 0) {
        /* Connection closed by remote */
        close(tcp_conns[conn_id].fd);
        tcp_conns[conn_id].in_use = 0;
        queue_error(CMD_TCP_POLL, ERR_TCP_FAIL);
        signal_data_ready(1);
    }
    /* n < 0 && errno == EAGAIN: nothing to read, don't respond */
}

/* ── SPI task ── */

static void spi_task(void *arg) {
    spi_slave_transaction_t t = {0};
    rsp_frame_t pending_rsp;
    int has_pending = 0;

    while (1) {
        /* Prepare TX: send pending response or IDLE */
        if (!has_pending) {
            has_pending = (xQueueReceive(rsp_queue, &pending_rsp, 0) == pdTRUE);
        }
        if (has_pending) {
            memcpy(spi_tx_buf, pending_rsp.buf, TRANSFER_SIZE);
        } else {
            build_rsp(spi_tx_buf, RSP_IDLE, NULL, 0);
        }

        memset(spi_rx_buf, 0, TRANSFER_SIZE);
        t.length    = TRANSFER_SIZE * 8;
        t.tx_buffer = spi_tx_buf;
        t.rx_buffer = spi_rx_buf;

        esp_err_t ret = spi_slave_transmit(SPI_HOST, &t, portMAX_DELAY);
        if (ret != ESP_OK) continue;

        /* If we just sent a response, clear it */
        if (has_pending) {
            has_pending = 0;
            /* Check if more pending; update DATA_READY */
            if (uxQueueMessagesWaiting(rsp_queue) == 0)
                signal_data_ready(0);
        }

        /* Parse incoming command */
        if (spi_rx_buf[0] != MAGIC) continue;
        uint8_t  cmd    = spi_rx_buf[1];
        uint16_t plen   = (uint16_t)spi_rx_buf[2] | ((uint16_t)spi_rx_buf[3] << 8);
        if (plen > PAYLOAD_MAX) continue;
        uint8_t *payload = spi_rx_buf + 4;

        switch (cmd) {
        case CMD_WIFI_CONNECT: handle_wifi_connect(payload, plen); break;
        case CMD_WIFI_STATUS:  handle_wifi_status();               break;
        case CMD_TCP_CONNECT:  handle_tcp_connect(payload, plen);  break;
        case CMD_TCP_SEND:     handle_tcp_send(payload, plen);     break;
        case CMD_TCP_CLOSE:    handle_tcp_close(payload, plen);    break;
        case CMD_TCP_POLL:     handle_tcp_poll(payload, plen);     break;
        default:
            ESP_LOGW(TAG, "Unknown cmd 0x%02x", cmd);
            queue_error(cmd, ERR_INVALID);
            signal_data_ready(1);
            break;
        }
    }
}

/* ── Background RX poller ──
 * Proactively polls all open TCP connections and queues any data received.
 * This means the P4 doesn't need to constantly poll — it just watches DATA_READY.
 */
static void rx_poll_task(void *arg) {
    while (1) {
        for (int i = 0; i < MAX_TCP_CONNS; i++) {
            if (!tcp_conns[i].in_use) continue;
            uint8_t tmp[PAYLOAD_MAX - 1];
            int n = recv(tcp_conns[i].fd, tmp, sizeof(tmp), MSG_DONTWAIT);
            if (n > 0) {
                uint8_t p[PAYLOAD_MAX];
                p[0] = (uint8_t)i;
                memcpy(p + 1, tmp, n);
                queue_rsp(RSP_TCP_DATA, p, (uint16_t)(n + 1));
                signal_data_ready(1);
            } else if (n == 0) {
                close(tcp_conns[i].fd);
                tcp_conns[i].in_use = 0;
            }
        }
        vTaskDelay(pdMS_TO_TICKS(10)); /* poll every 10ms */
    }
}

/* ── App main ── */

void app_main(void) {
    /* NVS (needed by WiFi) */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }

    /* DATA_READY GPIO */
    gpio_config_t io = {
        .pin_bit_mask = (1ULL << PIN_DATA_READY),
        .mode         = GPIO_MODE_OUTPUT,
        .pull_up_en   = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_ENABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&io);
    signal_data_ready(0);

    /* SPI slave init */
    spi_bus_config_t buscfg = {
        .mosi_io_num     = PIN_MOSI,
        .miso_io_num     = PIN_MISO,
        .sclk_io_num     = PIN_CLK,
        .quadwp_io_num   = -1,
        .quadhd_io_num   = -1,
        .max_transfer_sz = TRANSFER_SIZE,
    };
    spi_slave_interface_config_t slvcfg = {
        .mode         = 0,
        .spics_io_num = PIN_CS,
        .queue_size   = 2,
        .flags        = 0,
    };
    ESP_ERROR_CHECK(spi_slave_initialize(SPI_HOST, &buscfg, &slvcfg, SPI_DMA_CH_AUTO));

    /* WiFi init */
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t wifi_cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&wifi_cfg));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                                         &wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                                         &wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());

    /* Response queue */
    rsp_queue = xQueueCreate(RSP_QUEUE_SIZE, sizeof(rsp_frame_t));

    /* TCP conn pool */
    memset(tcp_conns, 0, sizeof(tcp_conns));

    ESP_LOGI(TAG, "CKB WiFi co-processor ready");

    /* Tasks */
    xTaskCreate(spi_task,      "spi",    4096, NULL, 10, NULL);
    xTaskCreate(rx_poll_task,  "rxpoll", 2048, NULL,  5, NULL);
}
