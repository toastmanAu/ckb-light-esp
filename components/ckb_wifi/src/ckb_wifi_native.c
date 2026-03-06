/*
 * ckb_wifi_native.c — Native WiFi backend for ESP32 targets with built-in WiFi
 *                     (C6, S3, C3, S2, classic ESP32, etc.)
 *
 * Selected at compile time via CKB_WIFI_NATIVE=1 in CMake/build_flags.
 * Falls back to ckb_wifi.c (SPI co-proc) when not defined.
 *
 * Implements the same ckb_wifi.h API — callers see no difference.
 *
 * Uses ESP-IDF esp_wifi + lwIP sockets directly.
 */

#ifdef CKB_WIFI_NATIVE

#include "ckb_wifi.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include <string.h>
#include <errno.h>

static const char *TAG = "ckb-wifi-native";

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

static EventGroupHandle_t s_wifi_eg = NULL;
static esp_netif_t       *s_netif   = NULL;
static uint8_t            s_ip[4]   = {0};
static uint8_t            s_initialized = 0;
static uint8_t            s_connected   = 0;

/* Socket table */
static int s_socks[CKB_WIFI_MAX_CONNS];

static void _wifi_event_handler(void *arg, esp_event_base_t base,
                                 int32_t id, void *data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        s_connected = 0;
        esp_wifi_connect();
        xEventGroupClearBits(s_wifi_eg, WIFI_CONNECTED_BIT);
        xEventGroupSetBits(s_wifi_eg, WIFI_FAIL_BIT);
        ESP_LOGW(TAG, "WiFi disconnected — reconnecting");
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *e = (ip_event_got_ip_t *)data;
        uint32_t ip = e->ip_info.ip.addr;
        s_ip[0] = ip & 0xFF;
        s_ip[1] = (ip >> 8) & 0xFF;
        s_ip[2] = (ip >> 16) & 0xFF;
        s_ip[3] = (ip >> 24) & 0xFF;
        ESP_LOGI(TAG, "Got IP: %d.%d.%d.%d", s_ip[0], s_ip[1], s_ip[2], s_ip[3]);
        s_connected = 1;
        xEventGroupSetBits(s_wifi_eg, WIFI_CONNECTED_BIT);
        xEventGroupClearBits(s_wifi_eg, WIFI_FAIL_BIT);
    }
}

int ckb_wifi_init(void)
{
    if (s_initialized) return CKB_WIFI_OK;

    for (int i = 0; i < CKB_WIFI_MAX_CONNS; i++) s_socks[i] = -1;

    esp_err_t err = esp_netif_init();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "netif init failed: %d", err);
        return CKB_WIFI_ERR_INIT;
    }

    err = esp_event_loop_create_default();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "event loop init failed: %d", err);
        return CKB_WIFI_ERR_INIT;
    }

    s_netif = esp_netif_create_default_wifi_sta();
    s_wifi_eg = xEventGroupCreate();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                         &_wifi_event_handler, NULL, NULL);
    esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                         &_wifi_event_handler, NULL, NULL);

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));

    s_initialized = 1;
    return CKB_WIFI_OK;
}

int ckb_wifi_connect(const char *ssid, const char *password,
                     uint32_t timeout_ms, uint8_t ip_out[4])
{
    if (!s_initialized) return CKB_WIFI_ERR_INIT;

    wifi_config_t wcfg = {0};
    strncpy((char *)wcfg.sta.ssid,     ssid,     sizeof(wcfg.sta.ssid) - 1);
    strncpy((char *)wcfg.sta.password, password, sizeof(wcfg.sta.password) - 1);
    wcfg.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wcfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    EventBits_t bits = xEventGroupWaitBits(s_wifi_eg,
                                            WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
                                            pdFALSE, pdFALSE,
                                            pdMS_TO_TICKS(timeout_ms));

    if (bits & WIFI_CONNECTED_BIT) {
        if (ip_out) memcpy(ip_out, s_ip, 4);
        return CKB_WIFI_OK;
    }
    return CKB_WIFI_ERR_CONN;
}

int ckb_wifi_is_connected(void)
{
    return s_connected;
}

int ckb_tcp_connect(const uint8_t ip[4], uint16_t port)
{
    /* Find free slot */
    int slot = -1;
    for (int i = 0; i < CKB_WIFI_MAX_CONNS; i++) {
        if (s_socks[i] < 0) { slot = i; break; }
    }
    if (slot < 0) return CKB_WIFI_ERR_CONN;

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) return CKB_WIFI_ERR_CONN;

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    addr.sin_addr.s_addr = (uint32_t)ip[0]
                         | ((uint32_t)ip[1] << 8)
                         | ((uint32_t)ip[2] << 16)
                         | ((uint32_t)ip[3] << 24);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        ESP_LOGE(TAG, "connect failed: %d", errno);
        close(fd);
        return CKB_WIFI_ERR_CONN;
    }

    s_socks[slot] = fd;
    ESP_LOGI(TAG, "TCP connected slot %d → %d.%d.%d.%d:%d",
             slot, ip[0], ip[1], ip[2], ip[3], port);
    return slot;
}

int ckb_tcp_send(int conn_id, const uint8_t *data, uint16_t len)
{
    if (conn_id < 0 || conn_id >= CKB_WIFI_MAX_CONNS || s_socks[conn_id] < 0)
        return CKB_WIFI_ERR_SEND;
    int sent = send(s_socks[conn_id], data, len, 0);
    return (sent < 0) ? CKB_WIFI_ERR_SEND : sent;
}

int ckb_tcp_recv(int conn_id, uint8_t *buf, uint16_t buf_len, uint32_t timeout_ms)
{
    if (conn_id < 0 || conn_id >= CKB_WIFI_MAX_CONNS || s_socks[conn_id] < 0)
        return CKB_WIFI_ERR_RECV;

    int fd = s_socks[conn_id];

    /* Set socket timeout */
    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int n = recv(fd, buf, buf_len, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0; /* timeout */
        return CKB_WIFI_ERR_RECV;
    }
    return n;
}

int ckb_tcp_close(int conn_id)
{
    if (conn_id < 0 || conn_id >= CKB_WIFI_MAX_CONNS) return CKB_WIFI_ERR_CONN;
    if (s_socks[conn_id] >= 0) {
        close(s_socks[conn_id]);
        s_socks[conn_id] = -1;
    }
    return CKB_WIFI_OK;
}

void ckb_wifi_print_wiring(void)
{
    ESP_LOGI(TAG, "Native WiFi — no external wiring required");
}

#endif /* CKB_WIFI_NATIVE */
