/*
 * CKB Light Client — ESP32-C6 (native WiFi)
 *
 * Connects to WiFi, polls the CKB node RPC, prints block height/peers
 * to serial every ~6s (one CKB block interval).
 *
 * Configure SSID/password via menuconfig or sdkconfig.defaults.esp32c6
 */
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "esp_http_client.h"
#include "ckb_types.h"

static const char *TAG = "ckb_c6";

/* ── WiFi credentials — set via sdkconfig or menuconfig ─────────── */
#ifndef CONFIG_CKB_WIFI_SSID
#define CONFIG_CKB_WIFI_SSID     "D-Link the router"
#endif
#ifndef CONFIG_CKB_WIFI_PASSWORD
#define CONFIG_CKB_WIFI_PASSWORD  "Ajeip853jw5590!"
#endif

/* ── CKB node ────────────────────────────────────────────────────── */
#define CKB_NODE_HOST    "192.168.68.87"
#define CKB_RPC_URL      "http://" CKB_NODE_HOST ":8114"

/* ── Network ready event ─────────────────────────────────────────── */
#define WIFI_GOT_IP_BIT  BIT0
static EventGroupHandle_t s_wifi_event_group;

/* ── HTTP response buffer ────────────────────────────────────────── */
#define HTTP_BUF_SIZE 512
static char s_http_buf[HTTP_BUF_SIZE];
static int  s_http_len = 0;

/* ─────────────────────────────────────────────────────────────────
 * WiFi event handler
 * ───────────────────────────────────────────────────────────────── */
static void wifi_event_handler(void *arg, esp_event_base_t base,
                               int32_t event_id, void *event_data)
{
    if (base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGW(TAG, "WiFi disconnected — retrying...");
        esp_wifi_connect();
    } else if (base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *ev = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&ev->ip_info.ip));
        xEventGroupSetBits(s_wifi_event_group, WIFI_GOT_IP_BIT);
    }
}

/* ─────────────────────────────────────────────────────────────────
 * WiFi init
 * ───────────────────────────────────────────────────────────────── */
static void wifi_init(void)
{
    s_wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                               &wifi_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                               &wifi_event_handler, NULL));

    wifi_config_t wifi_cfg = {
        .sta = {
            .ssid     = CONFIG_CKB_WIFI_SSID,
            .password = CONFIG_CKB_WIFI_PASSWORD,
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Connecting to SSID: %s", CONFIG_CKB_WIFI_SSID);
}

/* ─────────────────────────────────────────────────────────────────
 * HTTP helpers
 * ───────────────────────────────────────────────────────────────── */
static esp_err_t http_event_handler(esp_http_client_event_t *evt)
{
    if (evt->event_id == HTTP_EVENT_ON_DATA) {
        int copy = evt->data_len;
        if (s_http_len + copy >= HTTP_BUF_SIZE - 1)
            copy = HTTP_BUF_SIZE - 1 - s_http_len;
        memcpy(s_http_buf + s_http_len, evt->data, copy);
        s_http_len += copy;
    }
    return ESP_OK;
}

static uint64_t parse_hex_field(const char *json, const char *key)
{
    char search[64];
    snprintf(search, sizeof(search), "\"%s\":\"0x", key);
    const char *p = strstr(json, search);
    if (!p) return 0;
    p += strlen(search);
    return (uint64_t)strtoull(p, NULL, 16);
}

static const char *parse_str_field(const char *json, const char *key,
                                   char *out, size_t outlen)
{
    char search[64];
    snprintf(search, sizeof(search), "\"%s\":\"", key);
    const char *p = strstr(json, search);
    if (!p) { out[0] = '\0'; return out; }
    p += strlen(search);
    size_t i = 0;
    while (*p && *p != '"' && i < outlen - 1)
        out[i++] = *p++;
    out[i] = '\0';
    return out;
}

/* ─────────────────────────────────────────────────────────────────
 * CKB RPC
 * ───────────────────────────────────────────────────────────────── */
static bool ckb_rpc(const char *body, char *resp, int resp_len)
{
    s_http_len = 0;
    memset(s_http_buf, 0, sizeof(s_http_buf));

    esp_http_client_config_t cfg = {
        .url           = CKB_RPC_URL,
        .event_handler = http_event_handler,
        .timeout_ms    = 5000,
        .method        = HTTP_METHOD_POST,
    };
    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_post_field(client, body, strlen(body));

    esp_err_t err = esp_http_client_perform(client);
    esp_http_client_cleanup(client);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "HTTP error: %s", esp_err_to_name(err));
        return false;
    }
    s_http_buf[s_http_len] = '\0';
    strncpy(resp, s_http_buf, resp_len - 1);
    return true;
}

/* ─────────────────────────────────────────────────────────────────
 * CKB poll task
 * ───────────────────────────────────────────────────────────────── */
static void ckb_poll_task(void *arg)
{
    char resp[HTTP_BUF_SIZE];
    uint32_t poll_count = 0;

    ESP_LOGI(TAG, "CKB poll task started → %s", CKB_RPC_URL);

    while (1) {
        poll_count++;

        bool ok = ckb_rpc(
            "{\"jsonrpc\":\"2.0\",\"method\":\"get_tip_header\",\"params\":[],\"id\":1}",
            resp, sizeof(resp));

        if (ok) {
            uint64_t height = parse_hex_field(resp, "number");
            uint64_t ts_ms  = parse_hex_field(resp, "timestamp");
            char hash[72];
            parse_str_field(resp, "hash", hash, sizeof(hash));
            ESP_LOGI(TAG, "[#%lu] block=%llu  ts=%llu  hash=%.16s...",
                     (unsigned long)poll_count,
                     (unsigned long long)height,
                     (unsigned long long)ts_ms,
                     hash[0] ? hash : "?");
        } else {
            ESP_LOGE(TAG, "[#%lu] RPC failed", (unsigned long)poll_count);
        }

        /* Peer count */
        ok = ckb_rpc(
            "{\"jsonrpc\":\"2.0\",\"method\":\"get_peers\",\"params\":[],\"id\":2}",
            resp, sizeof(resp));
        if (ok) {
            uint32_t peers = 0;
            const char *p = resp;
            while ((p = strstr(p, "\"addresses\"")) != NULL) { peers++; p++; }
            ESP_LOGI(TAG, "        peers=%lu", (unsigned long)peers);
        }

        /* Node info on first poll */
        if (poll_count == 1) {
            ok = ckb_rpc(
                "{\"jsonrpc\":\"2.0\",\"method\":\"local_node_info\",\"params\":[],\"id\":3}",
                resp, sizeof(resp));
            if (ok) {
                char node_id[72], ver[32];
                parse_str_field(resp, "node_id", node_id, sizeof(node_id));
                parse_str_field(resp, "version", ver, sizeof(ver));
                ESP_LOGI(TAG, "        node=%.20s...  ver=%s", node_id, ver);
            }
        }

        vTaskDelay(pdMS_TO_TICKS(6000));
    }
}

/* ─────────────────────────────────────────────────────────────────
 * app_main
 * ───────────────────────────────────────────────────────────────── */
void app_main(void)
{
    vTaskDelay(pdMS_TO_TICKS(2000));

    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, " CKB Light Client — ESP32-C6 WiFi");
    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "IDF: %s  Target: %s", esp_get_idf_version(), CONFIG_IDF_TARGET);

    /* NVS */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    /* WiFi */
    wifi_init();

    /* Wait for IP (60s timeout) */
    ESP_LOGI(TAG, "Waiting for IP...");
    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
        WIFI_GOT_IP_BIT, pdFALSE, pdFALSE, pdMS_TO_TICKS(60000));

    if (bits & WIFI_GOT_IP_BIT) {
        ESP_LOGI(TAG, "Network ready — starting CKB poll");
        xTaskCreate(ckb_poll_task, "ckb_poll", 8192, NULL, 5, NULL);
    } else {
        ESP_LOGE(TAG, "WiFi timeout — check SSID/password in sdkconfig");
    }
}
