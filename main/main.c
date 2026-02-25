/*
 * CKB Light Client — main entry point
 *
 * Supports:
 *   ESP32-P4  + W5500 SPI Ethernet  (idf.py set-target esp32p4)
 *   ESP32-S3  + native WiFi         (idf.py set-target esp32s3)
 *
 * Networking backend selected automatically by IDF_TARGET at build time.
 * All CKB core/transport/protocol code is target-agnostic.
 */
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "ckb_types.h"
#include "ckb_protocol.h"

static const char *TAG = "ckb_main";

/* ─── Target-specific networking ─────────────────────────────────── */

#if defined(CONFIG_IDF_TARGET_ESP32P4)
/* ── ESP32-P4: W5500 SPI Ethernet ──────────────────────────────── */
#include "esp_eth.h"

#define ETH_SPI_HOST      SPI2_HOST
#define ETH_SPI_SCLK_GPIO 10
#define ETH_SPI_MOSI_GPIO 11
#define ETH_SPI_MISO_GPIO 13
#define ETH_SPI_CS_GPIO    9
#define ETH_SPI_INT_GPIO  14
#define ETH_SPI_RST_GPIO  15
#define ETH_SPI_CLOCK_MHZ 25

static void net_init(void)
{
    ESP_LOGI(TAG, "Network: W5500 SPI Ethernet");
    ESP_LOGI(TAG, "  SCLK=%d MOSI=%d MISO=%d CS=%d INT=%d RST=%d @%dMHz",
             ETH_SPI_SCLK_GPIO, ETH_SPI_MOSI_GPIO, ETH_SPI_MISO_GPIO,
             ETH_SPI_CS_GPIO, ETH_SPI_INT_GPIO, ETH_SPI_RST_GPIO,
             ETH_SPI_CLOCK_MHZ);
    /* TODO: full W5500 init via esp_eth + espressif/esp-eth-drivers */
}

#elif defined(CONFIG_IDF_TARGET_ESP32S3)
/* ── ESP32-S3: native WiFi ──────────────────────────────────────── */
#include "esp_wifi.h"
#include "esp_event.h"

#ifndef CONFIG_CKB_WIFI_SSID
#define CONFIG_CKB_WIFI_SSID     "your_ssid"
#endif
#ifndef CONFIG_CKB_WIFI_PASSWORD
#define CONFIG_CKB_WIFI_PASSWORD "your_password"
#endif

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1
#define WIFI_MAX_RETRY     5

static EventGroupHandle_t s_wifi_event_group;
static int s_retry = 0;

static void wifi_event_handler(void *arg, esp_event_base_t base,
                               int32_t event_id, void *event_data)
{
    if (base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_retry < WIFI_MAX_RETRY) {
            esp_wifi_connect();
            s_retry++;
            ESP_LOGW(TAG, "WiFi retry %d/%d", s_retry, WIFI_MAX_RETRY);
        } else {
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        }
    } else if (base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *e = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "WiFi connected, IP: " IPSTR, IP2STR(&e->ip_info.ip));
        s_retry = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static void net_init(void)
{
    ESP_LOGI(TAG, "Network: native WiFi (S3)");
    s_wifi_event_group = xEventGroupCreate();

    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t inst_any, inst_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, &inst_any));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, &inst_got_ip));

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

    /* Wait for connection */
    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
        WIFI_CONNECTED_BIT | WIFI_FAIL_BIT, pdFALSE, pdFALSE,
        pdMS_TO_TICKS(15000));

    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "WiFi ready");
    } else {
        ESP_LOGE(TAG, "WiFi failed — check SSID/password in menuconfig");
    }
}

#else
#error "Unsupported target. Use: idf.py set-target esp32p4  OR  esp32s3"
#endif

/* ─── Common app entry point ─────────────────────────────────────── */

void app_main(void)
{
    ESP_LOGI(TAG, "CKB Light Client starting...");
    ESP_LOGI(TAG, "Target: %s", CONFIG_IDF_TARGET);

    /* NVS */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    /* Network stack */
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    net_init();

    /* TODO: CKB light client init
     *   - SecIO handshake
     *   - Yamux + protocol negotiation
     *   - GetLastState
     *   - Eaglesong header verification (Layer 2)
     *   - Merkle proof verification (Layer 3)
     */

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
