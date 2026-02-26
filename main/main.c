/*
 * CKB Light Client — ESP32-P4 + W5500
 *
 * Brings up W5500 SPI Ethernet, gets an IP via DHCP,
 * then polls the CKB node RPC and prints block height to serial.
 *
 * Serial output proves connectivity and light client function
 * before a display is wired up.
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
#include "esp_eth.h"
#include "driver/spi_master.h"
#include "driver/gpio.h"
#include "esp_http_client.h"
#include "ckb_types.h"

static const char *TAG = "ckb_p4";

/* ── W5500 SPI pins ──────────────────────────────────────────────── */
#define ETH_SPI_HOST      SPI2_HOST
#define ETH_SPI_SCLK_GPIO 10
#define ETH_SPI_MOSI_GPIO 11
#define ETH_SPI_MISO_GPIO 13
#define ETH_SPI_CS_GPIO    9
#define ETH_SPI_INT_GPIO  14
#define ETH_SPI_RST_GPIO  15
#define ETH_SPI_CLOCK_MHZ 25

/* ── CKB node ────────────────────────────────────────────────────── */
#define CKB_NODE_HOST    "192.168.68.87"
#define CKB_NODE_PORT    8114
#define CKB_RPC_URL      "http://" CKB_NODE_HOST ":8114"

/* ── Network ready event ─────────────────────────────────────────── */
#define ETH_GOT_IP_BIT   BIT0
static EventGroupHandle_t s_eth_event_group;

/* ── HTTP response buffer ────────────────────────────────────────── */
#define HTTP_BUF_SIZE 512
static char s_http_buf[HTTP_BUF_SIZE];
static int  s_http_len = 0;

/* ─────────────────────────────────────────────────────────────────
 * ETH event handlers
 * ───────────────────────────────────────────────────────────────── */
static void eth_event_handler(void *arg, esp_event_base_t base,
                              int32_t event_id, void *event_data)
{
    switch (event_id) {
    case ETHERNET_EVENT_CONNECTED:
        ESP_LOGI(TAG, "Ethernet link UP");
        break;
    case ETHERNET_EVENT_DISCONNECTED:
        ESP_LOGW(TAG, "Ethernet link DOWN");
        break;
    case ETHERNET_EVENT_START:
        ESP_LOGI(TAG, "Ethernet started");
        break;
    case ETHERNET_EVENT_STOP:
        ESP_LOGI(TAG, "Ethernet stopped");
        break;
    }
}

static void got_ip_handler(void *arg, esp_event_base_t base,
                           int32_t event_id, void *event_data)
{
    ip_event_got_ip_t *ev = (ip_event_got_ip_t *)event_data;
    ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&ev->ip_info.ip));
    xEventGroupSetBits(s_eth_event_group, ETH_GOT_IP_BIT);
}

/* ─────────────────────────────────────────────────────────────────
 * W5500 init
 * ───────────────────────────────────────────────────────────────── */
static void w5500_init(void)
{
    ESP_LOGI(TAG, "W5500 init — SCLK:%d MOSI:%d MISO:%d CS:%d INT:%d RST:%d @%dMHz",
             ETH_SPI_SCLK_GPIO, ETH_SPI_MOSI_GPIO, ETH_SPI_MISO_GPIO,
             ETH_SPI_CS_GPIO, ETH_SPI_INT_GPIO, ETH_SPI_RST_GPIO,
             ETH_SPI_CLOCK_MHZ);

    /* GPIO ISR service (needed for INT pin) */
    gpio_install_isr_service(0);

    /* SPI bus */
    spi_bus_config_t buscfg = {
        .miso_io_num   = ETH_SPI_MISO_GPIO,
        .mosi_io_num   = ETH_SPI_MOSI_GPIO,
        .sclk_io_num   = ETH_SPI_SCLK_GPIO,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
    };
    ESP_ERROR_CHECK(spi_bus_initialize(ETH_SPI_HOST, &buscfg, SPI_DMA_CH_AUTO));

    /* SPI device config for W5500 */
    spi_device_interface_config_t devcfg = {
        .mode            = 0,
        .clock_speed_hz  = ETH_SPI_CLOCK_MHZ * 1000 * 1000,
        .queue_size      = 20,
        .spics_io_num    = ETH_SPI_CS_GPIO,
    };

    /* W5500 MAC + PHY */
    eth_w5500_config_t w5500_cfg = ETH_W5500_DEFAULT_CONFIG(ETH_SPI_HOST, &devcfg);
    w5500_cfg.int_gpio_num = ETH_SPI_INT_GPIO;

    eth_mac_config_t mac_cfg = ETH_MAC_DEFAULT_CONFIG();
    eth_phy_config_t phy_cfg = ETH_PHY_DEFAULT_CONFIG();
    phy_cfg.reset_gpio_num = ETH_SPI_RST_GPIO;
    phy_cfg.phy_addr       = 1;  /* W5500 fixed PHY addr */

    esp_eth_mac_t *mac = esp_eth_mac_new_w5500(&w5500_cfg, &mac_cfg);
    esp_eth_phy_t *phy = esp_eth_phy_new_w5500(&phy_cfg);
    

    /* Ethernet driver */
    esp_eth_config_t eth_cfg = ETH_DEFAULT_CONFIG(mac, phy);
    esp_eth_handle_t eth_handle = NULL;
    ESP_ERROR_CHECK(esp_eth_driver_install(&eth_cfg, &eth_handle));

    /* Attach to TCP/IP stack */
    esp_netif_config_t netif_cfg = ESP_NETIF_DEFAULT_ETH();
    esp_netif_t *eth_netif = esp_netif_new(&netif_cfg);
    ESP_ERROR_CHECK(esp_netif_attach(eth_netif, esp_eth_new_netif_glue(eth_handle)));

    /* Register event handlers */
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID,
                                               &eth_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP,
                                               &got_ip_handler, NULL));

    /* Start */
    ESP_ERROR_CHECK(esp_eth_start(eth_handle));
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

/* Parse "number":"0xHEX" from JSON — returns uint64 */
static uint64_t parse_hex_field(const char *json, const char *key)
{
    char search[64];
    snprintf(search, sizeof(search), "\"%s\":\"0x", key);
    const char *p = strstr(json, search);
    if (!p) return 0;
    p += strlen(search);
    return (uint64_t)strtoull(p, NULL, 16);
}

/* Parse string field — returns pointer to static buffer */
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
 * CKB RPC calls
 * ───────────────────────────────────────────────────────────────── */
static bool ckb_rpc(const char *body, char *resp, int resp_len)
{
    s_http_len = 0;
    memset(s_http_buf, 0, sizeof(s_http_buf));

    esp_http_client_config_t cfg = {
        .url            = CKB_RPC_URL,
        .event_handler  = http_event_handler,
        .timeout_ms     = 5000,
        .method         = HTTP_METHOD_POST,
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
 * Main task: poll CKB node, print to serial
 * ───────────────────────────────────────────────────────────────── */
static void ckb_poll_task(void *arg)
{
    char resp[HTTP_BUF_SIZE];
    uint32_t poll_count = 0;

    ESP_LOGI(TAG, "CKB poll task started, targeting %s", CKB_RPC_URL);

    while (1) {
        poll_count++;

        /* get_tip_header */
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

        /* get_peers — count only */
        ok = ckb_rpc(
            "{\"jsonrpc\":\"2.0\",\"method\":\"get_peers\",\"params\":[],\"id\":2}",
            resp, sizeof(resp));
        if (ok) {
            /* Count "addresses" occurrences as proxy for peer count */
            uint32_t peers = 0;
            const char *p = resp;
            while ((p = strstr(p, "\"addresses\"")) != NULL) { peers++; p++; }
            ESP_LOGI(TAG, "        peers=%lu", (unsigned long)peers);
        }

        /* local_node_info — once on first poll */
        if (poll_count == 1) {
            ok = ckb_rpc(
                "{\"jsonrpc\":\"2.0\",\"method\":\"local_node_info\",\"params\":[],\"id\":3}",
                resp, sizeof(resp));
            if (ok) {
                char node_id[72];
                char ver[32];
                parse_str_field(resp, "node_id", node_id, sizeof(node_id));
                parse_str_field(resp, "version", ver, sizeof(ver));
                ESP_LOGI(TAG, "        node_id=%.20s...  version=%s", node_id, ver);
            }
        }

        vTaskDelay(pdMS_TO_TICKS(6000));  /* ~1 CKB block interval */
    }
}

/* ─────────────────────────────────────────────────────────────────
 * app_main
 * ───────────────────────────────────────────────────────────────── */
void app_main(void)
{
    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, " CKB Light Client — ESP32-P4 + W5500");
    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "IDF: %s  Target: %s", esp_get_idf_version(), CONFIG_IDF_TARGET);

    /* NVS */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    /* TCP/IP + event loop */
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    s_eth_event_group = xEventGroupCreate();

    /* Bring up W5500 */
    w5500_init();

    /* Wait for DHCP IP (30s timeout) */
    ESP_LOGI(TAG, "Waiting for DHCP...");
    EventBits_t bits = xEventGroupWaitBits(s_eth_event_group,
        ETH_GOT_IP_BIT, pdFALSE, pdFALSE, pdMS_TO_TICKS(30000));

    if (bits & ETH_GOT_IP_BIT) {
        ESP_LOGI(TAG, "Network ready — starting CKB poll");
        xTaskCreate(ckb_poll_task, "ckb_poll", 8192, NULL, 5, NULL);
    } else {
        ESP_LOGE(TAG, "DHCP timeout — check cable and router");
        ESP_LOGE(TAG, "Hint: verify W5500 wiring (SCLK=%d MOSI=%d MISO=%d CS=%d)",
                 ETH_SPI_SCLK_GPIO, ETH_SPI_MOSI_GPIO, ETH_SPI_MISO_GPIO, ETH_SPI_CS_GPIO);
    }
}
