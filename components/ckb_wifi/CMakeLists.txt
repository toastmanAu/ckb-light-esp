idf_component_register(
    SRCS "src/ckb_wifi.c"
    INCLUDE_DIRS "include"
    REQUIRES driver esp_wifi esp_netif freertos
)
