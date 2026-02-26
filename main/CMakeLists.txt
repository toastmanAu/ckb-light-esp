if(IDF_TARGET STREQUAL "esp32p4")
    set(NET_REQUIRES esp_eth driver esp_http_client)
else()
    set(NET_REQUIRES esp_wifi esp_http_client)
endif()

idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES ckb_core ckb_transport ckb_protocol esp_netif esp_event nvs_flash ${NET_REQUIRES}
)
