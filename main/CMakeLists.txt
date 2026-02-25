if(IDF_TARGET STREQUAL "esp32s3")
    set(NET_REQUIRES esp_wifi esp_event)
else()
    # esp32p4 and any other target: W5500 SPI Ethernet
    set(NET_REQUIRES esp_eth)
endif()

idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES ckb_core ckb_transport ckb_protocol esp_netif nvs_flash ${NET_REQUIRES}
)
