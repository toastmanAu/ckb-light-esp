if(IDF_TARGET STREQUAL "esp32p4")
    # ESP32-P4 has no WiFi — use W5500 SPI Ethernet
    set(NET_REQUIRES esp_eth)
else()
    # All other supported targets have native WiFi
    # (esp32, esp32s2, esp32s3, esp32c3, esp32c6, esp32h2, esp32c5 ...)
    set(NET_REQUIRES esp_wifi)
endif()

idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES ckb_core ckb_transport ckb_protocol esp_netif esp_event nvs_flash ${NET_REQUIRES}
)
