idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES ckb_core ckb_transport ckb_protocol esp_netif nvs_flash
             $<IF:$<STREQUAL:${IDF_TARGET},esp32s3>,esp_wifi esp_event,esp_eth>
)
