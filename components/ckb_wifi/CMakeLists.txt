# Select WiFi backend:
#   CKB_WIFI_NATIVE=1 → native esp_wifi (ESP32 C6/S3/C3/S2/classic)
#   (default)         → SPI co-processor (ESP32-P4)

if(CONFIG_CKB_WIFI_NATIVE OR DEFINED ENV{CKB_WIFI_NATIVE})
    set(WIFI_SRC "src/ckb_wifi_native.c")
    set(WIFI_REQUIRES "esp_wifi esp_event esp_netif lwip freertos")
    message(STATUS "ckb_wifi: native WiFi backend selected")
else()
    set(WIFI_SRC "src/ckb_wifi.c")
    set(WIFI_REQUIRES "driver esp_wifi esp_netif freertos")
    message(STATUS "ckb_wifi: SPI co-processor backend selected")
endif()

idf_component_register(
    SRCS "${WIFI_SRC}"
    INCLUDE_DIRS "include"
    REQUIRES ${WIFI_REQUIRES}
)

if(CONFIG_CKB_WIFI_NATIVE OR DEFINED ENV{CKB_WIFI_NATIVE})
    target_compile_definitions(${COMPONENT_LIB} PUBLIC CKB_WIFI_NATIVE=1)
endif()
