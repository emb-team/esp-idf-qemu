set(COMPONENT_SRCS "src/btdm_api.c")

set(COMPONENT_REQUIRES "")

register_component()

component_compile_options(-Wno-strict-aliasing)
component_compile_definitions(
    __ets__
    EMBEDDED_SUPP
    IEEE8021X_EAPOL
    EAP_PEER_METHOD
    EAP_MSCHAPv2
    EAP_TTLS
    EAP_TLS
    EAP_PEAP
    USE_WPA2_TASK
    CONFIG_WPS2
    CONFIG_WPS_PIN
    USE_WPS_TASK
    ESPRESSIF_USE
    ESP32_WORKAROUND
    CONFIG_ECC
    )
