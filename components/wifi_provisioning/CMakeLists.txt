set(COMPONENT_ADD_INCLUDEDIRS include)
set(COMPONENT_PRIV_INCLUDEDIRS proto-c ../protocomm/proto-c)
set(COMPONENT_SRCS  "src/wifi_config.c"
                    "proto-c/wifi_config.pb-c.c"
                    "proto-c/wifi_constants.pb-c.c")

set(COMPONENT_REQUIRES lwip)
set(COMPONENT_PRIV_REQUIRES protobuf-c protocomm)
if(CONFIG_BT_ENABLED)
    if(CONFIG_BT_BLUEDROID_ENABLED OR CONFIG_BT_NIMBLE_ENABLED)
        list(APPEND srcs
            "src/scheme_ble.c")
    endif()
endif()

register_component()
