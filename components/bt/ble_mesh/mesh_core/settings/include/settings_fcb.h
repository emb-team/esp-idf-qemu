/*
 * Copyright (c) 2018 Nordic Semiconductor ASA
 * Copyright (c) 2015 Runtime Inc
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _BLE_MESH_SETTINGS_FCB_H_
#define _BLE_MESH_SETTINGS_FCB_H_

#include "nvs.h"

#ifdef __cplusplus
extern "C" {
#endif

struct settings_fcb {
    struct settings_store cf_store;
    nvs_handle handle;
};

struct settings_dup_check_arg {
    const char *name;
    const char *val;
    int is_dup;
};

int csi_load_check(struct settings_dup_check_arg *cdca);

#ifdef __cplusplus
}
#endif

#endif /* _BLE_MESH_SETTINGS_FCB_H_ */
