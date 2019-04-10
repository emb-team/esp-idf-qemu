/*
 * Copyright (c) 2018 Nordic Semiconductor ASA
 * Copyright (c) 2015 Runtime Inc
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _BLE_MESH_SETTINGS_PRIV_H_
#define _BLE_MESH_SETTINGS_PRIV_H_

#ifdef __cplusplus
extern "C" {
#endif

int settings_line_parse(char *buf, char **namep, char **valp);
int settings_line_make(char *dst, int dlen, const char *name, const char *val);

typedef void (*load_cb)(char *name, char *val, void *cb_arg);
struct settings_store_itf {
    int (*csi_load)(struct settings_store *cs, load_cb cb, void *cb_arg);
    int (*csi_save)(struct settings_store *cs, const char *name, const char *value);
};

void settings_src_register(struct settings_store *cs);
void settings_dst_register(struct settings_store *cs);

#ifdef __cplusplus
}
#endif

#endif /* _BLE_MESH_SETTINGS_PRIV_H_ */
