/*
 * Copyright (c) 2018 Nordic Semiconductor ASA
 * Copyright (c) 2015 Runtime Inc
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __SETTINGS_FCB_H_
#define __SETTINGS_FCB_H_

#include "nvs.h"
#include "include/settings.h"

#ifdef __cplusplus
extern "C" {
#endif

struct settings_fcb {
    struct settings_store cf_store;
    const char *file_name;
    nvs_handle handle;
};

struct settings_dup_check_arg {
    const char *name;
    const char *val;
    int is_dup;
};

extern int settings_fcb_src(struct settings_fcb *cf);
extern int settings_fcb_dst(struct settings_fcb *cf);

int csi_load_check(struct settings_dup_check_arg *cdca);

#ifdef __cplusplus
}
#endif

#endif /* __SETTINGS_FCB_H_ */
