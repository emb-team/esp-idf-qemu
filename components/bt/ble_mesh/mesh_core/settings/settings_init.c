/*
 * Copyright (c) 2018 Nordic Semiconductor ASA
 * Copyright (c) 2015 Runtime Inc
 *
 * SPDX-License-Identifier: Apache-2.0
 */


#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>

#include "sdkconfig.h"
#include "settings_act.h"
#include "settings_fcb.h"

#if CONFIG_BLE_MESH_SETTINGS

extern void settings_init(void);
extern int settings_fcb_src(struct settings_fcb *cf);
extern int settings_fcb_dst(struct settings_fcb *cf);

static struct settings_fcb config_init_settings_fcb;

static int settings_init_fcb(void)
{
    int rc;

    rc = settings_fcb_src(&config_init_settings_fcb);
    if (rc) {
        return rc;
    }

    rc = settings_fcb_dst(&config_init_settings_fcb);
    return rc;
}

int settings_subsys_init(void)
{
    settings_init();
    settings_init_fcb();
    return 0;
}

#endif /* CONFIG_BLE_MESH_SETTINGS */
