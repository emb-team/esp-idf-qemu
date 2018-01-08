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
#include "settings/include/settings.h"

#if CONFIG_BT_MESH_SETTINGS

void settings_init(void);

#ifdef CONFIG_SETTINGS_FS
#include <fs.h>

static struct settings_file config_init_settings_file = {
    .cf_name = CONFIG_SETTINGS_FS_FILE,
    .cf_maxlines = CONFIG_SETTINGS_FS_MAX_LINES
};

static void settings_init_fs(void)
{
    int rc;

    rc = settings_file_src(&config_init_settings_file);
    if (rc) {
        BT_ERR("%s, settings file srouce fail.", __func__);
        return;
    }

    rc = settings_file_dst(&config_init_settings_file);
    if (rc) {
        BT_ERR("%s, settings file dst fail.", __func__);
        return;
    }
}

#elif defined(CONFIG_SETTINGS_FCB)
#include "settings/include/fcb.h"
#include "settings/include/settings_fcb.h"

static struct settings_fcb config_init_settings_fcb = {

};

static void settings_init_fcb(void)
{
    int rc;
    rc = settings_fcb_src(&config_init_settings_fcb);

    if (rc != 0) {
        rc = settings_fcb_src(&config_init_settings_fcb);
    }

    rc = settings_fcb_dst(&config_init_settings_fcb);

}

#endif

int settings_subsys_init(void)
{
    settings_init();

#ifdef CONFIG_SETTINGS_FS
    settings_init_fs(); /* func rises kernel panic once error */

    /*
     * Must be called after root FS has been initialized.
     */
    return fs_mkdir(CONFIG_SETTINGS_FS_DIR);
#elif defined(CONFIG_SETTINGS_FCB)
    settings_init_fcb(); /* func rises kernel panic once error */
    return 0;
#endif
}

#endif /* CONFIG_BT_MESH_SETTINGS */
