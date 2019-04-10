/*
 * Copyright (c) 2018 Nordic Semiconductor ASA
 * Copyright (c) 2015 Runtime Inc
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <errno.h>

#include "sdkconfig.h"

#include "mesh_util.h"
#include "mesh_types.h"

#include "settings_act.h"
#include "settings_priv.h"
#include "settings_fcb.h"

#if CONFIG_BLE_MESH_SETTINGS

static struct settings_store *settings_save_dst;
static sys_slist_t settings_load_srcs;

void settings_src_register(struct settings_store *cs)
{
    sys_snode_t *prev = NULL;
    sys_snode_t *cur = NULL;

    SYS_SLIST_FOR_EACH_NODE(&settings_load_srcs, cur) {
        prev = cur;
    }

    sys_slist_insert(&settings_load_srcs, prev, &cs->cs_next);
}

void settings_dst_register(struct settings_store *cs)
{
    settings_save_dst = cs;
}

static void settings_load_cb(char *name, char *val, void *cb_arg)
{
    int rc = settings_set_value(name, val);
    __ASSERT(rc == 0, "%s, Failed to load setting value", __func__);
}

int settings_load(void)
{
    struct settings_store *cs;

    SYS_SLIST_FOR_EACH_CONTAINER(&settings_load_srcs, cs, cs_next) {
        cs->cs_itf->csi_load(cs, settings_load_cb, NULL);
    }
    return settings_commit();
}

/*
 * Append a single value to persisted config. Don't store duplicate value.
 */
int settings_save_one(const char *name, char *value)
{
    struct settings_dup_check_arg cdca;
    struct settings_store *cs;

    cs = settings_save_dst;
    if (!cs) {
        return -ENOENT;
    }

    /* Check if we're writing the same value again. */
    cdca.name = name;
    cdca.val = value;
    cdca.is_dup = 0;
    csi_load_check(&cdca);

    if (cdca.is_dup == 1) {
        return 0;
    }
    return cs->cs_itf->csi_save(cs, name, value);
}

void settings_store_init(void)
{
    sys_slist_init(&settings_load_srcs);
}

#endif /* CONFIG_BLE_MESH_SETTINGS */
