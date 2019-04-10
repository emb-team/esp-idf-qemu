/*
 * Copyright (c) 2018 Nordic Semiconductor ASA
 * Copyright (c) 2015 Runtime Inc
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>

#include "sdkconfig.h"

#include "mesh_types.h"

#include "settings_base64.h"
#include "settings_act.h"
#include "settings_priv.h"

#if CONFIG_BLE_MESH_SETTINGS

static sys_slist_t settings_handlers;

extern void settings_store_init(void);

void settings_init(void)
{
    sys_slist_init(&settings_handlers);
    settings_store_init();
}

int settings_register(struct settings_handler *handler)
{
    sys_slist_prepend(&settings_handlers, &handler->node);
    return 0;
}

/* Find settings_handler based on name. */
static struct settings_handler *settings_handler_lookup(char *name)
{
    struct settings_handler *ch;

    SYS_SLIST_FOR_EACH_CONTAINER(&settings_handlers, ch, node) {
        BT_DBG("%s, name = %s, ch->name = %s", __func__, name, ch->name);
        if (!strcmp(name, ch->name)) {
            return ch;
        }
    }
    return NULL;
}

/* Separate string into argv array. */
static int settings_parse_name(char *name, int *name_argc, char *name_argv[])
{
    int i = 0;

    while (name) {
        name_argv[i++] = name;

        while (1) {
            if (*name == '\0') {
                name = NULL;
                break;
            }

            if (*name == *SETTINGS_NAME_SEPARATOR) {
                *name = '\0';
                name++;
                break;
            }
            name++;
        }
    }

    *name_argc = i;

    return 0;
}

static struct settings_handler *settings_parse_and_lookup(char *name,
                int *name_argc, char *name_argv[])
{
    int rc;

    rc = settings_parse_name(name, name_argc, name_argv);
    if (rc) {
        BT_ERR("%s, Failed to parse settings name", __func__);
        return NULL;
    }
    return settings_handler_lookup(name_argv[0]);
}

int settings_bytes_from_str(char *val_str, void *vp, int *len)
{
    size_t rc;
    int err;

    err = base64_decode(vp, *len, &rc, (const u8_t *)val_str, strlen(val_str));

    if (err) {
        return -1;
    }

    *len = rc;
    return 0;
}

char *settings_str_from_bytes(void *vp, int vp_len, char *buf, int buf_len)
{
    size_t enc_len;

    if (BASE64_ENCODE_SIZE(vp_len) > buf_len) {
        return NULL;
    }

    base64_encode((u8_t *)buf, buf_len, &enc_len, vp, vp_len);

    return buf;
}

int settings_set_value(char *name, char *val_str)
{
    char *name_argv[SETTINGS_MAX_DIR_DEPTH];
    struct settings_handler *ch;
    int name_argc;

    ch = settings_parse_and_lookup(name, &name_argc, name_argv);
    if (!ch) {
        BT_ERR("%s, Failed to parse & lookup settings", __func__);
        return -EINVAL;
    }

    return ch->h_set(name_argc - 1, &name_argv[1], val_str);
}

int settings_commit(void)
{
    struct settings_handler *ch;
    int rc2 = 0;
    int rc = 0;

    SYS_SLIST_FOR_EACH_CONTAINER(&settings_handlers, ch, node) {
        if (ch->h_commit) {
            rc2 = ch->h_commit();
            if (!rc) {
                rc = rc2;
            }
        }
    }

    return rc;
}

#endif /* CONFIG_BLE_MESH_SETTINGS */
