/*
 * Copyright (c) 2018 Nordic Semiconductor ASA
 * Copyright (c) 2015 Runtime Inc
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <string.h>

#include "sdkconfig.h"
#include "nvs.h"

#include "settings/include/settings.h"
#include "settings/include/settings_fcb.h"
#include "settings/include/settings_priv.h"

#if CONFIG_BT_MESH_SETTINGS

#define SETTINGS_FCB_VERS       1
#define KEY_BUF_LEN_MAX         1024

static int buf_len = 0;
static const char *BLE_MESH_FCB_NVS_KEY = "fcb_nvs_key";
static const char *BLE_MESH_FCB_FILE_NAME = "fcb_nvs_file";
static char key_buf[KEY_BUF_LEN_MAX];

struct settings_fcb_load_cb_arg {
    load_cb cb;
    void *cb_arg;
};

static int settings_fcb_load(struct settings_store *cs, load_cb cb,
                             void *cb_arg);
static int settings_fcb_save(struct settings_store *cs, const char *name,
                             const char *value);

static struct settings_store_itf settings_fcb_itf = {
    .csi_load = settings_fcb_load,
    .csi_save = settings_fcb_save,
};

int settings_fcb_src(struct settings_fcb *cf)
{
    cf->file_name = BLE_MESH_FCB_FILE_NAME;
    if (nvs_open(BLE_MESH_FCB_FILE_NAME, NVS_READWRITE, &cf->handle) != ESP_OK) {
        return -1;
    }
    cf->cf_store.cs_itf = &settings_fcb_itf;
    settings_src_register(&cf->cf_store);

    return 0;
}

int settings_fcb_dst(struct settings_fcb *cf)
{
    cf->cf_store.cs_itf = &settings_fcb_itf;
    settings_dst_register(&cf->cf_store);

    return 0;
}

static int settings_fcb_load_cb(struct settings_fcb *cf, void *arg)
{
    struct settings_fcb_load_cb_arg *argp;
    char buf[SETTINGS_MAX_NAME_LEN + SETTINGS_MAX_VAL_LEN +
                                   SETTINGS_EXTRA_LEN];
    char *name_str;
    char *val_str;
    int rc = 0;
    size_t len = KEY_BUF_LEN_MAX;
    char *cp_start = NULL;

    argp = (struct settings_fcb_load_cb_arg *)arg;

    rc = nvs_get_blob(cf->handle, BLE_MESH_FCB_NVS_KEY, NULL, (size_t *)&buf_len);
    rc = nvs_get_blob(cf->handle, BLE_MESH_FCB_NVS_KEY, key_buf, (size_t *)&buf_len);

    if (rc) {
        return 0;
    }

    cp_start = key_buf;
    while (cp_start != NULL && *cp_start != '\0') {
        len = strlen(cp_start);
        if (len >= sizeof(buf)) {
            len = sizeof(buf) - 1;
        }

        memcpy(buf, cp_start, len);
        buf[len] = '\0';
        rc = settings_line_parse(buf, &name_str, &val_str);

        if (rc) {
            return 0;
        }
        BT_DBG("name_str = %s, val_str = %s", name_str, val_str);
        argp->cb(name_str, val_str, argp->cb_arg);
        cp_start += (len + 1);
    }
    return 0;
}

static int settings_fcb_load(struct settings_store *cs, load_cb cb,
                             void *cb_arg)
{
    struct settings_fcb *cf = (struct settings_fcb *)cs;
    struct settings_fcb_load_cb_arg arg;
    int rc;

    arg.cb = cb;
    arg.cb_arg = cb_arg;
    rc = settings_fcb_load_cb(cf, &arg);
    if (rc) {
        return -EINVAL;
    }

    return 0;
}

static char *settings_link_buf(char *buf)
{

    int blen = strlen(buf);

    memcpy(&key_buf[buf_len], buf, blen);
    buf_len += blen;

    key_buf[buf_len++] = '\0';

    return key_buf;
}

static int settings_fcb_save(struct settings_store *cs, const char *name,
                             const char *value)
{
    struct settings_fcb *cf = (struct settings_fcb *)cs;
    char buf[SETTINGS_MAX_NAME_LEN + SETTINGS_MAX_VAL_LEN +
                                   SETTINGS_EXTRA_LEN];
    int len;

    if (!name) {
        return -EINVAL;
    }

    len = settings_line_make(buf, sizeof(buf), name, value);
    if (len < 0 || len + 2 > sizeof(buf)) {
        return -EINVAL;
    }

    settings_link_buf(buf);
    return nvs_set_blob(cf->handle, BLE_MESH_FCB_NVS_KEY, (void *)key_buf, buf_len);
}

int csi_load_check(struct settings_dup_check_arg *cdca)
{
    char *cp_start = NULL;
    cp_start = key_buf;
    size_t len = 0;
    char buf[SETTINGS_MAX_NAME_LEN + SETTINGS_MAX_VAL_LEN +
                                   SETTINGS_EXTRA_LEN];
    char *name_str;
    char *val_str;
    int rc = 0;

    while (cp_start != NULL && *cp_start != '\0') {
        len = strlen(cp_start);
        if (len >= sizeof(buf)) {
            len = sizeof(buf) - 1;
        }

        memcpy(buf, cp_start, len);
        buf[len] = '\0';
        rc = settings_line_parse(buf, &name_str, &val_str);
        if (rc) {
            cp_start += (len + 1);
            continue;
        }

        if (strcmp(name_str, cdca->name)) {
            cp_start += (len + 1);
            continue;
        }

        if (cdca->val && !strcmp(val_str, cdca->val)) {
            cdca->is_dup = 1;
            return 0;
        } else {
            cdca->is_dup = 0;
        }

        cp_start += (len + 1);
    }

    return 0;
}

#endif /* CONFIG_BT_MESH_SETTINGS */
