/*
 * Copyright (c) 2018 Nordic Semiconductor ASA
 * Copyright (c) 2015 Runtime Inc
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _BLE_MESH_SETTINGS_H_
#define _BLE_MESH_SETTINGS_H_

#include <stdint.h>

#include "mesh_util.h"
#include "mesh_slist.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SETTINGS_MAX_DIR_DEPTH      8   /* max depth of settings tree */
#define SETTINGS_MAX_NAME_LEN       (8 * SETTINGS_MAX_DIR_DEPTH)
#define SETTINGS_MAX_VAL_LEN        256
#define SETTINGS_NAME_SEPARATOR     "/"

/* pleace for settings additions:
 * up to 7 separators, '=', '\0'
 */
#define SETTINGS_EXTRA_LEN          ((SETTINGS_MAX_DIR_DEPTH - 1) + 2)

/**
 * @struct settings_handler
 * Config handlers for subtree implement a set of handler functions.
 * These are registered using a call to settings_register().
 *
 * @param settings_handler::node Linked list node info for module internal usage.
 *
 * @param settings_handler::name Name of subtree.
 *
 * @param settings_handler::h_set Sey value handler of settings items
 * identified by keyword names. Parameters:
 *  - argc - count of item in argv, argv - array of pointers to keyword names.
 *  - val- pointer to value to be set.
 *
 * @param settings_handler::h_commit This handler gets called after settings
 * has been loaded in full. User might use it to apply setting to
 * the application.
 *
 * @remarks The User might limit a implementations of handler to serving only
 * one keyword at one call - what will impose limit to get/set values using full
 * subtree/key name.
 */
struct settings_handler {
    sys_snode_t node;
    char *name;
    int (*h_set)(int argc, char **argv, char *val);
    int (*h_commit)(void);
};

/**
 * Initialization of settings and backend
 *
 * Can be called at application startup.
 * In case the backend is NFFS Remember to call it after FS was mounted.
 * For FCB backend it can be called without such a restriction.
 *
 * @return 0 on success, non-zero on failure.
 */
int settings_subsys_init(void);

/**
 * Register a handler for settings items.
 *
 * @param cf Structure containing registration info.
 *
 * @return 0 on success, non-zero on failure.
 */
int settings_register(struct settings_handler *cf);

/**
 * Load serialized items from registered persistence sources. Handlers for
 * serialized item subtrees registered earlier will be called for encountered
 * values.
 *
 * @return 0 on success, non-zero on failure.
 */
int settings_load(void);

/**
 * Write a single serialized value to persisted storage (if it has
 * changed value).
 *
 * @param name Name/key of the settings item.
 * @param var Value of the settings item.
 *
 * @return 0 on success, non-zero on failure.
 */
int settings_save_one(const char *name, char *var);

/**
 * Set settings item identified by @p name to be value @p val_str.
 * This finds the settings handler for this subtree and calls it's
 * set handler.
 *
 * @param name Name/key of the settings item.
 * @param val_str Value of the settings item.
 *
 * @return 0 on success, non-zero on failure.
 */
int settings_set_value(char *name, char *val_str);

/**
 * Call commit for all settings handler. This should apply all
 * settings which has been set, but not applied yet.
 *
 * @return 0 on success, non-zero on failure.
 */
int settings_commit(void);

/**
 * Convenience routine for converting byte array passed as a base64
 * encoded string.
 *
 * @param val_str Value of the settings item as string.
 * @param vp Pointer to variable to fill with the decoded value.
 * @param len Size of that variable. On return the number of bytes in the array.
 *
 * @return 0 on success, non-zero on failure.
 */
int settings_bytes_from_str(char *val_str, void *vp, int *len);

/**
 * Convenience routine for converting byte array into a base64
 * encoded string.
 *
 * @param vp Pointer to variable to convert.
 * @param vp_len Number of bytes to convert.
 * @param buf Buffer where string value will be stored.
 * @param buf_len Size of the buffer.
 *
 * @return 0 on success, non-zero on failure.
 */
char *settings_str_from_bytes(void *vp, int vp_len, char *buf, int buf_len);

struct settings_store_itf;
struct settings_store {
    sys_snode_t cs_next;
    const struct settings_store_itf *cs_itf;
};

#ifdef __cplusplus
}
#endif

#endif /* _BLE_MESH_SETTINGS_H_ */
