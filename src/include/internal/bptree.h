/*
 * SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _SID_BPTREE_H
#define _SID_BPTREE_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct bptree      bptree_t;
typedef struct bptree_iter bptree_iter_t;

typedef enum {
	BPTREE_UPDATE_SKIP,   /* skip new value (keep old value) */
	BPTREE_UPDATE_WRITE,  /* write new value (overwrite old value) */
	BPTREE_UPDATE_REMOVE, /* remove old value */
} bptree_update_action_t;

/*
 * bptree_update_fn_t callback type to define bptree_update's bptree_update_fn callback function.
 * Function of this type returns:
 *      0 for bptree to keep old data
 *      1 for bptree to update old_data with new_data (new_data may be modified and/or newly allocated by this function)
 */
typedef bptree_update_action_t (*bptree_update_cb_fn_t)(const char *key,
                                                        void       *old_data,
                                                        size_t      old_data_size,
                                                        unsigned    old_data_ref_count,
                                                        void      **new_data,
                                                        size_t     *new_data_size,
                                                        void       *arg);

typedef void (
	*bptree_iterate_fn_t)(const char *key, void *data, size_t data_size, unsigned data_ref_count, void *bptree_iterate_fn_arg);

bptree_t *bptree_create(int order);
int       bptree_add(bptree_t *bptree, const char *key, void *data, size_t data_size);
int       bptree_add_alias(bptree_t *bptree, const char *key, const char *alias, bool force);
int       bptree_update(bptree_t             *bptree,
                        const char           *key,
                        void                **data,
                        size_t               *data_size,
                        bptree_update_cb_fn_t bptree_update_fn,
                        void                 *bptree_update_fn_arg);
int       bptree_del(bptree_t *bptree, const char *key);
void     *bptree_lookup(bptree_t *bptree, const char *key, size_t *data_size, unsigned *data_ref_count);
int       bptree_get_height(bptree_t *bptree);
size_t    bptree_get_size(bptree_t *bptree, size_t *meta_size, size_t *data_size);
size_t    bptree_get_entry_count(bptree_t *bptree);
int       bptree_destroy(bptree_t *bptree);
int       bptree_destroy_with_fn(bptree_t *bptree, bptree_iterate_fn_t fn, void *fn_arg);

void bptree_iter(bptree_t *bptree, const char *key_start, const char *key_end, bptree_iterate_fn_t fn, void *fn_arg);

bptree_iter_t *bptree_iter_create(bptree_t *bptree, const char *key_start, const char *key_end);
bptree_iter_t *bptree_iter_create_prefix(bptree_t *bptree, const char *prefix);
void          *bptree_iter_current(bptree_iter_t *iter, const char **key, size_t *data_size, unsigned *data_ref_count);
const char    *bptree_iter_current_key(bptree_iter_t *iter);
void          *bptree_iter_next(bptree_iter_t *iter, const char **key, size_t *data_size, unsigned *data_ref_count);
void           bptree_iter_reset(bptree_iter_t *iter, const char *key_start, const char *key_end);
void           bptree_iter_reset_prefix(bptree_iter_t *iter, const char *prefix);
void           bptree_iter_destroy(bptree_iter_t *iter);

#ifdef __cplusplus
}
#endif

#endif
