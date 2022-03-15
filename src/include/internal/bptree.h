/*
 * This file is part of SID.
 *
 * Copyright (C) 2022 Red Hat, Inc. All rights reserved.
 *
 * SID is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * SID is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with SID.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _SID_BPTREE_H
#define _SID_BPTREE_H

#include "internal/common.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct bptree      bptree_t;
typedef struct bptree_iter bptree_iter_t;

/*
 * bptree_update_fn_t callback type to define bptree_update's bptree_update_fn callback function.
 * Function of this type returns:
 *      0 for bptree to keep old data
 *      1 for bptree to update old_data with new_data (new_data may be modified and/or newly allocated by this function)
 */
typedef int (*bptree_update_fn_t)(const char *key,
                                  void *      old_data,
                                  size_t      old_data_size,
                                  void **     new_data,
                                  size_t *    new_data_size,
                                  void *      bptree_update_fn_arg);

bptree_t *bptree_create(int order);
int       bptree_insert(bptree_t *bptree, const char *key, void *data, size_t data_size);
int       bptree_update(bptree_t *         bptree,
                        const char *       key,
                        void **            data,
                        size_t *           data_size,
                        bptree_update_fn_t bptree_update_fn,
                        void *             bptree_update_fn_arg);
int       bptree_remove(bptree_t *bptree, const char *key);
void *    bptree_lookup(bptree_t *bptree, const char *key, size_t *data_size);
int       bptree_height(bptree_t *bptree);
int       bptree_destroy(bptree_t *bptree);

bptree_iter_t *bptree_iter_create(bptree_t *bptree, const char *key_start, const char *key_end);
void *         bptree_iter_current(bptree_iter_t *iter, size_t *data_size, const char **key);
const char *   bptree_iter_current_key(bptree_iter_t *iter);
void *         bptree_iter_next(bptree_iter_t *iter, size_t *data_size, const char **key);
void           bptree_iter_reset(bptree_iter_t *iter, const char *key_start, const char *key_end);
void           bptree_iter_destroy(bptree_iter_t *iter);

#ifdef __cplusplus
}
#endif

#endif
