/*
 * This file is part of SID.
 *
 * Copyright (C) 2017-2018 Red Hat, Inc. All rights reserved.
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

#ifndef _SID_KV_STORE_DB_H
#define _SID_KV_STORE_DB_H

#include "resource/kv-store.h"
#include "resource/resource.h"

#include <lmdb.h>
#include <sys/uio.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Returns:
 *   0 to keep old_data
 *   1 to update old_data with new_data
 */
typedef int (*kv_store_update_fn_db_t)(struct kv_store_update_spec *update_spec);

void *kv_store_set_value_db(sid_resource_t *          kv_store_res,
                            const char *              key,
                            void *                    value,
                            size_t                    value_size,
                            kv_store_value_flags_t    flags,
                            kv_store_value_op_flags_t op_flags,
                            kv_store_update_fn_db_t   kv_update_fn,
                            void *                    kv_update_fn_arg);
/*
 * Gets value for given key.
 *   - If value_size is not NULL, the function returns the size of the value through this output argument.
 *   - If flags is not NULL, the function returns the flags attached to the value through this output argument.
 */
void *kv_store_get_value_db(sid_resource_t *kv_store_res, const char *key, size_t *value_size, kv_store_value_flags_t *flags);

/*
 * Unsets value for given key.
 *   - Before the value is actually unset, unset_resolver with unset_resolver_arg is called to confirm the action.
 *
 * Returns:
 *    0 if value unset
 *   -1 if value not unset
 */
int kv_store_unset_value_db(sid_resource_t *        kv_store_res,
                            const char *            key,
                            kv_store_update_fn_db_t kv_unset_fn,
                            void *                  kv_unset_fn_arg);

size_t kv_store_get_size_db(sid_resource_t *kv_store_res, size_t *meta_size, size_t *data_size);

typedef struct kv_store_iter kv_store_iter_t;

kv_store_iter_t *kv_store_iter_create_db(sid_resource_t *kv_store_res);
int              kv_store_iter_current_size_db(kv_store_iter_t *iter,
                                               size_t *         int_size,
                                               size_t *         int_data_size,
                                               size_t *         ext_size,
                                               size_t *         ext_data_size);
void *           kv_store_iter_current_db(kv_store_iter_t *iter, size_t *size, kv_store_value_flags_t *flags);
void *           kv_store_iter_next_db(kv_store_iter_t *iter, size_t *size, const char **return_key, kv_store_value_flags_t *flags);
void             kv_store_iter_reset_db(kv_store_iter_t *iter);
const char *     kv_store_iter_current_key_db(kv_store_iter_t *iter);
size_t           kv_store_num_entries_db(sid_resource_t *kv_store_res);
void             kv_store_iter_destroy_db(kv_store_iter_t *iter);

#ifdef __cplusplus
}
#endif

#endif
