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

#ifndef _SID_KV_STORE_HT_H
#define _SID_KV_STORE_HT_H

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
typedef int (*kv_store_update_fn_ht_t)(struct kv_store_update_spec *update_spec);

// clang-format off
/*
 * Sets key-value pair:
 *   - kv_update_fn callback with kv_update_fn_arg is called before updating the value.
 *   - Value and size depend on flags with KV_STORE_VALUE_ prefix, see table below.
 *     INPUT VALUE:  value as provided via kv_store_set_value's "value" argument.
 *     INPUT SIZE:   value size as provided via kv_store_set_value's "value_size" argument.
 *     OUTPUT VALUE: value as returned by kv_store_{set,get}_value.
 *     OUTPUT SIZE:  value size as returned by kv_store_get_value.
 *
 *  - Flag support depends on used backend.
 *
 *
 *                     INPUT                               OUTPUT (DB RECORD)                                  NOTES
 *                       |                                         |
 *           -------------------------                     -------------------
 *          /        |                \                   /                   \
 *        FLAGS   OP_FLAG            VALUE             FLAGS                 VALUE
 *          |        |                 |                 |                     |
 *        ----       |            ------------         -----          --------------------
 *       /    \      |           /            \       /     \        /                    \
 * #  VECTOR  REF  MERGE      VALUE        SIZE    VECTOR  REF     VALUE                  SIZE
 * ---------------------------------------------------------------------------------------------------------------------------------------------------------------
 * A     0     0     0     value ref    value size    0     0    value copy ref         value size
 * B     0     0     1     value ref    value size    0     0    value copy ref         value size   merge flag has no effect: B == A
 * C     0     1     0     value ref    value size    0     1    value ref              value size
 * D     0     1     1     value ref    value size    0     1    value ref              value size   merge flag has no effect: D == C
 * E     1     0     0     iovec ref    iovec size    1     0    iovec deep copy ref    iovec size   allocated both iovec copy and value parts
 * F     1     0     1     iovec ref    iovec size    0     0    value merger ref       value size   iovec members merged into single value
 * G     1     1     0     iovec ref    iovec size    1     1    iovec ref              iovec size
 * H     1     1     1     iovec ref    iovec size    1     1    value merger iovec ref iovec size   iovec members merged into single value, iovec has refs to merged value parts
 *
 *
 * The AUTOFREE flag may be used together with REF flag (it has no effect otherwise). Then, if the reference to the
 * value is not needed anymore due to an update or edit, there's "free" called automatically on such a reference.
 * Of course, this assumes that caller allocated the value (for which there's the reference) by "malloc".
 * For vectors, this also means that both the struct iovec and values reference by iovec.iov_base have
 * been allocated by "malloc" too.
 *
 *
 * Returns:
 *   The value that has been set.
 */
// clang-format on
void *kv_store_set_value_ht(sid_resource_t *          kv_store_res,
                            const char *              key,
                            void *                    value,
                            size_t                    value_size,
                            kv_store_value_flags_t    flags,
                            kv_store_value_op_flags_t op_flags,
                            kv_store_update_fn_ht_t   kv_update_fn,
                            void *                    kv_update_fn_arg);
/*
 * Gets value for given key.
 *   - If value_size is not NULL, the function returns the size of the value through this output argument.
 *   - If flags is not NULL, the function returns the flags attached to the value through this output argument.
 */
void *kv_store_get_value_ht(sid_resource_t *kv_store_res, const char *key, size_t *value_size, kv_store_value_flags_t *flags);

/*
 * Unsets value for given key.
 *   - Before the value is actually unset, unset_resolver with unset_resolver_arg is called to confirm the action.
 *
 * Returns:
 *    0 if value unset
 *   -1 if value not unset
 */
int kv_store_unset_value_ht(sid_resource_t *        kv_store_res,
                            const char *            key,
                            kv_store_update_fn_ht_t kv_unset_fn,
                            void *                  kv_unset_fn_arg);

size_t kv_store_get_size_ht(sid_resource_t *kv_store_res, size_t *meta_size, size_t *data_size);

typedef struct kv_store_iter kv_store_iter_t;

kv_store_iter_t *kv_store_iter_create_ht(sid_resource_t *kv_store_res);
int              kv_store_iter_current_size_ht(kv_store_iter_t *iter,
                                               size_t *         int_size,
                                               size_t *         int_data_size,
                                               size_t *         ext_size,
                                               size_t *         ext_data_size);
void *           kv_store_iter_current_ht(kv_store_iter_t *iter, size_t *size, kv_store_value_flags_t *flags);
const char *     kv_store_iter_current_key_ht(kv_store_iter_t *iter);
void *           kv_store_iter_next_ht(kv_store_iter_t *iter, size_t *size, const char **return_key, kv_store_value_flags_t *flags);
void             kv_store_iter_reset_ht(kv_store_iter_t *iter);
void             kv_store_iter_destroy_ht(kv_store_iter_t *iter);
size_t           kv_store_num_entries_ht(sid_resource_t *kv_store_res);
size_t           kv_store_get_size_ht(sid_resource_t *kv_store_res, size_t *meta_size, size_t *data_size);

#ifdef __cplusplus
}
#endif

#endif
