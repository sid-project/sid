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

#ifndef _SID_KV_STORE_H
#define _SID_KV_STORE_H

#include "resource.h"

#include <sys/uio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KV_STORE_KEY_JOIN ":"

typedef enum {
	KV_STORE_BACKEND_HASH,
} kv_store_backend_t;

struct kv_store_hash_backend_params {
	size_t initial_size;
};

struct sid_kv_store_resource_params {
	kv_store_backend_t backend;
	union {
		struct kv_store_hash_backend_params hash;
	};
};

/*
 * Returns:
 *   0 to keep old_data
 *   1 to update old_data with new_data
 */
typedef int (*kv_dup_key_resolver_t) (const char *key_prefix, const char *key, void *old_value, void *new_value, void *arg);

/*
 * Sets key-value pair:
 *   - Final key is composed of key_prefix and key.
 *   - If copy is set, the value is first copied and the copy is used as the value which is stored.
 *   - If the key exists already, dup_key_resolver with dup_key_resolver_arg argument is called for resolution.
 *
 * Returns:
 *   The value that has been set.
 */
void *kv_store_set_value(struct sid_resource *kv_store_res, const char *key_prefix, const char *key,
			 void *value, size_t value_size, int copy,
			 kv_dup_key_resolver_t dup_key_resolver, void *dup_key_resolver_arg);

/*
 * Sets key-value pair, value components given by vector:
 *   - Final key is composed of key_prefix and key.
 *   - If copy is set, the vector items are merged together and copied as a single value which is then stored.
 *   - If the key existst already, dup_key_resolver with dup_key_resolver_arg argument is called for resolution.
 *
 * Returns:
 *   The value that has been set.
 */
void *kv_store_set_value_from_vector(struct sid_resource *kv_store_res, const char *key_prefix, const char *key,
				     struct iovec *iov, int iov_cnt, int copy,
				     kv_dup_key_resolver_t dup_key_resolver, void *dup_key_resolver_arg);

/*
 * Gets value for given key.
 *   - Final key is composed of key_prefix and key.
 *   - If value_size is not NULL, the function returns the size of the value through this output argument.
 */
void *kv_store_get_value(struct sid_resource *kv_store_res, const char *key_prefix, const char *key, size_t *value_size);

int kv_store_unset_value(struct sid_resource *kv_store_res, const char *key_prefix, const char *key);

typedef struct kv_store_iter kv_store_iter_t;

kv_store_iter_t *kv_store_iter_create(sid_resource_t *kv_store_res);
const char *kv_store_iter_current_key(kv_store_iter_t *iter);
void *kv_store_iter_current(kv_store_iter_t *iter, size_t *size);
void *kv_store_iter_next(kv_store_iter_t *iter, size_t *size);
void kv_store_iter_reset(kv_store_iter_t *iter);
void kv_store_iter_destroy(kv_store_iter_t *iter);

#ifdef __cplusplus
}
#endif

#endif
