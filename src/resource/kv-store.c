/*
 * This file is part of SID.
 *
 * Copyright (C) 2017-2020 Red Hat, Inc. All rights reserved.
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

#include "resource/kv-store.h"

#include "internal/hash.h"
#include "internal/mem.h"
#include "log/log.h"
#include "resource/kv-store-db.h"
#include "resource/kv-store-ht.h"
#include "resource/resource.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>

void *kv_store_set_value(sid_resource_t *          kv_store_res,
                         const char *              key,
                         void *                    value,
                         size_t                    value_size,
                         kv_store_value_flags_t    flags,
                         kv_store_value_op_flags_t op_flags,
                         kv_store_update_fn_t      kv_update_fn,
                         void *                    kv_update_fn_arg)
{
	struct kv_store *kv_store = sid_resource_get_data(kv_store_res);

	switch (kv_store->backend) {
		case KV_STORE_BACKEND_HASH:
			return kv_store_set_value_ht(kv_store_res,
			                             key,
			                             value,
			                             value_size,
			                             flags,
			                             op_flags,
			                             kv_update_fn,
			                             kv_update_fn_arg);
		case KV_STORE_BACKEND_LMDB:
			return kv_store_set_value_db(kv_store_res,
			                             key,
			                             value,
			                             value_size,
			                             flags,
			                             op_flags,
			                             kv_update_fn,
			                             kv_update_fn_arg);
	}
	log_error(ID(kv_store_res), "kv_store_set_value: unsupported backend.");
	return NULL;
}

void *kv_store_get_value(sid_resource_t *kv_store_res, const char *key, size_t *value_size, kv_store_value_flags_t *flags)
{
	struct kv_store *kv_store = sid_resource_get_data(kv_store_res);

	switch (kv_store->backend) {
		case KV_STORE_BACKEND_HASH:
			return kv_store_get_value_ht(kv_store_res, key, value_size, flags);
		case KV_STORE_BACKEND_LMDB:
			return kv_store_get_value_db(kv_store_res, key, value_size, flags);
	}
	log_error(ID(kv_store_res), "kv_store_get_value: unsupported backend.");
	return NULL;
}

int kv_store_unset_value(sid_resource_t *kv_store_res, const char *key, kv_store_update_fn_t kv_unset_fn, void *kv_unset_fn_arg)
{
	struct kv_store *kv_store = sid_resource_get_data(kv_store_res);

	switch (kv_store->backend) {
		case KV_STORE_BACKEND_HASH:
			return kv_store_unset_value_ht(kv_store_res, key, kv_unset_fn, kv_unset_fn_arg);
		case KV_STORE_BACKEND_LMDB:
			return kv_store_unset_value_db(kv_store_res, key, kv_unset_fn, kv_unset_fn_arg);
	}
	log_error(ID(kv_store_res), "kv_store_unset_value: unsupported backend.");
	return -1;
}

kv_store_iter_t *kv_store_iter_create(sid_resource_t *kv_store_res)
{
	struct kv_store *kv_store = sid_resource_get_data(kv_store_res);

	switch (kv_store->backend) {
		case KV_STORE_BACKEND_HASH:
			return kv_store_iter_create_ht(kv_store_res);
		case KV_STORE_BACKEND_LMDB:
			return kv_store_iter_create_db(kv_store_res);
	}
	log_error(ID(kv_store_res), "kv_store_iter_create: unsupported backend.");
	return NULL;
}

void *kv_store_iter_current(kv_store_iter_t *iter, size_t *size, kv_store_value_flags_t *flags)
{
	switch (iter->backend) {
		case KV_STORE_BACKEND_HASH:
			return kv_store_iter_current_ht(iter, size, flags);
		case KV_STORE_BACKEND_LMDB:
			return kv_store_iter_current_db(iter, size, flags);
	}
	log_error("kv-store", "kv_store_iter_current: unsupported backend.");
	return NULL;
}

int kv_store_iter_current_size(kv_store_iter_t *iter,
                               size_t *         int_size,
                               size_t *         int_data_size,
                               size_t *         ext_size,
                               size_t *         ext_data_size)
{
	switch (iter->backend) {
		case KV_STORE_BACKEND_HASH:
			return kv_store_iter_current_size_ht(iter, int_size, int_data_size, ext_size, ext_data_size);
		case KV_STORE_BACKEND_LMDB:
			return kv_store_iter_current_size_db(iter, int_size, int_data_size, ext_size, ext_data_size);
	}
	log_error("kv-store", "kv_store_iter_current_size: unsupported backend.");
	return -1;
}

const char *kv_store_iter_current_key(kv_store_iter_t *iter)
{
	switch (iter->backend) {
		case KV_STORE_BACKEND_HASH:
			return kv_store_iter_current_key_ht(iter);
		case KV_STORE_BACKEND_LMDB:
			return kv_store_iter_current_key_db(iter);
	}
	log_error("kv-store", "kv_store_iter_current_key: unsupported backend.");
	return NULL;
}

void *kv_store_iter_next(kv_store_iter_t *iter, size_t *size, const char **return_key, kv_store_value_flags_t *flags)
{
	switch (iter->backend) {
		case KV_STORE_BACKEND_HASH:
			return kv_store_iter_next_ht(iter, size, return_key, flags);
		case KV_STORE_BACKEND_LMDB:
			return kv_store_iter_next_db(iter, size, return_key, flags);
	}
	log_error("kv-store", "kv_store_iter_next: unsupported backend.");
	return NULL;
}

void kv_store_iter_reset(kv_store_iter_t *iter)
{
	switch (iter->backend) {
		case KV_STORE_BACKEND_HASH:
			return kv_store_iter_reset_ht(iter);
		case KV_STORE_BACKEND_LMDB:
			return kv_store_iter_reset_db(iter);
	}
	log_error("kv-store", "kv_store_iter_reset: unsupported backend.");
}

void kv_store_iter_destroy(kv_store_iter_t *iter)
{
	switch (iter->backend) {
		case KV_STORE_BACKEND_HASH:
			return kv_store_iter_destroy_ht(iter);
		case KV_STORE_BACKEND_LMDB:
			return kv_store_iter_destroy_db(iter);
	}
	log_error("kv-store", "kv_store_iter_destroy: unsupported backend.");
}

size_t kv_store_num_entries(sid_resource_t *kv_store_res)
{
	struct kv_store *kv_store = sid_resource_get_data(kv_store_res);

	switch (kv_store->backend) {
		case KV_STORE_BACKEND_HASH:
			return kv_store_num_entries_ht(kv_store_res);
		case KV_STORE_BACKEND_LMDB:
			return kv_store_num_entries_db(kv_store_res);
	}
	log_error(ID(kv_store_res), "kv_store_num_entries: unsupported backend.");
	return 0;
}

size_t kv_store_get_size(sid_resource_t *kv_store_res, size_t *meta_size, size_t *data_size)
{
	struct kv_store *kv_store = sid_resource_get_data(kv_store_res);

	switch (kv_store->backend) {
		case KV_STORE_BACKEND_HASH:
			return kv_store_get_size_ht(kv_store_res, meta_size, data_size);
		case KV_STORE_BACKEND_LMDB:
			return kv_store_get_size_db(kv_store_res, meta_size, data_size);
	}
	log_error(ID(kv_store_res), "kv_store_get_size: unsupported backend.");
	return 0;
}