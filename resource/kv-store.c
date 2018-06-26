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

#include "configure.h"
#include "hash.h"
#include "kv-store.h"
#include "log.h"
#include "mem.h"
#include "resource.h"

#include <limits.h>
#include <stdio.h>

#define KV_STORE_NAME "kv-store"

const sid_resource_reg_t sid_resource_reg_kv_store_hash;

struct kv_store {
	struct hash_table *ht;
};

struct kv_store_item {
	size_t size;
	int is_copy;
	union {
		void *data_p;
		char data[0];
	};
};

struct dup_key_resolver_arg {
	const char *key_prefix;
	const char *key;
	kv_resolver_t dup_key_resolver;
	void *dup_key_resolver_arg;
	int written;
};

struct kv_store_iter {
	struct kv_store *store;
	struct hash_node *current;
};

static const char *_get_full_key(char *buf, size_t buf_size, const char *key_prefix, const char *key)
{
	int size;

	if (key_prefix && *key_prefix) {
		size = snprintf(buf, buf_size, "%s%s%s", key_prefix, KV_STORE_KEY_JOIN, key);
		if (size < 0 || (size > buf_size))
			return NULL;
		return buf;
	}

	return key;
}

static void *_get_data(struct kv_store_item *item)
{
	return item->is_copy ? item->data : item->data_p;
}

static int _hash_dup_key_resolver(const char *key, uint32_t key_len, struct kv_store_item *old, struct kv_store_item *new,
				  struct dup_key_resolver_arg *arg)
{
	struct kv_store_item *item_to_free;
	int r;

	item_to_free = (r = arg->dup_key_resolver(arg->key_prefix, arg->key, _get_data(old), _get_data(new), arg->dup_key_resolver_arg)) ? old : new;
	free(item_to_free);

	arg->written = r;
	return r;
}

static struct kv_store_item *_create_kv_store_item(struct iovec *iov, int iov_cnt, int single, int copy)
{
	struct kv_store_item *item;
	size_t data_size = 0;
	char *p;
	int i;

	if (copy) {
		for (i = 0; i < iov_cnt; i++)
			data_size += iov[i].iov_len;

		if (!(item = malloc(sizeof(*item) + data_size))) {
			errno = ENOMEM;
			return NULL;
		}

		for (i = 0, p = item->data; i < iov_cnt; i++) {
			memcpy(p, iov[i].iov_base, iov[i].iov_len);
			p += iov[i].iov_len;
		}

		item->size = data_size;
		item->is_copy = 1;
	} else {
		if (!(item = malloc(sizeof(*item)))) {
			errno = ENOMEM;
			return NULL;
		}

		if (single) {
			item->data_p = iov[0].iov_base;
			item->size = iov[0].iov_len;
		} else {
			item->data_p = iov;
			item->size = iov_cnt;
		}

		item->is_copy = 0;
	}

	return item;
}

void *kv_store_set_value(sid_resource_t *kv_store_res, const char *key_prefix, const char *key,
			 void *value, size_t value_size, int copy,
			 kv_resolver_t dup_key_resolver, void *dup_key_resolver_arg)
{
	struct dup_key_resolver_arg hash_dup_key_resolver_arg = {.key_prefix = key_prefix,
								 .key = key,
								 .dup_key_resolver = dup_key_resolver,
								 .dup_key_resolver_arg = dup_key_resolver_arg,
								 .written = 1};
	struct kv_store *kv_store = sid_resource_get_data(kv_store_res);
	char buf[PATH_MAX];
	const char *full_key;
	struct kv_store_item *item;
	struct iovec iov = {.iov_base = value, .iov_len = value_size};

	if (!(full_key = _get_full_key(buf, sizeof(buf), key_prefix, key))) {
		errno = ENOKEY;
		return NULL;
	}

	if (!(item = _create_kv_store_item(&iov, 1, 1, copy)))
		return NULL;

	if (hash_update_binary(kv_store->ht, full_key, strlen(full_key) + 1, item,
			       (hash_dup_key_resolver_t) _hash_dup_key_resolver, &hash_dup_key_resolver_arg)) {
		errno = EIO;
		return NULL;
	}

	if (hash_dup_key_resolver_arg.written != 1) {
		errno = EADV;
		return NULL;
	}

	return item->data;
}

void *kv_store_set_value_from_vector(sid_resource_t *kv_store_res, const char *key_prefix, const char *key,
				     struct iovec *iov, int iov_cnt, int copy,
				     kv_resolver_t dup_key_resolver, void *dup_key_resolver_arg)
{
	struct dup_key_resolver_arg hash_dup_key_resolver_arg = {.key_prefix = key_prefix,
								 .key = key,
								 .dup_key_resolver = dup_key_resolver,
								 .dup_key_resolver_arg = dup_key_resolver_arg,
								 .written = 1};
	struct kv_store *kv_store = sid_resource_get_data(kv_store_res);
	char buf[PATH_MAX];
	const char *full_key;
	struct kv_store_item *item;

	if (!(full_key = _get_full_key(buf, sizeof(buf), key_prefix, key))) {
		errno = ENOKEY;
		return NULL;
	}

	if (!(item = _create_kv_store_item(iov, iov_cnt, 0, copy)))
		return NULL;

	if (hash_update_binary(kv_store->ht, full_key, strlen(full_key) + 1, item,
			       (hash_dup_key_resolver_t) _hash_dup_key_resolver, &hash_dup_key_resolver_arg)) {
		errno = EIO;
		return NULL;
	}

	if (hash_dup_key_resolver_arg.written != 1) {
		errno = EADV;
		return NULL;
	}

	return item->data;
}

void *kv_store_get_value(sid_resource_t *kv_store_res, const char *key_prefix, const char *key, size_t *value_size)
{
	struct kv_store *kv_store = sid_resource_get_data(kv_store_res);
	char buf[PATH_MAX];
	const char *full_key;
	struct kv_store_item *found;

	if (!(full_key = _get_full_key(buf, sizeof(buf), key_prefix, key))) {
		errno = ENOKEY;
		return NULL;
	}

	if (!(found = hash_lookup(kv_store->ht, full_key))) {
		errno = ENODATA;
		return NULL;
	}

	if (value_size)
		*value_size = found->size;

	if (found->is_copy)
		return found->data;

	return found->data_p;
}

int kv_store_unset_value(sid_resource_t *kv_store_res, const char *key_prefix, const char *key,
			 kv_resolver_t unset_resolver, void *unset_resolver_arg)
{
	struct kv_store *kv_store = sid_resource_get_data(kv_store_res);
	char buf[PATH_MAX];
	const char *full_key;
	struct kv_store_item *found;

	if (!(full_key = _get_full_key(buf, sizeof(buf), key_prefix, key))) {
		errno = ENOKEY;
		return -1;
	}

	/*
	 * FIXME: hash_lookup and hash_remove are two searches inside hash - maybe try to do
	 *        this in one step (...that requires hash interface extension).
	 */
	if (!(found = hash_lookup(kv_store->ht, full_key))) {
		errno = ENODATA;
		return -1;
	}

	if (unset_resolver && !unset_resolver(key_prefix, key, found->is_copy ? found->data : found->data_p, NULL, unset_resolver_arg)) {
		errno = EADV;
		return -1;
	}

	if (found->is_copy)
		free(found);

	hash_remove(kv_store->ht, full_key);

	return 0;
}

kv_store_iter_t *kv_store_iter_create(sid_resource_t *kv_store_res)
{
	kv_store_iter_t *iter;

	if (!(iter = malloc(sizeof(*iter))))
		return NULL;

	iter->store = sid_resource_get_data(kv_store_res);
	iter->current = NULL;

	return iter;
}

void *kv_store_iter_current(kv_store_iter_t *iter, size_t *size)
{
	struct kv_store_item *item;

	if (!(item = iter->current ? hash_get_data(iter->store->ht, iter->current) : NULL))
		return NULL;

	if (size)
		*size = item->size;
	return item->data;
}

const char *kv_store_iter_current_key(kv_store_iter_t *iter)
{
	return iter->current ? hash_get_key(iter->store->ht, iter->current) : NULL;
}

void *kv_store_iter_next(kv_store_iter_t *iter, size_t *size)
{
	iter->current = iter->current ? hash_get_next(iter->store->ht, iter->current)
				      : hash_get_first(iter->store->ht);

	return kv_store_iter_current(iter, size);
}

void kv_store_iter_reset(kv_store_iter_t *iter)
{
	iter->current = NULL;
}

void kv_store_iter_destroy(kv_store_iter_t *iter)
{
	free(iter);
}

static int _init_kv_store(sid_resource_t *kv_store_res, const void *kickstart_data, void **data)
{
	const struct sid_kv_store_resource_params *params = kickstart_data;
	struct kv_store *kv_store;

	if (!(kv_store = zalloc(sizeof(*kv_store)))) {
		log_error(ID(kv_store_res), "Failed to allocate key-value store structure.");
		goto out;
	}

	if (!(kv_store->ht = hash_create(params->hash.initial_size))) {
		log_error(ID(kv_store_res), "Failed to create hash table for key-value store.");
		goto out;
	}

	*data = kv_store;
	return 0;
out:
	if (kv_store) {
		if (kv_store->ht)
			hash_destroy(kv_store->ht);
		free(kv_store);
	}
	return -1;
}

static int _destroy_kv_store(sid_resource_t *kv_store_res)
{
	struct kv_store *kv_store = sid_resource_get_data(kv_store_res);

	hash_iter(kv_store->ht, (hash_iterate_fn) free);
	hash_destroy(kv_store->ht);
	free(kv_store);

	return 0;
}

const sid_resource_reg_t sid_resource_reg_kv_store = {
	.name = KV_STORE_NAME,
	.init = _init_kv_store,
	.destroy = _destroy_kv_store,
};
