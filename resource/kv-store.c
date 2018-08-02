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

#define KV_STORE_VALUE_INT_MERGED UINT32_C(0x00000001)

const sid_resource_reg_t sid_resource_reg_kv_store_hash;

struct kv_store {
	struct hash_table *ht;
};

struct kv_store_item {
	size_t size;
	uint32_t int_flags;
	uint32_t ext_flags;
	union {
		void *data_p;
		char data[0];
	};
};

struct kv_update_fn_relay {
	const char *key_prefix;
	const char *key;
	kv_store_update_fn_t kv_update_fn;
	void *kv_update_fn_arg;
	int updated;
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
	if (!item)
		return NULL;

	return item->ext_flags & KV_STORE_VALUE_REF ? item->data_p : item->data;
}

static void _destroy_kv_store_item(struct kv_store_item *item)
{
	struct iovec *iov;
	size_t i;

	if (!item)
		return;

	/* Take extra care of situations where we store reference to a value. */
	if (item->ext_flags & KV_STORE_VALUE_REF) {
		if (item->ext_flags & KV_STORE_VALUE_VECTOR) {
			/* vector value */
			iov = item->data_p;

			if (item->int_flags & KV_STORE_VALUE_INT_MERGED)
				/* vector value has been merged */
				free(iov[0].iov_base);

			if (item->ext_flags & KV_STORE_VALUE_AUTOFREE)
				free(item->data_p);
			else {
				/*
				 * If not autofreeing, at least zero out the vector content
				 * so it doesn't point to non-existent records.
				 */
				for (i = 0; i < item->size; i++) {
					iov[0].iov_base = NULL;
					iov[0].iov_len = 0;
				}
			}
		} else {
			/* single value */
			if (item->ext_flags & KV_STORE_VALUE_AUTOFREE)
				/* autofree requested */
				free(item->data_p);
		}
	}

	/*
	 * If the value stored is not a reference, it's stored as copy and
	 * part of item->data[] field allocated together with the item itself.
	 * Then it's freed just by calling free(item).
	 */

	free(item);
}

/*
 *       FLAG     OP_FLAG         INPUT                        OUTPUT
 *         |         |              |                            |
 *     ---------    ---    ---------------------    -------------------------------
 *    /         \  /   \  /                     \  /                               \
 * #  VECTOR  REF  MERGE  INPUT_VALUE  INPUT_SIZE  OUTPUT_VALUE           OUTPUT_SIZE  NOTE
 * ---------------------------------------------------------------------------------------------------------------------------------------------------------------
 * A    0      0     0    value ref    value size  value copy ref         value size
 * B    0      0     1    value ref    value size  value copy ref         value size   merge flag has no effect: B == A
 * C    0      1     0    value ref    value size  value ref              value size
 * D    0      1     1    value ref    value size  value ref              value size   merge flag has no effect: D == C
 * E    1      0     0    iovec ref    iovec size  iovec deep copy ref    iovec size
 * F    1      0     1    iovec ref    iovec size  value merger ref       value size   iovec members merged into single value
 * G    1      1     0    iovec ref    iovec size  iovec ref              iovec size
 * H    1      1     1    iovec ref    iovec size  value merger iovec ref iovec size   iovec members merged into single value, iovec has refs to merged value parts
 */
static struct kv_store_item *_create_kv_store_item(struct iovec *iov, int iov_cnt, uint32_t flags, uint64_t op_flags)
{
	struct kv_store_item *item;
	size_t data_size;
	char *p1, *p2;
	struct iovec *iov2;
	int i;

	if (flags & KV_STORE_VALUE_VECTOR) {
		if (flags & KV_STORE_VALUE_REF) {
			if (!(item = malloc(sizeof(*item)))) {
				errno = ENOMEM;
				return NULL;
			}

			if (op_flags & KV_STORE_VALUE_OP_MERGE) {
				/* H */
				for (i = 0, data_size = 0; i < iov_cnt; i++)
					data_size += iov[i].iov_len;

				if (!(p1 = malloc(data_size))) {
					free(item);
					errno = ENOMEM;
					return NULL;
				}

				for (i = 0, p2 = p1; i < iov_cnt; i++) {
					memcpy(p2, iov[i].iov_base, iov[i].iov_len);
					iov[i].iov_base = p2;
					p2 += iov[i].iov_len;
				}

				item->data_p = iov;
				item->size = iov_cnt;
				item->int_flags = KV_STORE_VALUE_INT_MERGED;
			} else {
				/* G */
				item->data_p = iov;
				item->size = iov_cnt;
			}
		} else {
			for (i = 0, data_size = 0; i < iov_cnt; i++)
				data_size += iov[i].iov_len;

			if (flags & KV_STORE_VALUE_OP_MERGE) {
				/* F */
				if (!(item = malloc(sizeof(*item) + data_size))) {
					errno = ENOMEM;
					return NULL;
				}

				for (i = 0, p1 = item->data; i < iov_cnt; i++) {
					memcpy(p1, iov[i].iov_base, iov[i].iov_len);
					p1 += iov[i].iov_len;
				}

				item->size = data_size;
				flags &= ~KV_STORE_VALUE_VECTOR;
				item->int_flags = KV_STORE_VALUE_INT_MERGED;
			} else {
				/* E */
				if (!(item = malloc(sizeof(*item) + iov_cnt * sizeof(struct iovec) + data_size))) {
					errno = ENOMEM;
					return NULL;
				}

				iov2 = (struct iovec *) item->data;
				p1 = item->data + iov_cnt * sizeof(struct iovec);

				for (i = 0; i < iov_cnt; i++) {
					memcpy(p1, iov[i].iov_base, iov[i].iov_len);
					iov2[i].iov_base = p1;
					iov2[i].iov_len = iov[i].iov_len;
					p1 += iov[i].iov_len;
				}

				item->size = iov_cnt;
				item->int_flags = KV_STORE_VALUE_INT_MERGED;
			}
		}
	} else {
		if (flags & KV_STORE_VALUE_REF) {
			/* C,D */
			if (!(item = malloc(sizeof(*item)))) {
				errno = ENOMEM;
				return NULL;
			}
			item->data_p = iov[0].iov_base;
		} else {
			/* A,B */
			if (!(item = malloc(sizeof(*item) + iov[0].iov_len))) {
				errno = ENOMEM;
				return NULL;
			}
			memcpy(item->data, iov[0].iov_base, iov[0].iov_len);
		}

		item->size = iov[0].iov_len;
	}

	item->ext_flags = flags;
	return item;
}

static int _hash_update_fn(const char *key, uint32_t key_len, struct kv_store_item *old, struct kv_store_item **new,
				  struct kv_update_fn_relay *relay)
{
	struct kv_store_item *orig_new_item;
	void *orig_new_value, *new_value;
	size_t orig_new_size, new_size;
	struct iovec iov_internal;
	int r = 1;

	if (relay->kv_update_fn) {
		orig_new_value = new_value = (new ? _get_data(*new) : NULL);
		orig_new_size = new_size = (new ? (*new) ? (*new)->size : 0 : 0);

		r = relay->kv_update_fn(relay->key_prefix, relay->key,
					_get_data(old), old ? old->size : 0,
					&new_value, &new_size,
					relay->kv_update_fn_arg);

		/* The kv_update_fn can modify/reallocate the new value, check if this is the case! */
		if ((r > 0) && ((new_value != orig_new_value) || (new_size != orig_new_size))) {
			/* new value has been modified/reallocated by kv_update_fn */
			if ((*new)->ext_flags & KV_STORE_VALUE_REF) {
				/*
				 * If kv_store_item stores value as reference, we only need to rewrite
				 * the data_p pointer and size, no need to recreate the whole kv_store_item.
				 */
				(*new)->data_p = new_value;
				(*new)->size = new_size;
			} else {
				/*
				 * If kv_store_item stores value directly, we need to recreate
				 * the kv_store_item with new_value and new_size and copy across the flags.
				 * Then, destroy the original new kv_store_item.
				 */
				orig_new_item = *new;
				iov_internal.iov_base = new_value;
				iov_internal.iov_len = new_size;
				if (!(*new = _create_kv_store_item(&iov_internal, 1, orig_new_item->ext_flags, 0))) {
					relay->updated = -1;
					return 0;
				}
				_destroy_kv_store_item(orig_new_item);
			}
		}
	}

	if (r) {
		if (old)
			_destroy_kv_store_item(old);
	} else {
		_destroy_kv_store_item(*new);
		*new = NULL;
	}

	relay->updated = r;
	return r;
}

void *kv_store_set_value(sid_resource_t *kv_store_res, const char *key_prefix, const char *key,
			 void *value, size_t value_size, uint32_t flags, uint64_t op_flags,
			 kv_store_update_fn_t kv_update_fn, void *kv_update_fn_arg)
{
	struct kv_update_fn_relay relay = {.key_prefix = key_prefix,
					   .key = key,
					   .kv_update_fn = kv_update_fn,
					   .kv_update_fn_arg = kv_update_fn_arg,
					   .updated = 0};
	struct kv_store *kv_store = sid_resource_get_data(kv_store_res);
	char buf[PATH_MAX];
	const char *full_key;
	struct iovec iov_internal = {.iov_base = value, .iov_len = value_size};
	struct iovec *iov;
	int iov_cnt;
	struct kv_store_item *item;

	if (!(full_key = _get_full_key(buf, sizeof(buf), key_prefix, key))) {
		errno = ENOKEY;
		return NULL;
	}

	if (flags & KV_STORE_VALUE_VECTOR) {
		iov = value;
		iov_cnt = value_size;
	} else {
		iov = &iov_internal;
		iov_cnt = 1;
	}

	if (!(item = _create_kv_store_item(iov, iov_cnt, flags, op_flags)))
		return NULL;

	if (hash_update_binary(kv_store->ht, full_key, strlen(full_key) + 1, (void **) &item,
			       (hash_update_fn_t) _hash_update_fn, &relay)) {
		errno = EIO;
		return NULL;
	}

	if (relay.updated < 0) {
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

	return found->ext_flags & KV_STORE_VALUE_REF ? found->data_p : found->data;
}

int kv_store_unset_value(sid_resource_t *kv_store_res, const char *key_prefix, const char *key,
			 kv_store_update_fn_t kv_unset_fn, void *kv_unset_fn_arg)
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

	if (kv_unset_fn && !kv_unset_fn(key_prefix, key, _get_data(found), found->size, NULL, 0, kv_unset_fn_arg)) {
		errno = EADV;
		return -1;
	}

	_destroy_kv_store_item(found);
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

void *kv_store_iter_current(kv_store_iter_t *iter, size_t *size, uint32_t *flags)
{
	struct kv_store_item *item;

	if (!(item = iter->current ? hash_get_data(iter->store->ht, iter->current) : NULL))
		return NULL;

	if (size)
		*size = item->size;

	if (flags)
		*flags = item->ext_flags;

	return item->data;
}

const char *kv_store_iter_current_key(kv_store_iter_t *iter)
{
	return iter->current ? hash_get_key(iter->store->ht, iter->current) : NULL;
}

void *kv_store_iter_next(kv_store_iter_t *iter, size_t *size, uint32_t *flags)
{
	iter->current = iter->current ? hash_get_next(iter->store->ht, iter->current)
				      : hash_get_first(iter->store->ht);

	return kv_store_iter_current(iter, size, flags);
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

	hash_iter(kv_store->ht, (hash_iterate_fn) _destroy_kv_store_item);
	hash_destroy(kv_store->ht);
	free(kv_store);

	return 0;
}

const sid_resource_reg_t sid_resource_reg_kv_store = {
	.name = KV_STORE_NAME,
	.init = _init_kv_store,
	.destroy = _destroy_kv_store,
};
