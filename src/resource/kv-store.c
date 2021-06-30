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
#include "resource/resource.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>

#define KV_STORE_NAME "kv-store"

typedef enum
{
	KV_STORE_VALUE_INT_ALLOC = UINT32_C(0x00000001),
} kv_store_value_int_flags_t;

struct kv_store {
	struct hash_table *ht;
};

struct kv_store_value {
	size_t                     size;
	kv_store_value_int_flags_t int_flags;
	kv_store_value_flags_t     ext_flags;
	char                       data[];
};

struct kv_update_fn_relay {
	const char *         key;
	kv_store_update_fn_t kv_update_fn;
	void *               kv_update_fn_arg;
	int                  ret_code;
};

struct kv_store_iter {
	struct kv_store * store;
	struct hash_node *current;
};

static void _set_ptr(void *dest, const void *p)
{
	memcpy(dest, (void *) &p, sizeof(intptr_t));
}

static void *_get_ptr(const void *src)
{
	intptr_t ptr;

	memcpy(&ptr, src, sizeof(ptr));
	return (void *) ptr;
}

static void *_get_data(struct kv_store_value *value)
{
	if (!value)
		return NULL;

	return value->ext_flags & KV_STORE_VALUE_REF ? _get_ptr(value->data) : value->data;
}

static void _destroy_kv_store_value(struct kv_store_value *value)
{
	struct iovec *iov;
	size_t        i;

	if (!value)
		return;

	/* Take extra care of situations where we store reference to a value. */
	if (value->ext_flags & KV_STORE_VALUE_REF) {
		if (value->ext_flags & KV_STORE_VALUE_VECTOR) {
			iov = _get_ptr(value->data);

			if (value->int_flags & KV_STORE_VALUE_INT_ALLOC) {
				/* H */
				free(iov[0].iov_base);
				if (value->ext_flags & KV_STORE_VALUE_AUTOFREE)
					free(iov);
				else
					for (i = 0; i < value->size; i++) {
						iov[i].iov_base = NULL;
						iov[i].iov_len  = 0;
					}
			} else if (value->ext_flags & KV_STORE_VALUE_AUTOFREE) {
				/* G */
				for (i = 0; i < value->size; i++)
					free(iov[i].iov_base);
				free(iov);
			}
		} else {
			/* C, D */
			if (value->ext_flags & KV_STORE_VALUE_AUTOFREE)
				free(_get_ptr(value->data));
		}
	}

	/*
	 * If the value stored is not a reference, it's stored as copy and
	 * part of value->data[] field allocated together with the value itself.
	 * Then it's freed just by calling free(value).
	 */

	/* A, B, C, D, E, F */
	free(value);
}

/*
 *                     INPUT                                     OUTPUT (DB RECORD)                         NOTES
 *                       |                                               |
 *           -------------------------                       --------------------------
 *          /        |                \                     /       |                  \
 *        FLAGS   OP_FLAG            VALUE             EXT_FLAGS INT_FLAGS            VALUE
 *          |        |                 |                 |        |                     |
 *        ----       |            ----------           -----      |             --------------------
 *       /    \      |           /          \         /     \     |            /                    \
 * #  VECTOR  REF  MERGE      VALUE        SIZE    VECTOR  REF  ALLOC       VALUE                  SIZE
 * ----------------------------------------------------------------------------------------------------------------
 * A     0     0     0     value ref    value size    0     0     1      value copy ref         value size
 * B     0     0     1     value ref    value size    0     0     1      value copy ref         value size   1
 * C     0     1     0     value ref    value size    0     1     0      value ref              value size
 * D     0     1     1     value ref    value size    0     1     0      value ref              value size   1
 * E     1     0     0     iovec ref    iovec size    1     0     1      iovec deep copy ref    iovec size   2
 * F     1     0     1     iovec ref    iovec size    0     0     1      value merger ref       value size   3
 * G     1     1     0     iovec ref    iovec size    1     1     0      iovec ref              iovec size
 * H     1     1     1     iovec ref    iovec size    1     1     1      value merger iovec ref iovec size   4
 *
 * NOTES:
 * 1: Merge flag has no effect: B == A and D == C
 * 2: allocated both iovec copy and value parts
 * 3: iovec members merged into a single value
 * 4: iovec members merged into a signle value. iovec has refs to merged value parts
 *
 *
 * The AUTOFREE flag may be used together with REF flag (it has no effect otherwise). Then, if the reference to the
 * value is not needed anymore due to an update or edit, there's "free" called automatically on such a reference.
 * Of course, this assumes that caller allocated the value (for which there's the reference) by "malloc".
 * For vectors, this also means that both the struct iovec and values reference by iovec.iov_base have
 * been allocated by "malloc" too.
 */
static struct kv_store_value *_create_kv_store_value(struct iovec *            iov,
                                                     int                       iov_cnt,
                                                     kv_store_value_flags_t    flags,
                                                     kv_store_value_op_flags_t op_flags,
                                                     size_t *                  size)
{
	struct kv_store_value *value;
	size_t                 value_size;
	size_t                 data_size;
	char *                 p1, *p2;
	struct iovec *         iov2;
	int                    i;

	if (flags & KV_STORE_VALUE_VECTOR) {
		if (flags & KV_STORE_VALUE_REF) {
			value_size = sizeof(*value) + sizeof(intptr_t);

			if (!(value = mem_zalloc(value_size)))
				return NULL;

			if (op_flags & KV_STORE_VALUE_OP_MERGE) {
				/* H */
				for (i = 0, data_size = 0; i < iov_cnt; i++)
					data_size += iov[i].iov_len;

				if (!(p1 = malloc(data_size)))
					return mem_freen(value);

				for (i = 0, p2 = p1; i < iov_cnt; i++) {
					memcpy(p2, iov[i].iov_base, iov[i].iov_len);
					if (flags & KV_STORE_VALUE_AUTOFREE)
						free(iov[i].iov_base);
					iov[i].iov_base = p2;
					p2 += iov[i].iov_len;
				}

				value->int_flags = KV_STORE_VALUE_INT_ALLOC;
			}
			/* G,H */
			_set_ptr(value->data, iov);
			value->size = iov_cnt;
		} else {
			for (i = 0, data_size = 0; i < iov_cnt; i++)
				data_size += iov[i].iov_len;

			if (op_flags & KV_STORE_VALUE_OP_MERGE) {
				/* F */
				value_size = sizeof(*value) + data_size;

				if (!(value = mem_zalloc(value_size)))
					return NULL;

				for (i = 0, p1 = value->data; i < iov_cnt; i++) {
					memcpy(p1, iov[i].iov_base, iov[i].iov_len);
					p1 += iov[i].iov_len;
				}

				value->size = data_size;
				flags &= ~KV_STORE_VALUE_VECTOR;
				value->int_flags = KV_STORE_VALUE_INT_ALLOC;
			} else {
				/* E */
				value_size = sizeof(*value) + iov_cnt * sizeof(struct iovec) + data_size;

				if (!(value = mem_zalloc(value_size)))
					return NULL;

				iov2 = (struct iovec *) value->data;
				p1   = value->data + iov_cnt * sizeof(struct iovec);

				for (i = 0; i < iov_cnt; i++) {
					memcpy(p1, iov[i].iov_base, iov[i].iov_len);
					iov2[i].iov_base = p1;
					iov2[i].iov_len  = iov[i].iov_len;
					p1 += iov[i].iov_len;
				}

				value->size      = iov_cnt;
				value->int_flags = KV_STORE_VALUE_INT_ALLOC;
			}
		}
	} else {
		if (flags & KV_STORE_VALUE_REF) {
			/* C,D */
			value_size = sizeof(*value) + sizeof(intptr_t);

			if (!(value = mem_zalloc(value_size)))
				return NULL;

			_set_ptr(value->data, iov[0].iov_base);
		} else {
			/* A,B */
			value_size = sizeof(*value) + iov[0].iov_len;

			if (!(value = mem_zalloc(value_size)))
				return NULL;

			memcpy(value->data, iov[0].iov_base, iov[0].iov_len);
			value->int_flags = KV_STORE_VALUE_INT_ALLOC;
		}

		value->size = iov[0].iov_len;
	}

	value->ext_flags = flags;
	*size            = value_size;

	return value;
}

static int _hash_update_fn(const char *               key,
                           uint32_t                   key_len,
                           struct kv_store_value *    old_value,
                           size_t                     old_value_len,
                           struct kv_store_value **   new_value,
                           size_t *                   new_value_len,
                           struct kv_update_fn_relay *relay)
{
	/*
	 * Note that:
	 *   '*new_value' is always non-NULL here
	 *   'old_value' can be NULL if there wasn't any previous record
	 */
	struct kv_store_value *     orig_new_value = *new_value;
	struct kv_store_value *     edited_new_value;
	void *                      orig_new_data      = NULL;
	size_t                      orig_new_data_size = 0;
	kv_store_value_flags_t      orig_new_flags     = 0;
	struct kv_store_update_spec update_spec        = {0};
	struct iovec                tmp_iov[1];
	struct iovec *              iov;
	size_t                      iov_cnt;
	size_t                      kv_store_value_size;
	int                         r = 1;

	if (relay->kv_update_fn) {
		if (old_value) {
			update_spec.old_data      = _get_data(old_value);
			update_spec.old_data_size = old_value->size;
			update_spec.old_flags     = old_value->ext_flags;
		}

		update_spec.new_data = orig_new_data = _get_data(orig_new_value);
		update_spec.new_data_size = orig_new_data_size = orig_new_value->size;
		update_spec.new_flags = orig_new_flags = orig_new_value->ext_flags;

		r = relay->kv_update_fn(relay->key, &update_spec, relay->kv_update_fn_arg);

		/* Check if there has been any change... */
		if ((r > 0) && ((update_spec.new_data != orig_new_data) || (update_spec.new_data_size != orig_new_data_size) ||
		                (update_spec.new_flags != orig_new_flags) || update_spec.op_flags)) {
			if ((update_spec.new_flags == orig_new_flags) && (update_spec.new_flags & KV_STORE_VALUE_REF) &&
			    (update_spec.new_data_size == orig_new_data_size) && !update_spec.op_flags) {
				/*
				 * If kv_store_value stores value as reference and we haven't changed the size,
				 * KV_STORE_VALUE_REF flag nor op_flags, we just need to rewrite the ptr stored
				 * in data, no need to recreate the whole kv_store_value...
				 */
				_set_ptr(orig_new_value->data, update_spec.new_data);
				orig_new_value->ext_flags = update_spec.new_flags;
			} else {
				/* ...otherwise we need to recreate the whole kv_store_value container with data. */
				if (update_spec.new_flags & KV_STORE_VALUE_VECTOR) {
					iov     = update_spec.new_data;
					iov_cnt = update_spec.new_data_size;
				} else {
					tmp_iov[0].iov_base = update_spec.new_data;
					tmp_iov[0].iov_len  = update_spec.new_data_size;
					iov_cnt             = 1;
					iov                 = tmp_iov;
				}

				if (!(edited_new_value = _create_kv_store_value(iov,
				                                                iov_cnt,
				                                                update_spec.new_flags,
				                                                update_spec.op_flags,
				                                                &kv_store_value_size))) {
					relay->ret_code = -ENOMEM;
					return 0;
				}

				_destroy_kv_store_value(orig_new_value);

				*new_value     = edited_new_value;
				*new_value_len = kv_store_value_size;
			}
		}
	}

	if (r) {
		if (old_value)
			_destroy_kv_store_value(old_value);
	} else {
		_destroy_kv_store_value(*new_value);
		*new_value = NULL;
	}

	relay->ret_code = r;
	return r;
}

void *kv_store_set_value(sid_resource_t *          kv_store_res,
                         const char *              key,
                         void *                    value,
                         size_t                    value_size,
                         kv_store_value_flags_t    flags,
                         kv_store_value_op_flags_t op_flags,
                         kv_store_update_fn_t      kv_update_fn,
                         void *                    kv_update_fn_arg)
{
	struct kv_update_fn_relay relay        = {.key              = key,
                                           .kv_update_fn     = kv_update_fn,
                                           .kv_update_fn_arg = kv_update_fn_arg,
                                           .ret_code         = -EREMOTEIO};
	struct kv_store *         kv_store     = sid_resource_get_data(kv_store_res);
	struct iovec              iov_internal = {.iov_base = value, .iov_len = value_size};
	struct iovec *            iov;
	int                       iov_cnt;
	size_t                    kv_store_value_size;
	struct kv_store_value *   kv_store_value;

	if (flags & KV_STORE_VALUE_VECTOR) {
		iov     = value;
		iov_cnt = value_size;
	} else {
		iov     = &iov_internal;
		iov_cnt = 1;
	}

	if (!(kv_store_value = _create_kv_store_value(iov, iov_cnt, flags, op_flags, &kv_store_value_size)))
		return NULL;

	if (hash_update(kv_store->ht,
	                key,
	                strlen(key) + 1,
	                (void **) &kv_store_value,
	                &kv_store_value_size,
	                (hash_update_fn_t) _hash_update_fn,
	                &relay))
		return NULL;

	if (relay.ret_code < 0)
		return NULL;

	return _get_data(kv_store_value);
}

void *kv_store_get_value(sid_resource_t *kv_store_res, const char *key, size_t *value_size, kv_store_value_flags_t *flags)
{
	struct kv_store *      kv_store = sid_resource_get_data(kv_store_res);
	struct kv_store_value *found;

	if (!(found = hash_lookup(kv_store->ht, key, strlen(key) + 1, NULL)))
		return NULL;

	if (value_size)
		*value_size = found->size;

	if (flags)
		*flags = found->ext_flags;

	return _get_data(found);
}

int kv_store_unset_value(sid_resource_t *kv_store_res, const char *key, kv_store_update_fn_t kv_unset_fn, void *kv_unset_fn_arg)
{
	struct kv_store *           kv_store = sid_resource_get_data(kv_store_res);
	struct kv_store_value *     found;
	struct kv_store_update_spec update_spec = {0};

	/*
	 * FIXME: hash_lookup and hash_remove are two searches inside hash - maybe try to do
	 *        this in one step (...that requires hash interface extension).
	 */
	if (!(found = hash_lookup(kv_store->ht, key, strlen(key) + 1, NULL)))
		return -ENODATA;

	update_spec.old_data      = _get_data(found);
	update_spec.old_data_size = found->size;
	update_spec.old_flags     = found->ext_flags;

	if (kv_unset_fn && !kv_unset_fn(key, &update_spec, kv_unset_fn_arg))
		return -EREMOTEIO;

	_destroy_kv_store_value(found);
	hash_remove(kv_store->ht, key, strlen(key) + 1);

	return 0;
}

kv_store_iter_t *kv_store_iter_create(sid_resource_t *kv_store_res)
{
	kv_store_iter_t *iter;

	if (!(iter = malloc(sizeof(*iter))))
		return NULL;

	iter->store   = sid_resource_get_data(kv_store_res);
	iter->current = NULL;

	return iter;
}

void *kv_store_iter_current(kv_store_iter_t *iter, size_t *size, kv_store_value_flags_t *flags)
{
	struct kv_store_value *value;

	if (!(value = iter->current ? hash_get_data(iter->store->ht, iter->current, NULL) : NULL))
		return NULL;

	if (size)
		*size = value->size;

	if (flags)
		*flags = value->ext_flags;

	return _get_data(value);
}

int kv_store_iter_current_size(kv_store_iter_t *iter,
                               size_t *         int_size,
                               size_t *         int_data_size,
                               size_t *         ext_size,
                               size_t *         ext_data_size)
{
	size_t                 iov_size, data_size;
	struct kv_store_value *value;

	if (!iter || !int_size || !int_data_size || !ext_size || !ext_data_size)
		return -1;

	if (!(value = iter->current ? hash_get_data(iter->store->ht, iter->current, NULL) : NULL))
		return -1;

	if (value->ext_flags & KV_STORE_VALUE_VECTOR) {
		int           i;
		struct iovec *iov;

		iov = (value->ext_flags & KV_STORE_VALUE_REF) ? _get_ptr(value->data) : (struct iovec *) value->data;

		iov_size = value->size * sizeof(struct iovec);
		for (i = 0, data_size = 0; i < value->size; i++)
			data_size += iov[i].iov_len;
	} else {
		data_size = value->size;
		iov_size  = 0;
	}

	if (value->int_flags & KV_STORE_VALUE_INT_ALLOC) {
		*int_size = *int_data_size = data_size;
		*ext_size = *ext_data_size = 0;
	} else {
		*int_size = *int_data_size = 0;
		*ext_size = *ext_data_size = data_size;
	}
	if (value->ext_flags & KV_STORE_VALUE_REF) {
		*int_size += sizeof(*value) + sizeof(intptr_t);
		*ext_size += iov_size;
	} else
		*int_size += sizeof(*value) + iov_size;

	return 0;
}

const char *kv_store_iter_current_key(kv_store_iter_t *iter)
{
	return iter->current ? hash_get_key(iter->store->ht, iter->current, NULL) : NULL;
}

void *kv_store_iter_next(kv_store_iter_t *iter, size_t *size, kv_store_value_flags_t *flags)
{
	iter->current = iter->current ? hash_get_next(iter->store->ht, iter->current) : hash_get_first(iter->store->ht);

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

size_t kv_store_get_size(sid_resource_t *kv_store_res, size_t *meta_size, size_t *data_size)
{
	struct kv_store *kv_store = sid_resource_get_data(kv_store_res);
	return hash_get_size(kv_store->ht, meta_size, data_size);
}

static int _init_kv_store(sid_resource_t *kv_store_res, const void *kickstart_data, void **data)
{
	const struct sid_kv_store_resource_params *params = kickstart_data;
	struct kv_store *                          kv_store;

	if (!(kv_store = mem_zalloc(sizeof(*kv_store)))) {
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

	hash_iter(kv_store->ht, (hash_iterate_fn) _destroy_kv_store_value);
	hash_destroy(kv_store->ht);
	free(kv_store);

	return 0;
}

const sid_resource_type_t sid_resource_type_kv_store = {
	.name    = KV_STORE_NAME,
	.init    = _init_kv_store,
	.destroy = _destroy_kv_store,
};
