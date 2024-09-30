/*
 * SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "internal/comp-attrs.h"

#include "resource/kvs.h"

#include "internal/bptree.h"
#include "internal/hash.h"
#include "internal/mem.h"
#include "internal/util.h"
#include "resource/res.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>

#define KV_STORE_VALUE_INT_ALLOC UINT32_C(0x00000001)

typedef uint32_t kv_store_value_int_flags_t;

struct kv_store {
	sid_kvs_backend_t backend;
	struct sid_buf   *trans_unset_buf;
	struct sid_buf   *trans_rollback_buf;

	union {
		struct hash_table *ht;
		struct bptree     *bpt;
	};
};

struct kv_store_value {
	size_t                     size;
	kv_store_value_int_flags_t int_flags;
	sid_kvs_val_fl_t           ext_flags;
	char                       data[] __aligned;
};

struct kv_rollback_arg {
	const char            *key;
	struct kv_store_value *kv_store_value;
	size_t                 kv_store_value_size;
	bool                   has_archive:1;
	bool                   is_archive :1;
};

struct kv_unset_arg {
	const char *key;
	bool        has_archive:1;
};

struct kv_archive_arg {
	struct kv_store_value *kv_store_value;
	size_t                 kv_store_value_size;
	bool                   has_archive:1;
	bool                   is_archive :1;
};

struct kv_trans_fn_arg {
	sid_res_t *res;
	bool       has_archive:1;
	bool       is_archive :1;
};

struct kv_update_fn_relay {
	sid_kvs_update_cb_fn_t kv_update_fn;
	void                  *kv_update_fn_arg;
	struct sid_buf        *unset_buf;
	struct sid_buf        *rollback_buf;
	struct kv_archive_arg  archive_arg;
	int                    ret_code;
};

typedef enum {
	ITER_EXACT,
	ITER_PREFIX,
} kvs_iter_method_t;

struct sid_kvs_iter {
	struct kv_store *store;

	union {
		struct {
			struct hash_node *current;
		} ht;

		struct {
			bptree_iter_t *iter;
		} bpt;
	};
};

static void _set_ptr(void *dest, const void *p)
{
	memcpy(dest, (void *) &p, sizeof(uintptr_t));
}

static void *_get_ptr(const void *src)
{
	uintptr_t ptr;

	memcpy(&ptr, src, sizeof(ptr));
	return (void *) ptr;
}

static void *_get_data(struct kv_store_value *value)
{
	if (!value)
		return NULL;

	return value->ext_flags & SID_KVS_VAL_FL_REF ? _get_ptr(value->data) : value->data;
}

static void _destroy_kv_store_value(struct kv_store_value *value)
{
	struct iovec *iov;
	size_t        i;

	if (!value)
		return;

	/* Take extra care of situations where we store reference to a value. */
	if (value->ext_flags & SID_KVS_VAL_FL_REF) {
		if (value->ext_flags & SID_KVS_VAL_FL_VECTOR) {
			iov = _get_ptr(value->data);

			if (value->int_flags & KV_STORE_VALUE_INT_ALLOC) {
				/* H */
				free(iov[0].iov_base);
				if (value->ext_flags & SID_KVS_VAL_FL_AUTOFREE)
					free(iov);
				else
					for (i = 0; i < value->size; i++) {
						iov[i].iov_base = NULL;
						iov[i].iov_len  = 0;
					}
			} else if (value->ext_flags & SID_KVS_VAL_FL_AUTOFREE) {
				/* G */
				for (i = 0; i < value->size; i++)
					free(iov[i].iov_base);
				free(iov);
			}
		} else {
			/* C, D */
			if (value->ext_flags & SID_KVS_VAL_FL_AUTOFREE)
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

static void
	_hash_destroy_kv_store_value(const void *key __unused, uint32_t key_len __unused, void *value, size_t value_size __unused)
{
	_destroy_kv_store_value(value);
}

static void _bptree_destroy_kv_store_value(const char *key   __unused,
                                           void             *value,
                                           size_t value_size __unused,
                                           unsigned          ref_count,
                                           void *arg         __unused)
{
	if (ref_count == 1)
		_destroy_kv_store_value(value);
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
static struct kv_store_value *
	_create_kv_store_value(struct iovec *iov, int iov_cnt, sid_kvs_val_fl_t flags, sid_kvs_val_op_fl_t op_flags, size_t *size)
{
	struct kv_store_value *value;
	size_t                 value_size;
	size_t                 data_size;
	char                  *p;
	struct iovec          *iov2;
	int                    i;

	if (flags & SID_KVS_VAL_FL_VECTOR) {
		if (flags & SID_KVS_VAL_FL_REF) {
			value_size = sizeof(*value) + sizeof(uintptr_t);

			if (!(value = mem_zalloc(value_size)))
				return NULL;

			if (op_flags & SID_KVS_VAL_OP_MERGE) {
				/* H */
				for (i = 0, data_size = 0; i < iov_cnt; i++)
					data_size += iov[i].iov_len;

				if (!(p = malloc(data_size)))
					return mem_freen(value);

				/*
				 * FIXME:
				 * The assignment of 'p' to value->data here is completely artificial and it makes
				 * no sense for us. It's just for static analyzers so they don't complain we're leaking
				 * the 'p'. We're not - the 'p' is assigned in iov[i].iov_base = p in the loop that
				 * follows and we can free the memory by simply calling free(iov[0].iov_base) as this
				 * very first item contains a pointer to the beginning of the whole allocated area.
				 *
				 * We overwrite value->data with proper data at the end of this code block.
				 */
				_set_ptr(value->data, p);

				for (i = 0; i < iov_cnt; i++) {
					memcpy(p, iov[i].iov_base, iov[i].iov_len);
					if (flags & SID_KVS_VAL_FL_AUTOFREE)
						free(iov[i].iov_base);
					iov[i].iov_base  = p;
					p               += iov[i].iov_len;
				}

				value->int_flags = KV_STORE_VALUE_INT_ALLOC;
			}
			/* G,H */
			_set_ptr(value->data, iov);
			value->size = iov_cnt;
		} else {
			for (i = 0, data_size = 0; i < iov_cnt; i++)
				data_size += iov[i].iov_len;

			if (op_flags & SID_KVS_VAL_OP_MERGE) {
				/* F */
				value_size = sizeof(*value) + data_size;

				if (!(value = mem_zalloc(value_size)))
					return NULL;

				for (i = 0, p = value->data; i < iov_cnt; i++) {
					memcpy(p, iov[i].iov_base, iov[i].iov_len);
					p += iov[i].iov_len;
				}

				value->size       = data_size;
				flags            &= ~SID_KVS_VAL_FL_VECTOR;
				value->int_flags  = KV_STORE_VALUE_INT_ALLOC;
			} else {
				/* E */
				value_size = sizeof(*value) + iov_cnt * sizeof(struct iovec) + data_size;

				if (!(value = mem_zalloc(value_size)))
					return NULL;

				iov2 = (struct iovec *) value->data;
				p    = value->data + iov_cnt * sizeof(struct iovec);

				for (i = 0; i < iov_cnt; i++) {
					memcpy(p, iov[i].iov_base, iov[i].iov_len);
					iov2[i].iov_base  = p;
					iov2[i].iov_len   = iov[i].iov_len;
					p                += iov[i].iov_len;
				}

				value->size      = iov_cnt;
				value->int_flags = KV_STORE_VALUE_INT_ALLOC;
			}
		}
	} else {
		if (flags & SID_KVS_VAL_FL_REF) {
			/* C,D */
			value_size = sizeof(*value) + sizeof(uintptr_t);

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

static int _update_fn(const char                *key,
                      struct kv_store_value     *old_value,
                      size_t                     old_value_len,
                      struct kv_store_value    **new_value,
                      size_t                    *new_value_len,
                      struct kv_update_fn_relay *relay)
{
	/*
	 * Note that:
	 *   '*new_value' is always non-NULL here
	 *   'old_value' can be NULL if there wasn't any previous record
	 */
	struct kv_store_value     *orig_new_value = *new_value;
	struct kv_store_value     *edited_new_value;
	void                      *orig_new_data      = NULL;
	size_t                     orig_new_data_size = 0;
	sid_kvs_val_fl_t           orig_new_flags     = 0;
	struct sid_kvs_update_spec update_spec        = {.key = key};
	struct iovec               tmp_iov[1];
	struct iovec              *iov;
	size_t                     iov_cnt;
	size_t                     kv_store_value_size;
	const char                *key_dup;
	int                        r = 1;

	if (relay->kv_update_fn) {
		if (old_value) {
			update_spec.old_data      = _get_data(old_value);
			update_spec.old_data_size = old_value->size;
			update_spec.old_flags     = old_value->ext_flags;
		}

		update_spec.new_data = orig_new_data = _get_data(orig_new_value);
		update_spec.new_data_size = orig_new_data_size = orig_new_value->size;
		update_spec.new_flags = orig_new_flags = orig_new_value->ext_flags;

		update_spec.arg                        = relay->kv_update_fn_arg;

		r                                      = relay->kv_update_fn(&update_spec);

		/* Check if there has been any change... */
		if ((r > 0) && ((update_spec.new_data != orig_new_data) || (update_spec.new_data_size != orig_new_data_size) ||
		                (update_spec.new_flags != orig_new_flags) || update_spec.op_flags)) {
			if ((update_spec.new_flags == orig_new_flags) && (update_spec.new_flags & SID_KVS_VAL_FL_REF) &&
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
				if (update_spec.new_flags & SID_KVS_VAL_FL_VECTOR) {
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
		if (relay->rollback_buf || relay->archive_arg.has_archive) {
			if (relay->rollback_buf) {
				if ((key_dup = strdup(key))) {
					struct kv_rollback_arg rollback_arg = {.key                 = key_dup,
					                                       .kv_store_value      = old_value,
					                                       .kv_store_value_size = old_value_len,
					                                       .has_archive = relay->archive_arg.has_archive,
					                                       .is_archive  = relay->archive_arg.is_archive};

					if ((relay->ret_code = sid_buf_add(relay->rollback_buf,
					                                   &rollback_arg,
					                                   sizeof(rollback_arg),
					                                   NULL,
					                                   NULL)) < 0)
						r = 0;
				} else {
					relay->ret_code = -ENOMEM;
					r               = 0;
				}
			}

			if (relay->archive_arg.has_archive) {
				relay->archive_arg.kv_store_value      = old_value;
				relay->archive_arg.kv_store_value_size = old_value_len;
			}
		} else
			_destroy_kv_store_value(old_value);
	}

	if (!r) {
		_destroy_kv_store_value(*new_value);
		*new_value = NULL;
	}

	return r;
}

static hash_update_action_t _hash_update_fn(const void      *key,
                                            uint32_t key_len __unused,
                                            void            *old_value,
                                            size_t           old_value_len,
                                            void           **new_value,
                                            size_t          *new_value_len,
                                            void            *arg)
{
	if (_update_fn((const char *) key,
	               (struct kv_store_value *) old_value,
	               old_value_len,
	               (struct kv_store_value **) new_value,
	               new_value_len,
	               (struct kv_update_fn_relay *) arg))
		return HASH_UPDATE_WRITE;

	return HASH_UPDATE_SKIP;
}

static bptree_update_action_t _bptree_update_fn(const char *key,
                                                void       *old_value,
                                                size_t      old_value_len,
                                                unsigned    old_value_ref_count,
                                                void      **new_value,
                                                size_t     *new_value_len,
                                                void       *arg)
{
	if (_update_fn(key,
	               (struct kv_store_value *) old_value,
	               old_value_len,
	               (struct kv_store_value **) new_value,
	               new_value_len,
	               (struct kv_update_fn_relay *) arg))
		return BPTREE_UPDATE_WRITE;

	return BPTREE_UPDATE_SKIP;
}

static const char *_canonicalize_key(const char *key)
{
	if (!key || !*key)
		return key;

	while (isspace(*key))
		key++;

	return key;
}

static int _set_value(struct kv_store           *kv_store,
                      const char                *key,
                      struct kv_store_value    **kv_store_value,
                      size_t                    *kv_store_value_size,
                      struct kv_update_fn_relay *relay)
{
	int r = 0;

	if (!key)
		return -EINVAL;

	switch (kv_store->backend) {
		case SID_KVS_BACKEND_HASH:
			r = hash_update(kv_store->ht,
			                key,
			                strlen(key) + 1,
			                (void **) kv_store_value,
			                kv_store_value_size,
			                _hash_update_fn,
			                relay);
			break;

		case SID_KVS_BACKEND_BPTREE:
			r = bptree_update(kv_store->bpt,
			                  key,
			                  (void **) kv_store_value,
			                  kv_store_value_size,
			                  _bptree_update_fn,
			                  relay);
			break;
	}

	if (r < 0 || relay->ret_code < 0)
		return -1;

	return 0;
}

static void _kv_store_trans_rollback_value(sid_res_t *kv_store_res, struct kv_rollback_arg *rollback_arg);

static void *_do_kv_store_set_value(sid_res_t             *kv_store_res,
                                    const char            *key,
                                    void                  *value,
                                    size_t                 value_size,
                                    sid_kvs_val_fl_t       flags,
                                    sid_kvs_val_op_fl_t    op_flags,
                                    sid_kvs_update_cb_fn_t kv_update_fn,
                                    void                  *kv_update_fn_arg,
                                    const char            *archive_key)
{
	struct kv_store          *kv_store     = sid_res_get_data(kv_store_res);
	struct iovec              iov_internal = {.iov_base = value, .iov_len = value_size};
	struct iovec             *iov;
	int                       iov_cnt;
	struct kv_update_fn_relay relay;
	size_t                    kv_store_value_size;
	struct kv_store_value    *kv_store_value;

	/*
	 * Update the record with new data under the 'key' first. If we fail to do so
	 * (e.g. the allocation fails underneath {hash,bptree}_update), return NULL immediately.
	 *
	 * If we are creating an archive, also update the record under the 'archive_key'.
	 * If we fail to do so, rollback the record under the 'key' (or just rely on
	 * kv_store_transaction_end to do that for us in case we are under a transaction).
	 *
	 */

	if (flags & SID_KVS_VAL_FL_VECTOR) {
		iov     = value;
		iov_cnt = value_size;
	} else {
		iov     = &iov_internal;
		iov_cnt = 1;
	}

	if (!(kv_store_value = _create_kv_store_value(iov, iov_cnt, flags, op_flags, &kv_store_value_size)))
		return NULL;

	key         = _canonicalize_key(key);
	archive_key = _canonicalize_key(archive_key);

	relay       = (struct kv_update_fn_relay) {.kv_update_fn            = kv_update_fn,
	                                           .kv_update_fn_arg        = kv_update_fn_arg,
	                                           .archive_arg.has_archive = archive_key != NULL,
	                                           .rollback_buf            = kv_store->trans_rollback_buf};

	if (_set_value(kv_store, key, &kv_store_value, &kv_store_value_size, &relay) < 0)
		return NULL;

	if (relay.archive_arg.has_archive && relay.archive_arg.kv_store_value) {
		relay.archive_arg.has_archive = false;
		relay.archive_arg.is_archive  = true;
		relay.kv_update_fn            = NULL;
		relay.kv_update_fn_arg        = NULL;

		if (_set_value(kv_store,
		               archive_key,
		               &relay.archive_arg.kv_store_value,
		               &relay.archive_arg.kv_store_value_size,
		               &relay) < 0) {
			if (!sid_kvs_transaction_active(kv_store_res)) {
				_kv_store_trans_rollback_value(
					kv_store_res,
					&(struct kv_rollback_arg) {.key                 = key,
				                                   .kv_store_value      = relay.archive_arg.kv_store_value,
				                                   .kv_store_value_size = relay.archive_arg.kv_store_value_size});
			}
			return NULL;
		}
	}

	return _get_data(kv_store_value);
}

void *sid_kvs_set(sid_res_t             *kv_store_res,
                  const char            *key,
                  void                  *value,
                  size_t                 value_size,
                  sid_kvs_val_fl_t       flags,
                  sid_kvs_val_op_fl_t    op_flags,
                  sid_kvs_update_cb_fn_t kv_update_fn,
                  void                  *kv_update_fn_arg)
{
	if (!sid_res_match(kv_store_res, &sid_res_type_kvs, NULL) || UTIL_STR_EMPTY(key))
		return NULL;

	return _do_kv_store_set_value(kv_store_res, key, value, value_size, flags, op_flags, kv_update_fn, kv_update_fn_arg, NULL);
}

void *sid_kvs_set_with_archive(sid_res_t             *kv_store_res,
                               const char            *key,
                               void                  *value,
                               size_t                 value_size,
                               sid_kvs_val_fl_t       flags,
                               sid_kvs_val_op_fl_t    op_flags,
                               sid_kvs_update_cb_fn_t kv_update_fn,
                               void                  *kv_update_fn_arg,
                               const char            *archive_key)
{
	if (!sid_res_match(kv_store_res, &sid_res_type_kvs, NULL) || UTIL_STR_EMPTY(key))
		return NULL;

	return _do_kv_store_set_value(kv_store_res,
	                              key,
	                              value,
	                              value_size,
	                              flags,
	                              op_flags,
	                              kv_update_fn,
	                              kv_update_fn_arg,
	                              archive_key);
}

int sid_kvs_add_alias(sid_res_t *kv_store_res, const char *key, const char *alias, bool force)
{
	struct kv_store *kv_store;

	if (!sid_res_match(kv_store_res, &sid_res_type_kvs, NULL) || UTIL_STR_EMPTY(key) || UTIL_STR_EMPTY(alias))
		return -EINVAL;

	kv_store = sid_res_get_data(kv_store_res);
	key      = _canonicalize_key(key);
	alias    = _canonicalize_key(alias);

	switch (kv_store->backend) {
		case SID_KVS_BACKEND_BPTREE:
			return bptree_add_alias(kv_store->bpt, key, alias, force);

		default:
			return -ENOTSUP;
	}
}

void *sid_kvs_get(sid_res_t *kv_store_res, const char *key, size_t *value_size, sid_kvs_val_fl_t *flags)
{
	struct kv_store       *kv_store;
	struct kv_store_value *found;

	if (!sid_res_match(kv_store_res, &sid_res_type_kvs, NULL) || UTIL_STR_EMPTY(key))
		return NULL;

	kv_store = sid_res_get_data(kv_store_res);
	key      = _canonicalize_key(key);
	found    = NULL;

	switch (kv_store->backend) {
		case SID_KVS_BACKEND_HASH:
			found = hash_lookup(kv_store->ht, key, strlen(key) + 1, NULL);
			break;

		case SID_KVS_BACKEND_BPTREE:
			found = bptree_lookup(kv_store->bpt, key, NULL, NULL);
			break;
	}

	if (!found)
		return NULL;

	if (value_size)
		*value_size = found->size;

	if (flags)
		*flags = found->ext_flags;

	return _get_data(found);
}

static int _unset_fn(const char                *key,
                     struct kv_store_value     *old_value,
                     size_t                     old_value_len,
                     unsigned                   old_value_ref_count,
                     struct kv_store_value    **new_value,
                     size_t                    *new_value_len,
                     struct kv_update_fn_relay *relay)
{
	struct sid_kvs_update_spec update_spec;
	const char                *key_dup;
	int                        r;

	if (relay->kv_update_fn) {
		update_spec.key           = key;

		update_spec.new_data      = NULL;
		update_spec.new_data_size = 0;
		update_spec.new_flags     = 0;

		if (old_value) {
			update_spec.old_data      = _get_data(old_value);
			update_spec.old_data_size = old_value->size;
			update_spec.old_flags     = old_value->ext_flags;
		} else {
			update_spec.old_data      = NULL;
			update_spec.old_data_size = 0;
			update_spec.old_flags     = 0;
		}

		update_spec.arg = relay->kv_update_fn_arg;

		r               = relay->kv_update_fn(&update_spec);
	} else
		r = 1;

	if (r == 1) {
		if (relay->unset_buf) {
			if ((key_dup = strdup(key))) {
				struct kv_unset_arg unset_arg = {.key = key_dup, .has_archive = relay->archive_arg.has_archive};

				relay->ret_code = sid_buf_add(relay->unset_buf, &unset_arg, sizeof(unset_arg), NULL, NULL);
			} else
				relay->ret_code = -ENOMEM;

			r = 0;
		} else if (old_value_ref_count == 1 && !relay->archive_arg.has_archive)
			_destroy_kv_store_value(old_value);

		if (relay->archive_arg.has_archive) {
			relay->archive_arg.kv_store_value      = old_value;
			relay->archive_arg.kv_store_value_size = old_value_len;
		}
	}

	return r;
}

static hash_update_action_t _hash_unset_fn(const void      *key,
                                           uint32_t key_len __unused,
                                           void            *old_value,
                                           size_t           old_value_len,
                                           void           **new_value,
                                           size_t          *new_value_len,
                                           void            *arg)
{
	if (_unset_fn(key,
	              (struct kv_store_value *) old_value,
	              old_value_len,
	              1,
	              (struct kv_store_value **) new_value,
	              new_value_len,
	              (struct kv_update_fn_relay *) arg))
		return HASH_UPDATE_REMOVE;

	return HASH_UPDATE_SKIP;
}

static bptree_update_action_t _bptree_unset_fn(const char *key,
                                               void       *old_value,
                                               size_t      old_value_len,
                                               unsigned    old_value_ref_count,
                                               void      **new_value,
                                               size_t     *new_value_len,
                                               void       *arg)
{
	if (_unset_fn(key,
	              (struct kv_store_value *) old_value,
	              old_value_len,
	              old_value_ref_count,
	              (struct kv_store_value **) new_value,
	              new_value_len,
	              (struct kv_update_fn_relay *) arg))
		return BPTREE_UPDATE_REMOVE;

	return BPTREE_UPDATE_SKIP;
}

static int _unset_value(struct kv_store *kv_store, const char *key, struct kv_update_fn_relay *relay)
{
	int r = 0;

	if (!key)
		return -EINVAL;

	switch (kv_store->backend) {
		case SID_KVS_BACKEND_HASH:
			r = hash_update(kv_store->ht, key, strlen(key) + 1, NULL, 0, _hash_unset_fn, relay);
			break;

		case SID_KVS_BACKEND_BPTREE:
			r = bptree_update(kv_store->bpt, key, NULL, 0, _bptree_unset_fn, relay);
			break;
	}

	if (r < 0 || relay->ret_code < 0)
		return -1;

	return 0;
}

static int _do_kv_store_unset(sid_res_t             *kv_store_res,
                              const char            *key,
                              struct sid_buf        *unset_buf,
                              sid_kvs_update_cb_fn_t kv_unset_fn,
                              void                  *kv_unset_fn_arg,
                              const char            *archive_key)
{
	struct kv_store          *kv_store = sid_res_get_data(kv_store_res);
	struct kv_update_fn_relay relay;

	key         = _canonicalize_key(key);
	archive_key = _canonicalize_key(archive_key);

	relay       = (struct kv_update_fn_relay) {.kv_update_fn            = kv_unset_fn,
	                                           .kv_update_fn_arg        = kv_unset_fn_arg,
	                                           .archive_arg.has_archive = archive_key != NULL,
	                                           .unset_buf               = unset_buf};

	if (_unset_value(kv_store, key, &relay) < 0)
		return -1;

	if (relay.archive_arg.has_archive && relay.archive_arg.kv_store_value) {
		relay.archive_arg.has_archive = false;
		relay.archive_arg.is_archive  = true;
		relay.kv_update_fn            = NULL;
		relay.kv_update_fn_arg        = NULL;

		if (_set_value(kv_store,
		               archive_key,
		               &relay.archive_arg.kv_store_value,
		               &relay.archive_arg.kv_store_value_size,
		               &relay) < 0) {
			if (!sid_kvs_transaction_active(kv_store_res)) {
				_kv_store_trans_rollback_value(
					kv_store_res,
					&(struct kv_rollback_arg) {.key                 = key,
				                                   .kv_store_value      = relay.archive_arg.kv_store_value,
				                                   .kv_store_value_size = relay.archive_arg.kv_store_value_size});
			}

			return -1;
		}
	}

	return 0;
}

int sid_kvs_unset(sid_res_t *kv_store_res, const char *key, sid_kvs_update_cb_fn_t kv_unset_fn, void *kv_unset_fn_arg)
{
	struct kv_store *kv_store = sid_res_get_data(kv_store_res);

	return _do_kv_store_unset(kv_store_res, key, kv_store->trans_unset_buf, kv_unset_fn, kv_unset_fn_arg, NULL);
}

int sid_kvs_unset_with_archive(sid_res_t             *kv_store_res,
                               const char            *key,
                               sid_kvs_update_cb_fn_t kv_unset_fn,
                               void                  *kv_unset_fn_arg,
                               const char            *archive_key)
{
	struct kv_store *kv_store = sid_res_get_data(kv_store_res);

	return _do_kv_store_unset(kv_store_res, key, kv_store->trans_unset_buf, kv_unset_fn, kv_unset_fn_arg, archive_key);
}

static int _rollback_fn(const char             *key,
                        struct kv_store_value  *curr_value,
                        struct kv_store_value **rollback_value,
                        struct kv_trans_fn_arg *trans_arg)
{
	if ((!rollback_value && !curr_value) || (rollback_value && curr_value == *rollback_value))
		return 0;

	if (!curr_value) {
		/*
		 * This is paranoia. The only way curr_value can be NULL is if we failed adding a new value. In
		 * that case, rollback_value should always be NULL. But destroy it if it exists, just to be safe.
		 * Otherwise, we would leak memory if it existed.
		 */
		_destroy_kv_store_value(*rollback_value);
		return 0;
	}

	if (!trans_arg->is_archive)
		_destroy_kv_store_value(curr_value);

	sid_res_log_debug(trans_arg->res, "Rolling back value for key %s", key);

	if (rollback_value)
		return 1;

	return 2;
}

static hash_update_action_t _hash_rollback_fn(const void                *key,
                                              uint32_t key_len           __unused,
                                              void                      *curr_value,
                                              size_t curr_value_len      __unused,
                                              void                     **rollback_value,
                                              size_t *rollback_value_len __unused,
                                              void                      *arg)
{
	int r;

	r = _rollback_fn((const char *) key,
	                 (struct kv_store_value *) curr_value,
	                 (struct kv_store_value **) rollback_value,
	                 (struct kv_trans_fn_arg *) arg);

	if (r == 1)
		return HASH_UPDATE_WRITE;
	else if (r == 2)
		return HASH_UPDATE_REMOVE;

	return HASH_UPDATE_SKIP;
}

static bptree_update_action_t _bptree_rollback_fn(const char                   *key,
                                                  void                         *curr_value,
                                                  size_t curr_value_len         __unused,
                                                  unsigned curr_value_ref_count __unused,
                                                  void                        **rollback_value,
                                                  size_t *rollback_value_len    __unused,
                                                  void                         *arg)
{
	int r;

	r = _rollback_fn((const char *) key,
	                 (struct kv_store_value *) curr_value,
	                 (struct kv_store_value **) rollback_value,
	                 (struct kv_trans_fn_arg *) arg);

	if (r == 1)
		return BPTREE_UPDATE_WRITE;
	else if (r == 2)
		return BPTREE_UPDATE_REMOVE;

	return BPTREE_UPDATE_SKIP;
}

static void _kv_store_trans_rollback_value(sid_res_t *kv_store_res, struct kv_rollback_arg *rollback_arg)
{
	struct kv_store       *kv_store     = sid_res_get_data(kv_store_res);
	struct kv_trans_fn_arg trans_fn_arg = {.res         = kv_store_res,
	                                       .has_archive = rollback_arg->has_archive,
	                                       .is_archive  = rollback_arg->is_archive};

	switch (kv_store->backend) {
		case SID_KVS_BACKEND_HASH:
			hash_update(kv_store->ht,
			            rollback_arg->key,
			            strlen(rollback_arg->key) + 1,
			            rollback_arg->kv_store_value ? (void **) &rollback_arg->kv_store_value : NULL,
			            &rollback_arg->kv_store_value_size,
			            _hash_rollback_fn,
			            &trans_fn_arg);
			break;

		case SID_KVS_BACKEND_BPTREE:
			if (bptree_update(kv_store->bpt,
			                  rollback_arg->key,
			                  rollback_arg->kv_store_value ? (void **) &rollback_arg->kv_store_value : NULL,
			                  &rollback_arg->kv_store_value_size,
			                  _bptree_rollback_fn,
			                  &trans_fn_arg))
				break;
	}
}

static void _kv_store_trans_unset_value(sid_res_t *kv_store_res, struct kv_unset_arg *unset_arg)
{
	struct kv_store          *kv_store = sid_res_get_data(kv_store_res);
	struct kv_update_fn_relay relay    = {0};

	relay.archive_arg.has_archive      = unset_arg->has_archive;

	_unset_value(kv_store, unset_arg->key, &relay);
}

bool sid_kvs_transaction_active(sid_res_t *kv_store_res)
{
	struct kv_store *kv_store;

	if (!sid_res_match(kv_store_res, &sid_res_type_kvs, NULL))
		return false;

	kv_store = sid_res_get_data(kv_store_res);

	return (kv_store->trans_rollback_buf != NULL);
}

int sid_kvs_transaction_begin(sid_res_t *kv_store_res)
{
	struct kv_store *kv_store;
	struct sid_buf  *rollback_buf, *unset_buf;
	int              r = -1;

	if (!sid_res_match(kv_store_res, &sid_res_type_kvs, NULL))
		return -EINVAL;

	if (sid_kvs_transaction_active(kv_store_res))
		return -EBUSY;

	if (!(rollback_buf = sid_buf_create(&((struct sid_buf_spec) {.backend = SID_BUF_BACKEND_MALLOC,
	                                                             .type    = SID_BUF_TYPE_LINEAR,
	                                                             .mode    = SID_BUF_MODE_PLAIN}),
	                                    &((struct sid_buf_init) {.size = 0, .alloc_step = 1, .limit = 0}),
	                                    &r))) {
		sid_res_log_error_errno(kv_store_res, r, "Failed to create transaction rollback tracker buffer");
		return r;
	}
	if (!(unset_buf = sid_buf_create(&((struct sid_buf_spec) {.backend = SID_BUF_BACKEND_MALLOC,
	                                                          .type    = SID_BUF_TYPE_LINEAR,
	                                                          .mode    = SID_BUF_MODE_PLAIN}),
	                                 &((struct sid_buf_init) {.size = 0, .alloc_step = 1, .limit = 0}),
	                                 &r))) {
		sid_res_log_error_errno(kv_store_res, r, "Failed to create transaction unset tracker buffer");
		sid_buf_destroy(rollback_buf);
		return r;
	}

	kv_store                     = sid_res_get_data(kv_store_res);
	kv_store->trans_rollback_buf = rollback_buf;
	kv_store->trans_unset_buf    = unset_buf;

	return 0;
}

void sid_kvs_transaction_end(sid_res_t *kv_store_res, bool rollback)
{
	struct kv_store        *kv_store;
	struct kv_rollback_arg *rollback_args;
	struct kv_unset_arg    *unset_args;
	size_t                  i, nr_args;

	if (!sid_res_match(kv_store_res, &sid_res_type_kvs, NULL))
		return;

	if (!sid_kvs_transaction_active(kv_store_res)) {
		sid_res_log_warning(kv_store_res, "Ending a transaction that hasn't been started");
		return;
	}

	kv_store = sid_res_get_data(kv_store_res);

	/*
	 * Handle unset buffer.
	 */
	sid_buf_get_data(kv_store->trans_unset_buf, (const void **) &unset_args, &nr_args);
	nr_args = nr_args / sizeof(struct kv_unset_arg);

	for (i = 0; i < nr_args; i++) {
		if (!rollback)
			_kv_store_trans_unset_value(kv_store_res, &unset_args[i]);

		free((void *) unset_args[i].key);
	}

	sid_buf_destroy(kv_store->trans_unset_buf);
	kv_store->trans_unset_buf = NULL;

	/*
	 * Handle rollback buffer.
	 */
	sid_buf_get_data(kv_store->trans_rollback_buf, (const void **) &rollback_args, &nr_args);
	nr_args = nr_args / sizeof(struct kv_rollback_arg);

	for (i = 0; i < nr_args; i++) {
		if (rollback)
			_kv_store_trans_rollback_value(kv_store_res, &rollback_args[i]);
		else if (!rollback_args[i].has_archive)
			_destroy_kv_store_value(rollback_args[i].kv_store_value);

		free((void *) rollback_args[i].key);
	}

	sid_buf_destroy(kv_store->trans_rollback_buf);
	kv_store->trans_rollback_buf = NULL;
}

static sid_kvs_iter_t *
	_do_sid_kvs_iter_create(sid_res_t *kv_store_res, kvs_iter_method_t method, const char *key_start, const char *key_end)
{
	sid_kvs_iter_t *iter;

	if (!sid_res_match(kv_store_res, &sid_res_type_kvs, NULL))
		return NULL;

	if (!(iter = malloc(sizeof(*iter))))
		return NULL;

	iter->store = sid_res_get_data(kv_store_res);

	switch (iter->store->backend) {
		case SID_KVS_BACKEND_HASH:
			// TODO: use key_start and key_end
			iter->ht.current = NULL;
			break;

		case SID_KVS_BACKEND_BPTREE:
			switch (method) {
				case ITER_EXACT:
					iter->bpt.iter = bptree_iter_create(iter->store->bpt, key_start, key_end);
					break;
				case ITER_PREFIX:
					iter->bpt.iter = bptree_iter_create_prefix(iter->store->bpt, key_start);
					break;
			}

			if (!iter->bpt.iter) {
				free(iter);
				iter = NULL;
			}
			break;
	};

	return iter;
}

sid_kvs_iter_t *sid_kvs_iter_create(sid_res_t *kv_store_res, const char *key_start, const char *key_end)
{
	return _do_sid_kvs_iter_create(kv_store_res, ITER_EXACT, key_start, key_end);
}

sid_kvs_iter_t *sid_kvs_iter_create_prefix(sid_res_t *kv_store_res, const char *prefix)
{
	return _do_sid_kvs_iter_create(kv_store_res, ITER_PREFIX, prefix, NULL);
}

void *sid_kvs_iter_current(sid_kvs_iter_t *iter, size_t *size, sid_kvs_val_fl_t *flags)
{
	struct kv_store_value *value;

	if (!iter)
		return NULL;

	value = NULL;

	switch (iter->store->backend) {
		case SID_KVS_BACKEND_HASH:
			value = iter->ht.current ? hash_get_data(iter->store->ht, iter->ht.current, NULL) : NULL;
			break;

		case SID_KVS_BACKEND_BPTREE:
			value = bptree_iter_current(iter->bpt.iter, NULL, NULL, NULL);
			break;
	}

	if (!value)
		return NULL;

	if (size)
		*size = value->size;

	if (flags)
		*flags = value->ext_flags;

	return _get_data(value);
}

int sid_kvs_iter_current_size(sid_kvs_iter_t *iter,
                              size_t         *int_size,
                              size_t         *int_data_size,
                              size_t         *ext_size,
                              size_t         *ext_data_size)
{
	size_t                 iov_size, data_size;
	struct kv_store_value *value;

	if (!iter || !int_size || !int_data_size || !ext_size || !ext_data_size)
		return -1;

	value = NULL;

	switch (iter->store->backend) {
		case SID_KVS_BACKEND_HASH:
			value = iter->ht.current ? hash_get_data(iter->store->ht, iter->ht.current, NULL) : NULL;
			break;

		case SID_KVS_BACKEND_BPTREE:
			value = bptree_iter_current(iter->bpt.iter, NULL, NULL, NULL);
			break;
	}

	if (!value)
		return -1;

	if (value->ext_flags & SID_KVS_VAL_FL_VECTOR) {
		int           i;
		struct iovec *iov;

		iov      = (value->ext_flags & SID_KVS_VAL_FL_REF) ? _get_ptr(value->data) : (struct iovec *) value->data;

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
	if (value->ext_flags & SID_KVS_VAL_FL_REF) {
		*int_size += sizeof(*value) + sizeof(uintptr_t);
		*ext_size += iov_size;
	} else
		*int_size += sizeof(*value) + iov_size;

	return 0;
}

const char *sid_kvs_iter_current_key(sid_kvs_iter_t *iter)
{
	const char *key;

	if (!iter)
		return NULL;

	switch (iter->store->backend) {
		case SID_KVS_BACKEND_HASH:
			return iter->ht.current ? hash_get_key(iter->store->ht, iter->ht.current, NULL) : NULL;

		case SID_KVS_BACKEND_BPTREE:
			return bptree_iter_current(iter->bpt.iter, &key, NULL, NULL) ? key : NULL;

		default:
			return NULL;
	}
}

void *sid_kvs_iter_next(sid_kvs_iter_t *iter, size_t *size, const char **return_key, sid_kvs_val_fl_t *flags)
{
	if (!iter)
		return NULL;

	switch (iter->store->backend) {
		case SID_KVS_BACKEND_HASH:
			iter->ht.current = iter->ht.current ? hash_get_next(iter->store->ht, iter->ht.current)
			                                    : hash_get_first(iter->store->ht);
			break;

		case SID_KVS_BACKEND_BPTREE:
			bptree_iter_next(iter->bpt.iter, NULL, NULL, NULL);
			break;
	}

	if (return_key != NULL)
		*return_key = sid_kvs_iter_current_key(iter);

	return sid_kvs_iter_current(iter, size, flags);
}

void _do_sid_kvs_iter_reset(sid_kvs_iter_t *iter, kvs_iter_method_t method, const char *key_start, const char *key_end)
{
	if (!iter)
		return;

	switch (iter->store->backend) {
		case SID_KVS_BACKEND_HASH:
			// TODO: use key_start and key_end
			iter->ht.current = NULL;
			break;

		case SID_KVS_BACKEND_BPTREE:
			switch (method) {
				case ITER_EXACT:
					bptree_iter_reset(iter->bpt.iter, key_start, key_end);
					break;
				case ITER_PREFIX:
					bptree_iter_reset_prefix(iter->bpt.iter, key_start);
					break;
			}
			break;
	}
}

void sid_kvs_iter_reset(sid_kvs_iter_t *iter, const char *key_start, const char *key_end)
{
	_do_sid_kvs_iter_reset(iter, ITER_EXACT, key_start, key_end);
}

void sid_kvs_iter_reset_prefix(sid_kvs_iter_t *iter, const char *prefix)
{
	_do_sid_kvs_iter_reset(iter, ITER_PREFIX, prefix, NULL);
}

void sid_kvs_iter_destroy(sid_kvs_iter_t *iter)
{
	if (!iter)
		return;

	switch (iter->store->backend) {
		case SID_KVS_BACKEND_HASH:
			free(iter);
			break;

		case SID_KVS_BACKEND_BPTREE:
			bptree_iter_destroy(iter->bpt.iter);
			free(iter);
			break;
	}
}

size_t kv_store_num_entries(sid_res_t *kv_store_res)
{
	struct kv_store *kv_store = sid_res_get_data(kv_store_res);

	switch (kv_store->backend) {
		case SID_KVS_BACKEND_HASH:
			return hash_get_entry_count(kv_store->ht);

		case SID_KVS_BACKEND_BPTREE:
			return bptree_get_entry_count(kv_store->bpt);

		default:
			return 0;
	}
}

size_t sid_kvs_get_size(sid_res_t *kv_store_res, size_t *meta_size, size_t *data_size)
{
	struct kv_store *kv_store = sid_res_get_data(kv_store_res);

	switch (kv_store->backend) {
		case SID_KVS_BACKEND_HASH:
			return hash_get_size(kv_store->ht, meta_size, data_size);

		case SID_KVS_BACKEND_BPTREE:
			return bptree_get_size(kv_store->bpt, meta_size, data_size);

		default:
			return 0;
	}
}

static int _init_kv_store(sid_res_t *kv_store_res, const void *kickstart_data, void **data)
{
	const struct sid_kvs_res_params *params = kickstart_data;
	struct kv_store                 *kv_store;

	if (!(kv_store = mem_zalloc(sizeof(*kv_store)))) {
		sid_res_log_error(kv_store_res, "Failed to allocate key-value store structure.");
		goto out;
	}

	kv_store->backend = params->backend;

	switch (kv_store->backend) {
		case SID_KVS_BACKEND_HASH:
			if (!(kv_store->ht = hash_create(params->hash.initial_size))) {
				sid_res_log_error(kv_store_res, "Failed to create hash table for key-value store.");
				goto out;
			}
			break;

		case SID_KVS_BACKEND_BPTREE:
			if (!(kv_store->bpt = bptree_create(params->bptree.order))) {
				sid_res_log_error(kv_store_res, "Failed to create B+ tree for key-value store.");
				goto out;
			}
	}

	*data = kv_store;
	return 0;
out:
	free(kv_store);
	return -1;
}

static int _destroy_kv_store(sid_res_t *kv_store_res)
{
	struct kv_store *kv_store = sid_res_get_data(kv_store_res);

	switch (kv_store->backend) {
		case SID_KVS_BACKEND_HASH:
			hash_iter(kv_store->ht, _hash_destroy_kv_store_value);
			hash_destroy(kv_store->ht);
			break;

		case SID_KVS_BACKEND_BPTREE:
			bptree_destroy_with_fn(kv_store->bpt, _bptree_destroy_kv_store_value, NULL);
			break;
	}

	free(kv_store);
	return 0;
}

const sid_res_type_t sid_res_type_kvs = {
	.name        = "kv-store",
	.short_name  = "kvs",
	.description = "Resource providing key-value store capabilities with selectable backends.",
	.init        = _init_kv_store,
	.destroy     = _destroy_kv_store,
};
