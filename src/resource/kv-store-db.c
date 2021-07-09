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

#include "internal/hash.h"
#include "internal/mem.h"
#include "log/log.h"
#include "resource/kv-store.h"
#include "resource/resource.h"

#include <dirent.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

static void _set_ptr_db(void *dest, const void *p)
{
	memcpy(dest, (void *) &p, sizeof(intptr_t));
}

// TODO: should this be shared with the db implementation?
static void *_get_ptr_db(const void *src)
{
	intptr_t ptr;

	memcpy(&ptr, src, sizeof(ptr));
	return (void *) ptr;
}

static void *_get_data_db(struct kv_store_value *value)
{
	if (!value)
		return NULL;

	return value->ext_flags & KV_STORE_VALUE_REF ? _get_ptr_db(value->data) : value->data;
}

struct kv_store_value *_create_kv_store_value_db(struct iovec *            iov,
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
			_set_ptr_db(value->data, iov);
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

			_set_ptr_db(value->data, iov[0].iov_base);
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

void *kv_store_set_value_db(sid_resource_t *          kv_store_res,
                            const char *              key,
                            void *                    value,
                            size_t                    value_size,
                            kv_store_value_flags_t    flags,
                            kv_store_value_op_flags_t op_flags,
                            kv_store_update_fn_t      kv_update_fn,
                            void *                    kv_update_fn_arg)
{
	struct kv_store *      kv_store     = sid_resource_get_data(kv_store_res);
	struct iovec           iov_internal = {.iov_base = value, .iov_len = value_size};
	struct iovec *         iov;
	int                    iov_cnt;
	size_t                 kv_store_value_size;
	struct kv_store_value *kv_store_value;
	MDB_txn *              txn;
	MDB_val                mdb_key, data;
	int                    rc;

	if (flags & KV_STORE_VALUE_VECTOR) {
		iov     = value;
		iov_cnt = value_size;
	} else {
		iov     = &iov_internal;
		iov_cnt = 1;
	}

	if (!(kv_store_value = _create_kv_store_value(iov, iov_cnt, flags, op_flags, &kv_store_value_size)))
		return NULL;

	mdb_key.mv_size = strlen(key) + 1;
	mdb_key.mv_data = (void *) key;
	data.mv_size    = kv_store_value_size;
	data.mv_data    = kv_store_value;

	if ((rc = mdb_txn_begin(kv_store->env, NULL, 0, &txn)) != 0) {
		log_error("ITER", "mdb_txn_begin error,detail:%s\n", mdb_strerror(rc));
		return NULL;
	}

	if ((rc = mdb_put(txn, kv_store->dbi, &mdb_key, &data, 0)) != 0) {
		log_error("ITER", "mdb_put error,detail:%s\n", mdb_strerror(rc));
		return NULL;
	}

	if ((rc = mdb_txn_commit(txn)) != 0) {
		log_error("ITER", "mdb_txn_commit: (%d) %s\n", rc, mdb_strerror(rc));
		return NULL;
	}

	return value;
}

void *kv_store_get_value_db(sid_resource_t *kv_store_res, const char *key, size_t *size, kv_store_value_flags_t *flags)
{
	struct kv_store *      kv_store = sid_resource_get_data(kv_store_res);
	struct kv_store_value *value;
	int                    rc;
	MDB_txn *              txn;
	MDB_val                mdb_key;
	MDB_val                data;

	mdb_key.mv_size = strlen(key);
	mdb_key.mv_data = NULL;

	if ((rc = mdb_txn_begin(kv_store->env, NULL, 0, &txn)) != 0) {
		log_error("ITER", "mdb_txn_begin error,detail:%s\n", mdb_strerror(rc));
		return NULL;
	}

	// TODO: if we support duplicate keys, we need to use a cursor for the get
	if ((rc = mdb_get(txn, kv_store->dbi, &mdb_key, &data)) != 0) {
		if (rc == MDB_NOTFOUND) {
			if (size)
				*size = 0;
			return NULL;
		}
		log_error("ITER", "mdb_get error,detail:%s\n", mdb_strerror(rc));
		return NULL;
	}

	if (!(value = mem_zalloc(data.mv_size))) {
		log_error("ITER", "Failed to allocate kv_store_value structure in kv_store_iter_current.");
	}
	memcpy(value, data.mv_data, data.mv_size);

	if ((rc = mdb_txn_commit(txn)) != 0) {
		log_error("ITER", "mdb_txn_commit: (%d) %s\n", rc, mdb_strerror(rc));
		return NULL;
	}

	if (size)
		*size = value->size;

	if (flags)
		*flags = value->ext_flags;

	/* TODO: fix memory leaked here */
	return value;
}

int kv_store_unset_value_db(sid_resource_t *kv_store_res, const char *key, kv_store_update_fn_t kv_unset_fn, void *kv_unset_fn_arg)
{
	struct kv_store *kv_store = sid_resource_get_data(kv_store_res);
	MDB_txn *        txn;
	MDB_val          mdb_key;
	MDB_val          mdb_value;
	int              rc;

	mdb_key.mv_size = strlen(key);
	mdb_key.mv_data = NULL;

	if ((rc = mdb_txn_begin(kv_store->env, NULL, 0, &txn)) != 0) {
		log_error("LMDB", "mdb_txn_begin error,detail:%s\n", mdb_strerror(rc));
		return -1;
	}

	// TODO: if we support duplicate keys, we need to use a cursor for the get
	if ((rc = mdb_del(txn, kv_store->dbi, &mdb_key, &mdb_value)) != 0) {
		if (rc == MDB_NOTFOUND) {
			return -1;
		}
		log_error("LMDB", "mdb_del error,detail:%s\n", mdb_strerror(rc));
		return -1;
	}

	if ((rc = mdb_txn_commit(txn)) != 0) {
		log_error("LMDB", "mdb_txn_commit: (%d) %s\n", rc, mdb_strerror(rc));
		return -1;
	}

	return 0;
}

kv_store_iter_t *kv_store_iter_create_db(sid_resource_t *kv_store_res)
{
	kv_store_iter_t *iter;
	struct kv_store *kv_store = sid_resource_get_data(kv_store_res);
	int              rc;

	if (!(iter = mem_zalloc(sizeof(*iter))))
		return NULL;
	iter->backend = KV_STORE_BACKEND_LMDB;
	iter->env     = kv_store->env;
	if ((rc = mdb_txn_begin(kv_store->env, NULL, MDB_RDONLY, &iter->txn)) != 0) {
		log_error(ID(kv_store_res), "mdb_txn_begin failed.");
	}

	if ((rc = mdb_cursor_open(iter->txn, kv_store->dbi, &iter->cursor)) != 0) {
		log_error(ID(kv_store_res), "mdb_cursor_open failed.");
	}

	return iter;
}

void *kv_store_iter_current_db(kv_store_iter_t *iter, size_t *size, kv_store_value_flags_t *flags)
{
	MDB_val                key, data;
	struct kv_store_value *value;
	int                    rc;

	if ((rc = mdb_cursor_get(iter->cursor, &key, &data, MDB_NEXT)) != 0) {
		log_error("kv_store_iter_current", "mdb_cursor_open failed.");
		return NULL;
	}

	if (!(value = mem_zalloc(data.mv_size))) {
		log_error("ITER", "Failed to allocate kv_store_value structure in kv_store_iter_current.");
		return NULL;
	}
	memcpy(value, data.mv_data, data.mv_size);

	if (size)
		*size = value->size;

	if (flags)
		*flags = value->ext_flags;

	/* TODO: this memory will be leaked */
	return value;
}

int kv_store_iter_current_size_db(kv_store_iter_t *iter,
                                  size_t *         int_size,
                                  size_t *         int_data_size,
                                  size_t *         ext_size,
                                  size_t *         ext_data_size)
{
	struct kv_store_value *value;
	MDB_val                key, data;
	int                    rc;

	if (!iter || !int_size || !int_data_size || !ext_size || !ext_data_size)
		return -1;

	if ((rc = mdb_cursor_get(iter->cursor, &key, &data, MDB_GET_CURRENT)) != 0) {
		log_error("iter", "mdb_cursor_get failed. detail:%s\n", mdb_strerror(rc));
	}

	/* TODO this is not complete */
	*int_size += sizeof(*value) + data.mv_size;

	return 0;
}

const char *kv_store_iter_current_key_db(kv_store_iter_t *iter)
{
	MDB_val key, data;
	char *  ret_key;
	int     rc;

	if ((rc = mdb_cursor_get(iter->cursor, &key, &data, MDB_GET_CURRENT)) != 0) {
		log_error("kv_store_iter_current", "mdb_cursor_open failed.");
		return NULL;
	}

	if (!(ret_key = (char *) mem_zalloc(key.mv_size))) {
		log_error("ITER", "Failed to allocate kv_store_value structure in kv_store_iter_current.");
		return NULL;
	}
	memcpy(ret_key, key.mv_data, key.mv_size);
	/* TODO: this memory will be leaked */
	return ret_key;
}

void *kv_store_iter_next_db(kv_store_iter_t *iter, size_t *size, const char **return_key, kv_store_value_flags_t *flags)
{
	MDB_val                key, data;
	struct kv_store_value *value;
	int                    rc;

	if (return_key == NULL || *return_key == NULL) {
		log_error("ITER", "Null return key error.");
		return NULL;
	}

	if ((rc = mdb_cursor_get(iter->cursor, &key, &data, MDB_NEXT)) != 0) {
		log_error("ITER", "mdb_cursor_get failed. detail:%s\n", mdb_strerror(rc));
		return NULL;
	}

	if (!(value = mem_zalloc(data.mv_size))) {
		log_error("ITER", "Failed to allocate kv_store_value structure in kv_store_iter_next.");
		return NULL;
	}
	memcpy(value, data.mv_data, data.mv_size);

	if (!(*return_key = mem_zalloc(key.mv_size))) {
		log_error("ITER", "Failed to allocate kv_store_value structure in kv_store_iter_next.");
		return NULL;
	}
	memcpy((char *) *return_key, key.mv_data, key.mv_size);
	if (size)
		*size = value->size;

	if (flags)
		*flags = value->ext_flags;

	*size = data.mv_size;
	/* TODO: fix memory leak */
	return value->data;
}

void kv_store_iter_reset_db(kv_store_iter_t *iter)
{
	mdb_cursor_renew(iter->txn, iter->cursor);
}

void kv_store_iter_destroy_db(kv_store_iter_t *iter)
{
	mdb_cursor_close(iter->cursor);
	mdb_txn_abort(iter->txn);
	iter->cursor = NULL;
	free(iter);
}

size_t kv_store_num_entries_db(sid_resource_t *kv_store_res)
{
	MDB_stat stat;

	struct kv_store *kv_store = sid_resource_get_data(kv_store_res);
	if (mdb_env_stat(kv_store->env, &stat)) {
		log_error(ID(kv_store_res), "mdb_env_stat failed.");
	}
	return stat.ms_entries;
}

size_t kv_store_get_size_db(sid_resource_t *kv_store_res, size_t *meta_size, size_t *data_size)
{
	MDB_stat stat;

	struct kv_store *kv_store = sid_resource_get_data(kv_store_res);
	if (mdb_env_stat(kv_store->env, &stat)) {
		log_error(ID(kv_store_res), "mdb_env_stat failed.");
	}
	// TODO verify this is correct.
	return stat.ms_psize;
}

static int _remove_db_directory(const char *path)
{
	DIR *  d        = opendir(path);
	size_t path_len = strlen(path);
	int    rc       = -1;
	char * name_buffer;
	size_t name_len;

	if (d) {
		struct dirent *p;

		rc = 0;
		while (!rc && (p = readdir(d))) {
			/* skip . and .. */
			if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, ".."))
				continue;

			name_len    = path_len + strlen(p->d_name) + 2;
			name_buffer = mem_zalloc(name_len);

			if (name_buffer) {
				struct stat statbuf;

				snprintf(name_buffer, name_len, "%s/%s", path, p->d_name);
				if (!stat(name_buffer, &statbuf)) {
					if (S_ISDIR(statbuf.st_mode))
						rc = _remove_db_directory(name_buffer);
					else
						rc = unlink(name_buffer);
				}
				free(name_buffer);
			}
		}
		closedir(d);
		if (!rc)
			rc = rmdir(path);
	} else { /* the directory doesn't exist */
		rc = 0;
	}

	return rc;
}

static int _create_db_dir(char *path)
{
	struct stat st;

	if (stat(path, &st) != -1) { /* directory already exists? */

		if (S_ISDIR(st.st_mode)) {
			return 0;
		}

		if (S_ISREG(st.st_mode)) {
			log_error("_create_db_dir", "%s is a regular file, expected directory\n", path);
			goto out;
		}

		goto out;
	} else {
		if (mkdir(path, 0700) == -1) {
			log_error("_create_db_dir", "failed to create database directory %s\n", path);
			goto out;
		}
	}
	return 0;

out:
	return -1;
}

static int _init_kv_store_db(sid_resource_t *kv_store_res, const void *kickstart_data, void **data)
{
	const struct sid_kv_store_resource_params *params   = kickstart_data;
	struct kv_store *                          kv_store = NULL;
	int                                        rc;
	MDB_txn *                                  txn;

	if ((rc = _create_db_dir(params->lmdb.db_dir)) != 0) {
		log_error(ID(kv_store_res), "Failed to create lmdb directory %s\n.", params->lmdb.db_dir);
		goto out;
	}

	if (!(kv_store = mem_zalloc(sizeof(*kv_store)))) {
		log_error(ID(kv_store_res), "Failed to allocate key-value store structure.");
		goto out;
	}

	kv_store->backend = KV_STORE_BACKEND_LMDB;
	if ((rc = mdb_env_create(&kv_store->env)) != 0) {
		log_error(ID(kv_store_res), "mdb_env_create error,detail:%s\n", mdb_strerror(rc));
		goto out;
	}

	// Open the database, if the directory is empty, will initialize a database in the directory
	if ((rc = mdb_env_open(kv_store->env, params->lmdb.db_dir, 0, 0644)) != 0) {
		log_error(ID(kv_store_res), "mdb_env_open error,detail:%s\n", mdb_strerror(rc));
		goto out;
	}

	if ((rc = mdb_txn_begin(kv_store->env, NULL, 0, &txn)) != 0) {
		log_error(ID(kv_store_res), "mdb_txn_begin error,detail:%s\n", mdb_strerror(rc));
		goto out;
	}

	if ((rc = mdb_dbi_open(txn, NULL, 0, &kv_store->dbi)) != 0) {
		log_error(ID(kv_store_res), "mdb_dbi_open failed.");
		goto out;
	};

	if ((rc = mdb_txn_commit(txn)) != 0) {
		log_error(ID(kv_store_res), "mdb_txn_commit: (%d) %s\n", rc, mdb_strerror(rc));
		goto out;
	}

	*data = kv_store;
	return 0;
out:
	if (kv_store != NULL) {
		/* TODO: Cleanup database */
		free(kv_store);
	}
	return -1;
}

static int _drop_database(sid_resource_t *kv_store_res)
{
	MDB_txn *        txn;
	MDB_dbi          dbi;
	int              rc;
	struct kv_store *kv_store = sid_resource_get_data(kv_store_res);

	rc = mdb_txn_begin(kv_store->env, NULL, 0, &txn);
	if (rc) {
		mdb_env_close(kv_store->env);
		return rc;
	}

	rc = mdb_dbi_open(txn, NULL, 0, &dbi);
	if (rc) {
		mdb_txn_abort(txn);
		mdb_env_close(kv_store->env);
		return rc;
	}

	rc = mdb_drop(txn, dbi, 1);
	if (rc) {
		mdb_txn_abort(txn);
		mdb_env_close(kv_store->env);
		return rc;
	}

	rc = mdb_txn_commit(txn);
	if (rc) {
		mdb_env_close(kv_store->env);
		return rc;
	}
	return rc;
}

static int _destroy_kv_store_db(sid_resource_t *kv_store_res)
{
	struct kv_store *kv_store = sid_resource_get_data(kv_store_res);

	mdb_env_close(kv_store->env);
	free(kv_store);

	return 0;
}

const sid_resource_type_t sid_resource_type_kv_store_db = {
	.name    = KV_STORE_NAME,
	.init    = _init_kv_store_db,
	.destroy = _destroy_kv_store_db,
};