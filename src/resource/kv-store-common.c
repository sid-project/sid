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

static void _set_ptr(void *dest, const void *p)
{
	memcpy(dest, (void *) &p, sizeof(intptr_t));
}

// TODO: should this be shared with the db implementation?
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

	return value->ext_flags & KV_STORE_VALUE_REF ? _get_ptr_db(value->data) : value->data;
}

struct kv_store_value *_create_kv_store_value(struct iovec *            iov,
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