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

#include "buffer-type.h"

#include "base/mem.h"

#include <errno.h>
#include <sys/uio.h>

#define VECTOR_ITEM_SIZE sizeof(struct iovec)

static int _buffer_vector_create(struct buffer *buf)
{
	size_t needed;

	struct iovec *iov;

	needed = buf->stat.initial_size;
	if (buf->stat.mode == BUFFER_MODE_SIZE_PREFIX)
		needed += 1;

	if (!(buf->mem = mem_zalloc(needed * VECTOR_ITEM_SIZE)))
		return -ENOMEM;

	if (buf->stat.mode == BUFFER_MODE_SIZE_PREFIX) {
		iov = buf->mem;
		if (!(iov[0].iov_base = mem_zalloc(MSG_SIZE_PREFIX_LEN))) {
			free(buf->mem);
			return -ENOMEM;
		}
		iov[0].iov_len = MSG_SIZE_PREFIX_LEN;
	}

	buf->stat.allocated = needed;
	return 0;
}

int _buffer_vector_destroy(struct buffer *buf)
{
	struct iovec *iov;

	if (buf->stat.mode == BUFFER_MODE_SIZE_PREFIX) {
		iov = buf->mem;
		free(iov[0].iov_base);
	}

	free(buf->mem);
	return 0;
}

static int _buffer_vector_realloc(struct buffer *buf, size_t needed, int force)
{
	void *p;
	size_t align;
	size_t alloc_step;

	if (!force) {
		if (buf->stat.allocated >= needed)
			return 0;

		if (!(alloc_step = buf->stat.alloc_step))
			return -ENOMEM;
	} else
		alloc_step = 1;

	if ((align = (needed % alloc_step)))
		needed += alloc_step - align;

	if (!(p = realloc(buf->mem, needed * VECTOR_ITEM_SIZE)))
		return -errno;

	buf->mem = p;
	buf->stat.allocated = needed;

	return 0;
}

int _buffer_vector_reset(struct buffer *buf)
{
	size_t needed;

	buf->stat.used = 0;

	needed = buf->stat.initial_size;

	if (!needed) {
		switch (buf->stat.mode) {
			case BUFFER_MODE_PLAIN:
				/* keep needed = 0 */
				break;
			case BUFFER_MODE_SIZE_PREFIX:
				needed = 1;
				break;
		}
	}

	return _buffer_vector_realloc(buf, needed, 1);
}

const void *_buffer_vector_add(struct buffer *buf, void *data, size_t len, int *ret_code)
{
	size_t used = buf->stat.used;
	struct iovec *iov;
	int r;

	if (!used && buf->stat.mode == BUFFER_MODE_SIZE_PREFIX)
		used = 1;

	if ((r = _buffer_vector_realloc(buf, used + 1, 0)) < 0)
		goto out;;

	iov = buf->mem;
	iov[used].iov_base = data;
	iov[used].iov_len = len;
	buf->stat.used = used + 1;
out:
	if (ret_code)
		*ret_code = r;
	if (r < 0)
		return NULL;
	else
		return &iov[buf->stat.used - 1];
}

const void *_buffer_vector_fmt_add(struct buffer *buf, int *ret_code, const char *fmt, va_list ap)
{
	if (ret_code)
		*ret_code = -ENOTSUP;
	return NULL;
}

int _buffer_vector_rewind(struct buffer *buf, size_t pos)
{
	size_t min_pos = (buf->stat.mode == BUFFER_MODE_SIZE_PREFIX) ? 1 : 0;

	if (pos > buf->stat.used || pos < min_pos)
		return -EINVAL;

	buf->stat.used = pos;
	return 0;
}

int _buffer_vector_rewind_mem(struct buffer *buf, const void *mem)
{
	return _buffer_vector_rewind(buf, (struct iovec *)mem - (struct iovec *)buf->mem);
}

bool _buffer_vector_is_complete(struct buffer *buf, int *ret_code)
{
	/*	struct iovec *iov;
		MSG_SIZE_PREFIX_TYPE size_prefix;
		size_t size = 0;
		unsigned i;

		switch (buf->mode) {
			case BUFFER_MODE_PLAIN:
				return true;
			case BUFFER_MODE_SIZE_PREFIX:
				iov = buf->mem;
				size_prefix = *((MSG_SIZE_PREFIX_TYPE *) iov[0].iov_base);
				for (i = 1; i < buf->used; i++)
					size += iov[i].iov_len;
				return buf->used && size_prefix == size;
		}
	*/
	if (*ret_code)
		*ret_code = -ENOTSUP;
	return true;
}

int _buffer_vector_get_data(struct buffer *buf, const void **data, size_t *data_size)
{
	switch (buf->stat.mode) {
		case BUFFER_MODE_PLAIN:
			if (data)
				*data = buf->mem;
			if (data_size)
				*data_size = buf->stat.used;
			break;
		case BUFFER_MODE_SIZE_PREFIX:
			if (data)
				*data = buf->mem + VECTOR_ITEM_SIZE;
			if (data_size)
				*data_size = buf->stat.used - 1;
			break;
	}

	return 0;
}

static ssize_t _buffer_vector_read_plain(struct buffer *buf, int fd)
{
	return -ENOTSUP;
}

static ssize_t _buffer_vector_read_with_size_prefix(struct buffer *buf, int fd)
{
	return -ENOTSUP;
}

ssize_t _buffer_vector_read(struct buffer *buf, int fd)
{
	switch (buf->stat.mode) {
		case BUFFER_MODE_PLAIN:
			return _buffer_vector_read_plain(buf, fd);
		case BUFFER_MODE_SIZE_PREFIX:
			return _buffer_vector_read_with_size_prefix(buf, fd);
	}

	return -1;
}

ssize_t _buffer_vector_write(struct buffer *buf, int fd, size_t pos)
{
	struct iovec *iov = buf->mem;
	MSG_SIZE_PREFIX_TYPE size_prefix = 0;
	unsigned i, start_idx = 0;
	void *save_base;
	size_t save_len, start_off = pos;
	ssize_t n;

	if (pos < 0)
		return -ERANGE;

	if (buf->stat.mode == BUFFER_MODE_SIZE_PREFIX) {
		for (i = 0; i < buf->stat.used; i++)
			size_prefix += iov[i].iov_len;
		*((MSG_SIZE_PREFIX_TYPE *) iov[0].iov_base) = size_prefix;
	}

	i = 0;
	if (pos) {
		for ( ; i < buf->stat.used; i++) {
			if (iov[i].iov_len > start_off) {
				start_idx = i;
				save_base = iov[i].iov_base;
				save_len = iov[i].iov_len;
				iov[i].iov_base += start_off;
				iov[i].iov_len -= start_off;
				break;
			}
			start_off -= iov[i].iov_len;
		}
	}
	if (i == buf->stat.used) {
		if (start_off == 0)
			return -ENODATA;
		else
			return -ERANGE;
	}

	n = writev(fd, &iov[start_idx], buf->stat.used - start_idx);
	if (pos) {
		iov[start_idx].iov_base = save_base;
		iov[start_idx].iov_len = save_len;
	}
	if (n < 0)
		n = -errno;

	return n;
}

const struct buffer_type buffer_type_vector = {
	.create = _buffer_vector_create,
	.destroy = _buffer_vector_destroy,
	.reset = _buffer_vector_reset,
	.add = _buffer_vector_add,
	.fmt_add = _buffer_vector_fmt_add,
	.rewind = _buffer_vector_rewind,
	.rewind_mem = _buffer_vector_rewind_mem,
	.is_complete = _buffer_vector_is_complete,
	.get_data = _buffer_vector_get_data,
	.read = _buffer_vector_read,
	.write = _buffer_vector_write
};
