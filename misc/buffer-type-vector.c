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

#include "buffer-type.h"
#include "mem.h"

#include <errno.h>
#include <sys/uio.h>

#define VECTOR_ITEM_SIZE sizeof(struct iovec)

static int _buffer_vector_create(struct buffer *buf, size_t initial_size)
{
	struct iovec *iov;

	if (buf->mode == BUFFER_MODE_SIZE_PREFIX)
		initial_size += 1;

	if (!(buf->mem = zalloc(initial_size * VECTOR_ITEM_SIZE))) {
		errno = ENOMEM;
		return -1;
	}

	if (buf->mode == BUFFER_MODE_SIZE_PREFIX) {
		iov = buf->mem;
		if (!(iov[0].iov_base = zalloc(MSG_SIZE_PREFIX_LEN))) {
			free(buf->mem);
			errno = ENOMEM;
			return -1;
		}
		iov[0].iov_len = MSG_SIZE_PREFIX_LEN;
	}

	buf->allocated = initial_size;
	return 0;
}

int _buffer_vector_destroy(struct buffer *buf)
{
	struct iovec *iov;

	if (buf->mode == BUFFER_MODE_SIZE_PREFIX) {
		iov = buf->mem;
		free(iov[0].iov_base);
	}

	free(buf->mem);
	return 0;
}

static int _buffer_vector_realloc(struct buffer *buf, size_t needed, int force)
{
	char *p;
	size_t align;

	if (!force && buf->allocated >= needed)
		return 0;

	if ((align = (needed % buf->alloc_step)))
		needed += buf->alloc_step - align;

	if (!(p = realloc(buf->mem, needed * VECTOR_ITEM_SIZE)))
		return -errno;

	buf->mem = p;
	buf->allocated = needed;

	return 0;
}

int _buffer_vector_reset(struct buffer *buf, size_t initial_size)
{
	buf->used = 0;

	if (!initial_size) {
		switch (buf->mode) {
			case BUFFER_MODE_PLAIN:
				/* keep initial_size = 0 */
				break;
			case BUFFER_MODE_SIZE_PREFIX:
				initial_size = 1;
				break;
		}
	}

	return _buffer_vector_realloc(buf, initial_size, 1);
}

int _buffer_vector_add(struct buffer *buf, void *data, size_t len)
{
	size_t used = buf->used;
	struct iovec *iov;
	int r;

	if (!used && buf->mode == BUFFER_MODE_SIZE_PREFIX)
		used = 1;

	if ((r = _buffer_vector_realloc(buf, used + 1, 0)) < 0)
		return r;

	iov = buf->mem;
	iov[used].iov_base = data;
	iov[used].iov_len = len;
	buf->used = used + 1;

	return 0;
}

bool _buffer_vector_is_complete(struct buffer *buf)
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
	return true;
}

int _buffer_vector_get_data(struct buffer *buf, const void **data, size_t *data_len)
{
	switch (buf->mode) {
		case BUFFER_MODE_PLAIN:
			*data = buf->mem;
			*data_len = buf->used;
			break;
		case BUFFER_MODE_SIZE_PREFIX:
			*data = buf->mem + VECTOR_ITEM_SIZE;
			*data_len = buf->used - 1;
			break;
	}

	return 0;
}

static ssize_t _buffer_vector_read_plain(struct buffer *buf, int fd)
{
	return 0;
}

static ssize_t _buffer_vector_read_with_size_prefix(struct buffer *buf, int fd)
{
	return 0;
}

ssize_t _buffer_vector_read(struct buffer *buf, int fd)
{
	switch (buf->mode) {
		case BUFFER_MODE_PLAIN:
			return _buffer_vector_read_plain(buf, fd);
		case BUFFER_MODE_SIZE_PREFIX:
			return _buffer_vector_read_with_size_prefix(buf, fd);
	}

	return -1;
}

ssize_t _buffer_vector_write(struct buffer *buf, int fd)
{
	struct iovec *iov = buf->mem;
	MSG_SIZE_PREFIX_TYPE size_prefix = 0;
	unsigned i;

	if (buf->mode == BUFFER_MODE_SIZE_PREFIX) {
		for (i = 0; i < buf->used; i++)
			size_prefix += iov[i].iov_len;
		*((MSG_SIZE_PREFIX_TYPE *) iov[0].iov_base) = size_prefix;
	}

	return writev(fd, (const struct iovec *) buf->mem, buf->used);
}

const struct buffer_type buffer_type_vector = {
	.create = _buffer_vector_create,
	.destroy = _buffer_vector_destroy,
	.reset = _buffer_vector_reset,
	.add = _buffer_vector_add,
	.is_complete = _buffer_vector_is_complete,
	.get_data = _buffer_vector_get_data,
	.read = _buffer_vector_read,
	.write = _buffer_vector_write
};
