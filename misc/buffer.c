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

#include "buffer.h"
#include "buffer-type.h"
#include "mem.h"
#include <errno.h>

static const struct buffer_type *_buffer_type_registry[] =
{
	[BUFFER_TYPE_LINEAR] = &buffer_type_linear,
	[BUFFER_TYPE_VECTOR] = &buffer_type_vector
};

struct buffer *buffer_create(buffer_type_t type, buffer_mode_t mode, size_t initial_size, size_t alloc_step)
{
	struct buffer *buf;

	if (!(buf = zalloc(sizeof(*buf))))
		goto fail;

	buf->type = type;
	buf->mode = mode;
	buf->alloc_step = alloc_step;

	if (_buffer_type_registry[type]->create(buf, initial_size) < 0)
		goto fail;

	return buf;
fail:
	free(buf);
	return NULL;
}

void buffer_destroy(struct buffer *buf)
{
	(void) _buffer_type_registry[buf->type]->destroy(buf);
	free(buf);
}

int buffer_reset(struct buffer *buf, size_t initial_size, size_t alloc_step)
{
	buf->alloc_step = alloc_step;
	return _buffer_type_registry[buf->type]->reset(buf, initial_size);
}

const void *buffer_add(struct buffer *buf, void *data, size_t len)
{
	if (!data || !len) {
		errno = EINVAL;
		return NULL;
	}

	return _buffer_type_registry[buf->type]->add(buf, data, len);
}

int buffer_rewind(struct buffer *buf, size_t pos, buffer_pos_t whence)
{
	if (whence == BUFFER_POS_REL) {
		if (pos > buf->used) {
			errno = EINVAL;
			return -1;
		}

		pos = buf->used - pos;
	}

	return _buffer_type_registry[buf->type]->rewind(buf, pos);
}

bool buffer_is_complete(struct buffer *buf)
{
	return _buffer_type_registry[buf->type]->is_complete(buf);
}

int buffer_get_data(struct buffer *buf, const void **data, size_t *data_len)
{
	return _buffer_type_registry[buf->type]->get_data(buf, data, data_len);
}

ssize_t buffer_read(struct buffer *buf, int fd)
{
	return _buffer_type_registry[buf->type]->read(buf, fd);
}

ssize_t buffer_write(struct buffer *buf, int fd)
{
	return _buffer_type_registry[buf->type]->write(buf, fd);
}
