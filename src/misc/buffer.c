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

#include "buffer.h"
#include "buffer-type.h"
#include "mem.h"
#include <errno.h>

static const struct buffer_type *_buffer_type_registry[] = {
	[BUFFER_TYPE_LINEAR] = &buffer_type_linear,
	[BUFFER_TYPE_VECTOR] = &buffer_type_vector
};

static bool _check_buf(struct buffer *buf)
{
	struct buffer_stat *stat = &buf->stat;

	/* We are checking only limit right now so if no limit, nothing to check as well. */
	if (stat->limit == 0)
		return true;

	return (stat->limit >= stat->initial_size &&
	        stat->limit >= stat->alloc_step &&
	        stat->limit % stat->alloc_step == 0);
}

struct buffer *buffer_create(buffer_type_t type, buffer_mode_t mode, size_t initial_size, size_t alloc_step, size_t limit, int *ret_code)
{
	struct buffer *buf;
	int r = 0;

	if (!(buf = zalloc(sizeof(*buf)))) {
		r = -ENOMEM;
		goto out;
	}

	buf->stat = (struct buffer_stat) {
		.type = type,
		.mode = mode,
		.initial_size = initial_size,
		.alloc_step = alloc_step,
		.limit = limit,
		.allocated = 0,
		.used = 0,
	};

	if (!_check_buf(buf)) {
		r = -EINVAL;
		goto out;
	}

	if ((r = _buffer_type_registry[type]->create(buf)) < 0)
		goto out;
out:
	if (ret_code)
		*ret_code = r;
	if (r < 0)
		return freen(buf);
	else
		return buf;
}

void buffer_destroy(struct buffer *buf)
{
	(void) _buffer_type_registry[buf->stat.type]->destroy(buf);
	free(buf);
}

int buffer_reset_init(struct buffer *buf, size_t initial_size, size_t alloc_step, size_t limit)
{
	struct buffer_stat orig_stat = buf->stat;

	buf->stat.initial_size = initial_size;
	buf->stat.alloc_step = alloc_step;
	buf->stat.limit = limit;

	if (!_check_buf(buf)) {
		buf->stat = orig_stat;
		return -EINVAL;
	}

	return _buffer_type_registry[buf->stat.type]->reset(buf);
}

int buffer_reset(struct buffer *buf)
{
	return _buffer_type_registry[buf->stat.type]->reset(buf);
}

const void *buffer_add(struct buffer *buf, void *data, size_t len, int *ret_code)
{
	if (!data) {
		if (*ret_code)
			*ret_code = -EINVAL;
		return NULL;
	}

	return _buffer_type_registry[buf->stat.type]->add(buf, data, len, ret_code);
}

const void *buffer_fmt_add(struct buffer *buf, int *ret_code, const char *fmt, ...)
{
	va_list ap;
	const void *p;

	va_start(ap, fmt);
	p = _buffer_type_registry[buf->stat.type]->fmt_add(buf, ret_code, fmt, ap);
	va_end(ap);

	return p;
}

const void *buffer_vfmt_add(struct buffer *buf, int *ret_code, const char *fmt, va_list ap)
{
	return _buffer_type_registry[buf->stat.type]->fmt_add(buf, ret_code, fmt, ap);
}

int buffer_rewind(struct buffer *buf, size_t pos, buffer_pos_t whence)
{
	if (whence == BUFFER_POS_REL) {
		if (pos > buf->stat.used)
			return -EINVAL;

		pos = buf->stat.used - pos;
	}

	return _buffer_type_registry[buf->stat.type]->rewind(buf, pos);
}

int buffer_rewind_mem(struct buffer *buf, const void *mem)
{
	if (mem < buf->mem)
		return -EINVAL;

	return _buffer_type_registry[buf->stat.type]->rewind_mem(buf, mem);
}

bool buffer_is_complete(struct buffer *buf, int *ret_code)
{
	return _buffer_type_registry[buf->stat.type]->is_complete(buf, ret_code);
}

int buffer_get_data(struct buffer *buf, const void **data, size_t *data_size)
{
	return _buffer_type_registry[buf->stat.type]->get_data(buf, data, data_size);
}

ssize_t buffer_read(struct buffer *buf, int fd)
{
	return _buffer_type_registry[buf->stat.type]->read(buf, fd);
}

ssize_t buffer_write(struct buffer *buf, int fd, size_t pos)
{
	return _buffer_type_registry[buf->stat.type]->write(buf, fd, pos);
}

struct buffer_stat buffer_stat(struct buffer *buf)
{
	return buf->stat;
}
