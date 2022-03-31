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

#include "base/buffer.h"

#include "base/buffer-type.h"

#include <errno.h>
#include <stdlib.h>

static const struct sid_buffer_type *_buffer_type_registry[] =
	{[SID_BUFFER_TYPE_LINEAR] = &sid_buffer_type_linear, [SID_BUFFER_TYPE_VECTOR] = &sid_buffer_type_vector};

static bool _check_buf(struct sid_buffer *buf)
{
	struct sid_buffer_stat *stat = &buf->stat;

	/* We are checking only limit right now so if no limit, nothing to check as well. */
	if (stat->init.limit == 0)
		return true;

	return (stat->init.limit >= stat->init.size && stat->init.limit >= stat->init.alloc_step &&
	        stat->init.limit % stat->init.alloc_step == 0);
}

struct sid_buffer *sid_buffer_create(struct sid_buffer_spec *spec, struct sid_buffer_init *init, int *ret_code)
{
	struct sid_buffer *buf;
	int                r = 0;

	if (!(buf = malloc(sizeof(*buf)))) {
		r = -ENOMEM;
		goto out;
	}

	buf->stat = (struct sid_buffer_stat) {
		.spec  = *spec,
		.init  = *init,
		.usage = (struct sid_buffer_usage) {0},
	};

	buf->mem = NULL;
	buf->fd  = -1;

	if (!_check_buf(buf)) {
		r = -EINVAL;
		goto out;
	}

	if ((r = _buffer_type_registry[spec->type]->create(buf)) < 0)
		goto out;
out:
	if (ret_code)
		*ret_code = r;
	if (r < 0) {
		free(buf);
		return NULL;
	} else
		return buf;
}

void sid_buffer_destroy(struct sid_buffer *buf)
{
	(void) _buffer_type_registry[buf->stat.spec.type]->destroy(buf);
	free(buf);
}

int sid_buffer_reset_init(struct sid_buffer *buf, struct sid_buffer_init *init)
{
	struct sid_buffer_stat orig_stat = buf->stat;

	buf->stat.init = *init;

	if (!_check_buf(buf)) {
		buf->stat = orig_stat;
		return -EINVAL;
	}

	return _buffer_type_registry[buf->stat.spec.type]->reset(buf);
}

int sid_buffer_reset(struct sid_buffer *buf)
{
	return _buffer_type_registry[buf->stat.spec.type]->reset(buf);
}

const void *sid_buffer_add(struct sid_buffer *buf, void *data, size_t len, int *ret_code)
{
	return _buffer_type_registry[buf->stat.spec.type]->add(buf, data, len, ret_code);
}

const void *sid_buffer_fmt_add(struct sid_buffer *buf, int *ret_code, const char *fmt, ...)
{
	va_list     ap;
	const void *p;

	va_start(ap, fmt);
	p = _buffer_type_registry[buf->stat.spec.type]->fmt_add(buf, ret_code, fmt, ap);
	va_end(ap);

	return p;
}

const void *sid_buffer_vfmt_add(struct sid_buffer *buf, int *ret_code, const char *fmt, va_list ap)
{
	return _buffer_type_registry[buf->stat.spec.type]->fmt_add(buf, ret_code, fmt, ap);
}

int sid_buffer_rewind(struct sid_buffer *buf, size_t pos, sid_buffer_pos_t whence)
{
	if (whence == SID_BUFFER_POS_REL) {
		if (pos == 0)
			return 0; /* otherwise this fails on an empty size-prefixed buffer */
		if (pos > buf->stat.usage.used)
			return -EINVAL;

		pos = buf->stat.usage.used - pos;
	}

	return _buffer_type_registry[buf->stat.spec.type]->rewind(buf, pos);
}

int sid_buffer_rewind_mem(struct sid_buffer *buf, const void *mem)
{
	if (mem < buf->mem)
		return -EINVAL;

	return _buffer_type_registry[buf->stat.spec.type]->rewind_mem(buf, mem);
}

bool sid_buffer_is_complete(struct sid_buffer *buf, int *ret_code)
{
	return _buffer_type_registry[buf->stat.spec.type]->is_complete(buf, ret_code);
}

int sid_buffer_get_data(struct sid_buffer *buf, const void **data, size_t *data_size)
{
	return _buffer_type_registry[buf->stat.spec.type]->get_data(buf, data, data_size);
}

int sid_buffer_get_fd(struct sid_buffer *buf)
{
	return _buffer_type_registry[buf->stat.spec.type]->get_fd(buf);
}

ssize_t sid_buffer_read(struct sid_buffer *buf, int fd)
{
	return _buffer_type_registry[buf->stat.spec.type]->read(buf, fd);
}

ssize_t sid_buffer_write(struct sid_buffer *buf, int fd, size_t pos)
{
	return _buffer_type_registry[buf->stat.spec.type]->write(buf, fd, pos);
}

size_t sid_buffer_count(struct sid_buffer *buf)
{
	return _buffer_type_registry[buf->stat.spec.type]->count(buf);
}

struct sid_buffer_stat sid_buffer_stat(struct sid_buffer *buf)
{
	return buf->stat;
}

int sid_buffer_write_all(struct sid_buffer *buf, int fd)
{
	size_t  pos;
	ssize_t n;

	if (!buf || fd < 0)
		return -EINVAL;

	for (pos = 0;; pos += n) {
		n = sid_buffer_write(buf, fd, pos);

		if (n < 0) {
			if (n == -ENODATA)
				break;

			if (n == -EAGAIN || n == -EINTR) {
				n = 0;
				continue;
			}
			return n;
		}
	}
	return 0;
}
