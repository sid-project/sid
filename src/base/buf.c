/*
 * SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "base/buf.h"

#include "base/buf-type.h"

#include <errno.h>
#include <stdlib.h>

static const struct sid_buf_type *_buffer_type_registry[] =
	{[SID_BUF_TYPE_LINEAR] = &sid_buf_type_linear, [SID_BUF_TYPE_VECTOR] = &sid_buf_type_vector};

static bool _check_buf(struct sid_buf *buf)
{
	struct sid_buf_stat *stat = &buf->stat;

	/* We are checking only limit right now so if no limit, nothing to check as well. */
	if (stat->init.limit == 0)
		return true;

	return (stat->init.limit >= stat->init.size && stat->init.limit >= stat->init.alloc_step &&
	        stat->init.limit % stat->init.alloc_step == 0);
}

struct sid_buf *sid_buf_create(const struct sid_buf_spec *spec, const struct sid_buf_init *init, int *ret_code)
{
	struct sid_buf *buf = NULL;
	int             r   = 0;

	if (!spec || !init) {
		r = -EINVAL;
		goto out;
	}

	if (!(buf = malloc(sizeof(*buf)))) {
		r = -ENOMEM;
		goto out;
	}

	buf->stat = (struct sid_buf_stat) {
		.spec  = *spec,
		.init  = *init,
		.usage = (struct sid_buf_usage) {0},
	};

	buf->mem      = NULL;
	buf->fd       = -1;
	buf->mark.set = false;
	buf->mark.pos = 0;

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

void sid_buf_destroy(struct sid_buf *buf)
{
	(void) _buffer_type_registry[buf->stat.spec.type]->destroy(buf);
	free(buf);
}

int sid_buf_reset_init(struct sid_buf *buf, const struct sid_buf_init *init)
{
	struct sid_buf_stat orig_stat = buf->stat;

	if (!init)
		return -EINVAL;

	buf->stat.init = *init;
	buf->mark.set  = false;
	buf->mark.pos  = 0;

	if (!_check_buf(buf)) {
		buf->stat = orig_stat;
		return -EINVAL;
	}

	return _buffer_type_registry[buf->stat.spec.type]->reset(buf);
}

int sid_buf_reset(struct sid_buf *buf)
{
	buf->mark.set = false;
	buf->mark.pos = 0;

	return _buffer_type_registry[buf->stat.spec.type]->reset(buf);
}

int sid_buf_add(struct sid_buf *buf, const void *data, size_t len, const void **mem, size_t *pos)
{
	size_t tmp_pos;
	int    r;

	if (buf->mark.set)
		return -EBUSY;

	if ((r = _buffer_type_registry[buf->stat.spec.type]->add(buf, data, len, mem, &tmp_pos)) < 0)
		return r;

	if (mem) {
		buf->mark.set = true;
		buf->mark.pos = tmp_pos;
	}

	if (pos)
		*pos = tmp_pos;

	return 0;
}

int sid_buf_add_fmt(struct sid_buf *buf, const void **mem, size_t *pos, const char *fmt, ...)
{
	size_t  tmp_pos;
	va_list ap;
	int     r;

	if (buf->mark.set)
		return -EBUSY;

	va_start(ap, fmt);
	r = _buffer_type_registry[buf->stat.spec.type]->add_fmt(buf, mem, &tmp_pos, fmt, ap);
	va_end(ap);

	if (r < 0)
		return r;

	if (mem) {
		buf->mark.set = true;
		buf->mark.pos = tmp_pos;
	}

	if (pos)
		*pos = tmp_pos;

	return 0;
}

int sid_buf_add_vfmt(struct sid_buf *buf, const void **mem, size_t *pos, const char *fmt, va_list ap)
{
	size_t tmp_pos;
	int    r;

	if (buf->mark.set)
		return -EBUSY;

	if ((r = _buffer_type_registry[buf->stat.spec.type]->add_fmt(buf, mem, &tmp_pos, fmt, ap)) < 0)
		return r;

	if (mem) {
		buf->mark.set = true;
		buf->mark.pos = tmp_pos;
	}

	if (pos)
		*pos = tmp_pos;

	return 0;
}

static int _do_sid_buf_release(struct sid_buf *buf, size_t pos, sid_buf_pos_t whence, bool rewind)
{
	size_t count = sid_buf_count(buf);

	if (!count)
		return pos ? -ERANGE : 0;

	if (pos > count)
		return -ERANGE;

	if (whence == SID_BUF_POS_REL)
		pos = count - pos; /* translate relative to absolute */

	return _buffer_type_registry[buf->stat.spec.type]->release(buf, pos, rewind);
}

int sid_buf_unbind(struct sid_buf *buf, size_t pos, sid_buf_pos_t whence)
{
	return _do_sid_buf_release(buf, pos, whence, false);
}

int sid_buf_rewind(struct sid_buf *buf, size_t pos, sid_buf_pos_t whence)
{
	return _do_sid_buf_release(buf, pos, whence, true);
}

static int _do_sid_buf_mem_release(struct sid_buf *buf, const void *mem, bool rewind)
{
	if (!mem || mem < buf->mem)
		return -EINVAL;

	return _buffer_type_registry[buf->stat.spec.type]->release_mem(buf, mem, rewind);
}

int sid_buf_unbind_mem(struct sid_buf *buf, const void *mem)
{
	return _do_sid_buf_mem_release(buf, mem, false);
}

int sid_buf_rewind_mem(struct sid_buf *buf, const void *mem)
{
	return _do_sid_buf_mem_release(buf, mem, true);
}

bool sid_buf_is_complete(struct sid_buf *buf, int *ret_code)
{
	return _buffer_type_registry[buf->stat.spec.type]->is_complete(buf, ret_code);
}

int sid_buf_get_data_from(struct sid_buf *buf, size_t pos, const void **data, size_t *data_size)
{
	if (pos > sid_buf_count(buf))
		return -ERANGE;

	if (!buf->mark.set || pos < buf->mark.set) {
		buf->mark.set = true;
		buf->mark.pos = pos;
	}

	return _buffer_type_registry[buf->stat.spec.type]->get_data(buf, pos, data, data_size);
}

int sid_buf_get_data(struct sid_buf *buf, const void **data, size_t *data_size)
{
	return sid_buf_get_data_from(buf, 0, data, data_size);
}

int sid_buf_get_fd(struct sid_buf *buf)
{
	return _buffer_type_registry[buf->stat.spec.type]->get_fd(buf);
}

ssize_t sid_buf_read(struct sid_buf *buf, int fd)
{
	return _buffer_type_registry[buf->stat.spec.type]->read(buf, fd);
}

ssize_t sid_buf_write(struct sid_buf *buf, int fd, size_t pos)
{
	return _buffer_type_registry[buf->stat.spec.type]->write(buf, fd, pos);
}

size_t sid_buf_count(struct sid_buf *buf)
{
	return _buffer_type_registry[buf->stat.spec.type]->count(buf);
}

struct sid_buf_stat sid_buf_stat(struct sid_buf *buf)
{
	return buf->stat;
}

int sid_buf_write_all(struct sid_buf *buf, int fd)
{
	size_t  pos;
	ssize_t n;

	if (!buf || fd < 0)
		return -EINVAL;

	for (pos = 0;; pos += n) {
		n = sid_buf_write(buf, fd, pos);

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
