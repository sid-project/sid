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

#include "base/common.h"

#include "base/buffer-type.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <unistd.h>

static int _buffer_linear_realloc(struct buffer *buf, size_t needed, int force)
{
	char * p;
	size_t align;
	size_t alloc_step;

	if (force)
		alloc_step = 1;
	else {
		if (buf->stat.usage.allocated >= needed)
			return 0;
		if (!(alloc_step = buf->stat.init.alloc_step))
			return -EXFULL;
	}

	if ((align = (needed % alloc_step)))
		needed += alloc_step - align;

	if (buf->stat.init.limit && needed > buf->stat.init.limit)
		return -EOVERFLOW;

	switch (buf->stat.spec.backend) {
		case BUFFER_BACKEND_MALLOC:
			if (!(p = realloc(buf->mem, needed)))
				return -errno;
			break;

		case BUFFER_BACKEND_MEMFD:
			if (buf->fd == -1 && (buf->fd = memfd_create("buffer", MFD_CLOEXEC | MFD_ALLOW_SEALING)) < 0)
				return -errno;

			if (ftruncate(buf->fd, needed) < 0)
				return -errno;

			if (needed > 0) {
				if (buf->mem)
					p = mremap(buf->mem, buf->stat.usage.allocated, needed, MREMAP_MAYMOVE);
				else
					p = mmap(NULL, needed, PROT_READ | PROT_WRITE, MAP_SHARED, buf->fd, 0);

				if (p == MAP_FAILED)
					return -errno;
			} else {
				if (buf->stat.usage.allocated > 0) {
					if (munmap(buf->mem, buf->stat.usage.allocated) < 0)
						return -errno;
				}
				p = NULL;
			}
			break;

		default:
			return -ENOTSUP;
	}

	buf->mem                  = p;
	buf->stat.usage.allocated = needed;

	return 0;
}

static int _buffer_linear_create(struct buffer *buf)
{
	size_t needed = buf->stat.init.size;
	int    r;

	if (buf->stat.spec.mode == BUFFER_MODE_SIZE_PREFIX)
		needed += BUFFER_SIZE_PREFIX_LEN;

	if ((r = _buffer_linear_realloc(buf, needed, 1)) < 0) {
		if (buf->fd > -1)
			(void) close(buf->fd);
	}

	return r;
}

static int _buffer_linear_destroy(struct buffer *buf)
{
	int r;

	switch (buf->stat.spec.backend) {
		case BUFFER_BACKEND_MALLOC:
			free(buf->mem);
			r = 0;
			break;

		case BUFFER_BACKEND_MEMFD:
			(void) close(buf->fd);
			r = munmap(buf->mem, buf->stat.usage.allocated);
			break;

		default:
			return -ENOTSUP;
	}

	return r;
}

static int _buffer_linear_reset(struct buffer *buf)
{
	size_t needed;

	buf->stat.usage.used = 0;
	needed               = buf->stat.init.size;

	if (buf->stat.spec.mode == BUFFER_MODE_SIZE_PREFIX)
		needed += BUFFER_SIZE_PREFIX_LEN;

	return _buffer_linear_realloc(buf, needed, 1);
}

static const void *_buffer_linear_add(struct buffer *buf, void *data, size_t len, int *ret_code)
{
	size_t used  = buf->stat.usage.used;
	void * start = NULL;
	int    r;

	if (!used && buf->stat.spec.mode == BUFFER_MODE_SIZE_PREFIX)
		used = BUFFER_SIZE_PREFIX_LEN;

	if ((r = _buffer_linear_realloc(buf, used + len, 0)) < 0)
		goto out;

	start = buf->mem + used;
	if (data)
		memcpy(start, data, len);
	else
		memset(start, 0, len);
	buf->stat.usage.used = used + len;
out:
	if (ret_code)
		*ret_code = r;
	return start;
}

static const void *_buffer_linear_fmt_add(struct buffer *buf, int *ret_code, const char *fmt, va_list ap)
{
	va_list     ap_copy;
	size_t      used = buf->stat.usage.used;
	size_t      available;
	int         printed;
	const void *start = NULL;
	int         r;

	va_copy(ap_copy, ap);

	if (!used && buf->stat.spec.mode == BUFFER_MODE_SIZE_PREFIX)
		used = BUFFER_SIZE_PREFIX_LEN;

	available = buf->stat.usage.allocated - used;
	printed   = vsnprintf(buf->mem + used, available, fmt, ap_copy);
	va_end(ap_copy);

	if (printed < 0) {
		r = -EIO;
		goto out;
	} else if ((printed >= available)) {
		if ((r = _buffer_linear_realloc(buf, used + printed + 1, 0)) < 0)
			goto out;
		available = buf->stat.usage.allocated - used;
		if ((printed = vsnprintf(buf->mem + used, available, fmt, ap)) < 0) {
			r = -EIO;
			goto out;
		}
	}

	start                = buf->mem + used;
	buf->stat.usage.used = used + printed + 1;
	r                    = 0;
out:
	if (ret_code)
		*ret_code = r;
	return start;
}

static int _buffer_linear_rewind(struct buffer *buf, size_t pos)
{
	size_t min_pos = (buf->stat.spec.mode == BUFFER_MODE_SIZE_PREFIX) ? BUFFER_SIZE_PREFIX_LEN : 0;

	if (!buf->stat.usage.used && pos == min_pos)
		return 0;

	if (pos > buf->stat.usage.used || pos < min_pos)
		return -EINVAL;

	buf->stat.usage.used = pos;
	return 0;
}

static int _buffer_linear_rewind_mem(struct buffer *buf, const void *mem)
{
	if (mem < buf->mem)
		return -EINVAL;

	return _buffer_linear_rewind(buf, mem - buf->mem);
}

#define EXPECTED(buf) (buf->stat.usage.used >= BUFFER_SIZE_PREFIX_LEN ? *((BUFFER_SIZE_PREFIX_TYPE *) buf->mem) : 0)

static bool _buffer_linear_is_complete(struct buffer *buf, int *ret_code)
{
	bool result;
	int  r = 0;

	switch (buf->stat.spec.mode) {
		case BUFFER_MODE_PLAIN:
			result = true;
			break;
		case BUFFER_MODE_SIZE_PREFIX:
			result = buf->stat.usage.used && buf->stat.usage.used == EXPECTED(buf);
			break;
		default:
			r      = -ENOTSUP;
			result = false;
	}

	if (ret_code)
		*ret_code = r;

	return result;
}

static int _buffer_linear_get_data(struct buffer *buf, const void **data, size_t *data_size)
{
	switch (buf->stat.spec.mode) {
		case BUFFER_MODE_PLAIN:
			if (data)
				*data = buf->mem;
			if (data_size)
				*data_size = buf->stat.usage.used;
			break;
		case BUFFER_MODE_SIZE_PREFIX:
			if (data)
				*data = buf->mem + BUFFER_SIZE_PREFIX_LEN;
			if (data_size)
				*data_size = (buf->stat.usage.used) ? buf->stat.usage.used - BUFFER_SIZE_PREFIX_LEN : 0;
			break;
		default:
			return -ENOTSUP;
	}

	return 0;
}

static void _update_size_prefix(struct buffer *buf, size_t pos)
{
	*((BUFFER_SIZE_PREFIX_TYPE *) buf->mem) = (BUFFER_SIZE_PREFIX_TYPE) buf->stat.usage.used;
}

static int _buffer_linear_get_fd(struct buffer *buf)
{
	switch (buf->stat.spec.mode) {
		case BUFFER_MODE_PLAIN:
			/* nothing to do here, just return the fd */
			break;
		case BUFFER_MODE_SIZE_PREFIX:
			_update_size_prefix(buf, 0);
			break;
		default:
			return -ENOTSUP;
	}

	return buf->fd;
}

static ssize_t _buffer_linear_read_plain(struct buffer *buf, int fd)
{
	ssize_t n;
	int     r;

	if (buf->stat.usage.used == buf->stat.usage.allocated &&
	    (r = _buffer_linear_realloc(buf, buf->stat.usage.allocated + buf->stat.init.alloc_step, 0)) < 0)
		return r;

	n = read(fd, buf->mem + buf->stat.usage.used, buf->stat.usage.allocated - buf->stat.usage.used);

	if (n > 0)
		buf->stat.usage.used += n;
	else if (n < 0)
		n = -errno;

	return n;
}

static ssize_t _buffer_linear_read_with_size_prefix(struct buffer *buf, int fd)
{
	ssize_t n;
	size_t  previous_used;
	size_t  expected;
	int     r;

	if (_buffer_linear_is_complete(buf, &r)) {
		return r < 0 ? r : -EXFULL;
	} else if (r < 0)
		return r;

	n = read(fd, buf->mem + buf->stat.usage.used, buf->stat.usage.allocated - buf->stat.usage.used);

	if (n > 0) {
		previous_used = buf->stat.usage.used;
		buf->stat.usage.used += n;
		if ((expected = EXPECTED(buf))) {
			/* Message must start with a prefix that is BUFFER_SIZE_PREFIX_LEN bytes! */
			if (expected < BUFFER_SIZE_PREFIX_LEN)
				return -EBADE;
			if (previous_used < BUFFER_SIZE_PREFIX_LEN) {
				if ((r = _buffer_linear_realloc(buf, expected, 0)) < 0)
					return r;
			}
		}
	} else if (n == 0) {
		/* Detect premature EOF when we haven't received full message yet. */
		expected = EXPECTED(buf);
		if ((!expected && buf->stat.usage.used) || (expected && buf->stat.usage.used != expected))
			return -EBADMSG;
	} else
		n = -errno;

	return n;
}

static ssize_t _buffer_linear_read(struct buffer *buf, int fd)
{
	switch (buf->stat.spec.mode) {
		case BUFFER_MODE_PLAIN:
			return _buffer_linear_read_plain(buf, fd);
		case BUFFER_MODE_SIZE_PREFIX:
			return _buffer_linear_read_with_size_prefix(buf, fd);
		default:
			return -ENOTSUP;
	}
}

static ssize_t _buffer_linear_write(struct buffer *buf, int fd, size_t pos)
{
	ssize_t n;
	off_t   offset;

	if (pos == buf->stat.usage.used)
		return -ENODATA;

	if (pos > buf->stat.usage.used)
		return -ERANGE;

	if (buf->stat.spec.mode == BUFFER_MODE_SIZE_PREFIX)
		_update_size_prefix(buf, pos);

	switch (buf->stat.spec.backend) {
		case BUFFER_BACKEND_MALLOC:
			n = write(fd, buf->mem + pos, buf->stat.usage.used - pos);
			break;

		case BUFFER_BACKEND_MEMFD:
			offset = pos;
			n      = sendfile(fd, buf->fd, &offset, buf->stat.usage.used - pos);
			break;

		default:
			return -ENOTSUP;
	}

	if (n < 0)
		n = -errno;

	return n;
}

const struct buffer_type sid_buffer_type_linear = {.create      = _buffer_linear_create,
                                                   .destroy     = _buffer_linear_destroy,
                                                   .reset       = _buffer_linear_reset,
                                                   .add         = _buffer_linear_add,
                                                   .fmt_add     = _buffer_linear_fmt_add,
                                                   .rewind      = _buffer_linear_rewind,
                                                   .rewind_mem  = _buffer_linear_rewind_mem,
                                                   .is_complete = _buffer_linear_is_complete,
                                                   .get_data    = _buffer_linear_get_data,
                                                   .get_fd      = _buffer_linear_get_fd,
                                                   .read        = _buffer_linear_read,
                                                   .write       = _buffer_linear_write};
