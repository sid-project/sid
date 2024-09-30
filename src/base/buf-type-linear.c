/*
 * SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "base/buf-type.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <unistd.h>

static size_t _buffer_linear_count(struct sid_buf *buf)
{
	switch (buf->stat.spec.mode) {
		case SID_BUF_MODE_PLAIN:
			return buf->stat.usage.used;
		case SID_BUF_MODE_SIZE_PREFIX:
			return buf->stat.usage.used ? buf->stat.usage.used - SID_BUF_SIZE_PREFIX_LEN : 0;
		default:
			return 0;
	}
}

static int _buffer_linear_realloc(struct sid_buf *buf, size_t needed, int force)
{
	char  *p;
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
		case SID_BUF_BACKEND_MALLOC:
			if (needed > 0) {
				if (!(p = realloc(buf->mem, needed)))
					return -errno;
			} else {
				free(buf->mem);
				p = NULL;
			}
			break;

		case SID_BUF_BACKEND_MEMFD:
			if (buf->fd == -1 && (buf->fd = memfd_create("buffer", MFD_CLOEXEC | MFD_ALLOW_SEALING)) < 0)
				return -errno;
			/* fall through */
		case SID_BUF_BACKEND_FILE:
			if (buf->fd == -1 &&
			    (buf->fd = open(buf->stat.spec.ext.file.path, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR)) < 0)
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

static int _buffer_linear_create(struct sid_buf *buf)
{
	size_t needed = buf->stat.init.size;
	int    r;

	if (buf->stat.spec.mode == SID_BUF_MODE_SIZE_PREFIX)
		needed += SID_BUF_SIZE_PREFIX_LEN;

	if ((r = _buffer_linear_realloc(buf, needed, 1)) < 0) {
		if (buf->fd > -1)
			(void) close(buf->fd);
	}

	return r;
}

static int _buffer_linear_destroy(struct sid_buf *buf)
{
	int r;

	switch (buf->stat.spec.backend) {
		case SID_BUF_BACKEND_MALLOC:
			free(buf->mem);
			r = 0;
			break;

		case SID_BUF_BACKEND_MEMFD:
		case SID_BUF_BACKEND_FILE:
			(void) close(buf->fd);
			r = munmap(buf->mem, buf->stat.usage.allocated);
			break;

		default:
			return -ENOTSUP;
	}

	return r;
}

static int _buffer_linear_reset(struct sid_buf *buf)
{
	size_t needed;

	buf->stat.usage.used = 0;
	needed               = buf->stat.init.size;

	if (buf->stat.spec.mode == SID_BUF_MODE_SIZE_PREFIX)
		needed += SID_BUF_SIZE_PREFIX_LEN;

	return _buffer_linear_realloc(buf, needed, 1);
}

static int _buffer_linear_add(struct sid_buf *buf, const void *data, size_t len, const void **mem, size_t *pos)
{
	size_t used      = buf->stat.usage.used;
	void  *start     = NULL;
	size_t start_pos = 0;
	int    r;

	if (!used && buf->stat.spec.mode == SID_BUF_MODE_SIZE_PREFIX)
		used = SID_BUF_SIZE_PREFIX_LEN;

	if (pos)
		start_pos = _buffer_linear_count(buf);

	if ((r = _buffer_linear_realloc(buf, used + len, 0)) < 0)
		goto out;

	if (buf->mem) {
		start = buf->mem + used;
		if (len) {
			if (data)
				memcpy(start, data, len);
			else
				memset(start, 0, len);
		}
	}
	buf->stat.usage.used = used + len;
out:
	if (r == 0) {
		if (mem)
			*mem = start;
		if (pos)
			*pos = start_pos;
	}
	return r;
}

static int _buffer_linear_fmt_add(struct sid_buf *buf, const void **mem, size_t *pos, const char *fmt, va_list ap)
{
	va_list     ap_copy;
	size_t      used = buf->stat.usage.used;
	size_t      available;
	int         printed;
	const void *start     = NULL;
	size_t      start_pos = 0;
	int         r;

	va_copy(ap_copy, ap);

	if (!used && buf->stat.spec.mode == SID_BUF_MODE_SIZE_PREFIX)
		used = SID_BUF_SIZE_PREFIX_LEN;

	if (pos)
		start_pos = _buffer_linear_count(buf);

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

	if (mem)
		*mem = start;
	if (pos)
		*pos = start_pos;
out:
	return r;
}

static int _buffer_linear_release(struct sid_buf *buf, size_t pos, bool rewind)
{
	if (buf->mark.set && pos <= buf->mark.pos) {
		buf->mark.set = false;
		buf->mark.pos = 0;
	}

	if (rewind) {
		if (buf->stat.spec.mode == SID_BUF_MODE_SIZE_PREFIX)
			pos += SID_BUF_SIZE_PREFIX_LEN;

		buf->stat.usage.used = pos;
	}

	return 0;
}

static int _buffer_linear_mem_release(struct sid_buf *buf, const void *mem, bool rewind)
{
	size_t pos = mem - buf->mem;

	if (pos > buf->stat.usage.used)
		return -ERANGE;

	if (buf->stat.spec.mode == SID_BUF_MODE_SIZE_PREFIX)
		pos -= SID_BUF_SIZE_PREFIX_LEN;

	return _buffer_linear_release(buf, pos, rewind);
}

#define EXPECTED(buf) (buf->stat.usage.used >= SID_BUF_SIZE_PREFIX_LEN ? *((SID_BUF_SIZE_PREFIX_TYPE *) buf->mem) : 0)

static bool _buffer_linear_is_complete(struct sid_buf *buf, int *ret_code)
{
	bool result;
	int  r = 0;

	switch (buf->stat.spec.mode) {
		case SID_BUF_MODE_PLAIN:
			result = true;
			break;
		case SID_BUF_MODE_SIZE_PREFIX:
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

static int _buffer_linear_data_get(struct sid_buf *buf, size_t pos, const void **data, size_t *data_size)
{
	switch (buf->stat.spec.mode) {
		case SID_BUF_MODE_PLAIN:
			if (data)
				*data = buf->mem + pos;
			if (data_size)
				*data_size = buf->stat.usage.used - pos;
			break;
		case SID_BUF_MODE_SIZE_PREFIX:
			if (data)
				*data = buf->mem + SID_BUF_SIZE_PREFIX_LEN + pos;
			if (data_size)
				*data_size = (buf->stat.usage.used) ? buf->stat.usage.used - SID_BUF_SIZE_PREFIX_LEN - pos : 0;
			break;
		default:
			return -ENOTSUP;
	}

	return 0;
}

static void _update_size_prefix(struct sid_buf *buf, size_t pos)
{
	*((SID_BUF_SIZE_PREFIX_TYPE *) buf->mem) = (SID_BUF_SIZE_PREFIX_TYPE) buf->stat.usage.used;
}

static int _buffer_linear_fd_get(struct sid_buf *buf)
{
	switch (buf->stat.spec.mode) {
		case SID_BUF_MODE_PLAIN:
			/* nothing to do here, just return the fd */
			break;
		case SID_BUF_MODE_SIZE_PREFIX:
			_update_size_prefix(buf, 0);
			break;
		default:
			return -ENOTSUP;
	}

	return buf->fd;
}

static ssize_t _buffer_linear_read_plain(struct sid_buf *buf, int fd)
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

static ssize_t _buffer_linear_read_with_size_prefix(struct sid_buf *buf, int fd)
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
		previous_used         = buf->stat.usage.used;
		buf->stat.usage.used += n;
		if ((expected = EXPECTED(buf))) {
			/* Message must start with a prefix that is SID_BUF_SIZE_PREFIX_LEN bytes! */
			if (expected < SID_BUF_SIZE_PREFIX_LEN)
				return -EBADE;
			if (previous_used < SID_BUF_SIZE_PREFIX_LEN) {
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

static ssize_t _buffer_linear_read(struct sid_buf *buf, int fd)
{
	switch (buf->stat.spec.mode) {
		case SID_BUF_MODE_PLAIN:
			return _buffer_linear_read_plain(buf, fd);
		case SID_BUF_MODE_SIZE_PREFIX:
			return _buffer_linear_read_with_size_prefix(buf, fd);
		default:
			return -ENOTSUP;
	}
}

static ssize_t _buffer_linear_write(struct sid_buf *buf, int fd, size_t pos)
{
	ssize_t n;
	off_t   offset;

	if (pos == buf->stat.usage.used)
		return -ENODATA;

	if (pos > buf->stat.usage.used)
		return -ERANGE;

	if (buf->stat.spec.mode == SID_BUF_MODE_SIZE_PREFIX)
		_update_size_prefix(buf, pos);

	switch (buf->stat.spec.backend) {
		case SID_BUF_BACKEND_MALLOC:
			n = write(fd, buf->mem + pos, buf->stat.usage.used - pos);
			break;

		case SID_BUF_BACKEND_MEMFD:
		case SID_BUF_BACKEND_FILE:
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

const struct sid_buf_type sid_buf_type_linear = {.create      = _buffer_linear_create,
                                                 .destroy     = _buffer_linear_destroy,
                                                 .reset       = _buffer_linear_reset,
                                                 .add         = _buffer_linear_add,
                                                 .add_fmt     = _buffer_linear_fmt_add,
                                                 .release     = _buffer_linear_release,
                                                 .release_mem = _buffer_linear_mem_release,
                                                 .is_complete = _buffer_linear_is_complete,
                                                 .get_data    = _buffer_linear_data_get,
                                                 .get_fd      = _buffer_linear_fd_get,
                                                 .count       = _buffer_linear_count,
                                                 .read        = _buffer_linear_read,
                                                 .write       = _buffer_linear_write};
