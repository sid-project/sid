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
#include "mem.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int _buffer_linear_create(struct buffer *buf, size_t initial_size)
{
	if (buf->mode == BUFFER_MODE_SIZE_PREFIX)
		initial_size += MSG_SIZE_PREFIX_LEN;

	if (!(buf->mem = zalloc(initial_size)))
		return -ENOMEM;

	buf->allocated = initial_size;
	return 0;
}

static int _buffer_linear_destroy(struct buffer *buf)
{
	free(buf->mem);
	return 0;
}

static int _buffer_linear_realloc(struct buffer *buf, size_t needed, int force)
{
	char *p;
	size_t align;
	size_t alloc_step;

	if (!force) {
		if (buf->allocated >= needed)
			return 0;

		if (!(alloc_step = buf->alloc_step))
			return -ENOMEM;
	} else
		alloc_step = 1;

	if ((align = (needed % alloc_step)))
		needed += alloc_step - align;

	if (!(p = realloc(buf->mem, needed)))
		return -errno;

	buf->mem = p;
	buf->allocated = needed;

	return 0;
}

static int _buffer_linear_reset(struct buffer *buf, size_t initial_size)
{
	buf->used = 0;

	if (!initial_size) {
		switch (buf->mode) {
			case BUFFER_MODE_PLAIN:
				/* keep initial_size = 0 */
				break;
			case BUFFER_MODE_SIZE_PREFIX:
				initial_size = MSG_SIZE_PREFIX_LEN;
				break;
		}
	}

	return _buffer_linear_realloc(buf, initial_size, 1);
}

static const void *_buffer_linear_add(struct buffer *buf, void *data, size_t len, int *ret_code)
{
	size_t used = buf->used;
	void *start = NULL;
	int r;

	if (!used && buf->mode == BUFFER_MODE_SIZE_PREFIX)
		used = MSG_SIZE_PREFIX_LEN;

	if ((r = _buffer_linear_realloc(buf, used + len, 0)) < 0)
		goto out;

	start = buf->mem + used;
	memcpy(start, data, len);
	buf->used = used + len;
out:
	if (ret_code)
		*ret_code = r;
	return start;
}

static const void *_buffer_linear_fmt_add(struct buffer *buf, int *ret_code, const char *fmt, va_list ap)
{
	va_list ap_copy;
	size_t used = buf->used;
	size_t available;
	int printed;
	const void *start = NULL;
	int r;

	va_copy(ap_copy, ap);

	if (!used && buf->mode == BUFFER_MODE_SIZE_PREFIX)
		used = MSG_SIZE_PREFIX_LEN;

	available = buf->allocated - used;
	printed = vsnprintf(buf->mem + used, available, fmt, ap_copy);
	va_end(ap_copy);

	if (printed < 0) {
		r = -EIO;
		goto out;
	} else if ((printed >= available)) {
		if ((r = _buffer_linear_realloc(buf, used + printed + 1, 0)) < 0)
			goto out;
		available = buf->allocated - used;
		if ((printed = vsnprintf(buf->mem + used, available, fmt, ap)) < 0) {
			r = -EIO;
			goto out;
		}
	}

	start = buf->mem + used;
	buf->used = used + printed + 1;
out:
	if (ret_code)
		*ret_code = r;
	return start;
}

static int _buffer_linear_rewind(struct buffer *buf, size_t pos)
{
	size_t min_pos = (buf->mode == BUFFER_MODE_SIZE_PREFIX) ? MSG_SIZE_PREFIX_LEN : 0;

	if (pos > buf->used || pos < min_pos)
		return -EINVAL;

	buf->used = pos;
	return 0;
}

static int _buffer_linear_rewind_mem(struct buffer *buf, const void *mem)
{
	return _buffer_linear_rewind(buf, mem - buf->mem);
}

#define EXPECTED(buf) (buf->used >= MSG_SIZE_PREFIX_LEN ? *((MSG_SIZE_PREFIX_TYPE *) buf->mem) : 0)

static bool _buffer_linear_is_complete(struct buffer *buf, int *ret_code)
{
	bool result;

	switch (buf->mode) {
		case BUFFER_MODE_PLAIN:
			result = true;
		case BUFFER_MODE_SIZE_PREFIX:
			result = buf->used && buf->used == EXPECTED(buf);
	}

	if (ret_code)
		*ret_code = 0;
	return result;
}

static int _buffer_linear_get_data(struct buffer *buf, const void **data, size_t *data_size)
{
	switch (buf->mode) {
		case BUFFER_MODE_PLAIN:
			if (data)
				*data = buf->mem;
			if (data_size)
				*data_size = buf->used;
			break;
		case BUFFER_MODE_SIZE_PREFIX:
			if (data)
				*data = buf->mem + MSG_SIZE_PREFIX_LEN;
			if (data_size)
				*data_size = buf->used - MSG_SIZE_PREFIX_LEN;
			break;
	}

	return 0;
}

static ssize_t _buffer_linear_read_plain(struct buffer *buf, int fd)
{
	ssize_t n;

	if (buf->used == buf->allocated)
		return -EXFULL;

	n = read(fd, buf->mem + buf->used, buf->allocated - buf->used);

	if (n > 0)
		buf->used += n;
	else if (n < 0)
		n = -errno;

	return n;
}

static ssize_t _buffer_linear_read_with_size_prefix(struct buffer *buf, int fd)
{
	ssize_t n;
	size_t previous_used;
	size_t expected;
	int r;

	if (_buffer_linear_is_complete(buf, &r)) {
		return r < 0 ? r : -EXFULL;
	} else if (r < 0)
		return r;

	n = read(fd, buf->mem + buf->used, buf->allocated - buf->used);

	if (n > 0) {
		previous_used = buf->used;
		buf->used += n;
		if ((expected = EXPECTED(buf))) {
			/* Message must start with a prefix that is MSG_SIZE_PREFIX_LEN bytes! */
			if (expected < MSG_SIZE_PREFIX_LEN)
				return -EBADE;
			if (previous_used < MSG_SIZE_PREFIX_LEN) {
				if (_buffer_linear_realloc(buf, expected, 0) < 0)
					return -1;
			}
		}
	} else if (n == 0) {
		/* Detect premature EOF when we haven't received full message yet. */
		expected = EXPECTED(buf);
		if ((!expected && buf->used) || (expected && buf->used != expected))
			return -EBADE;
	} else
		n = -errno;

	return n;
}

static ssize_t _buffer_linear_read(struct buffer *buf, int fd)
{
	switch (buf->mode) {
		case BUFFER_MODE_PLAIN:
			return _buffer_linear_read_plain(buf, fd);
		case BUFFER_MODE_SIZE_PREFIX:
			return _buffer_linear_read_with_size_prefix(buf, fd);
	}
}

static ssize_t _buffer_linear_write(struct buffer *buf, int fd, size_t pos)
{
	ssize_t n;

	if (buf->mode == BUFFER_MODE_SIZE_PREFIX)
		*((MSG_SIZE_PREFIX_TYPE *) buf->mem) = (MSG_SIZE_PREFIX_TYPE) buf->used;

	if (pos == buf->used)
		return -ENODATA;

	if (pos > buf->used)
		return -ERANGE;

	n = write(fd, buf->mem + pos, buf->used - pos);

	if (n < 0)
		n = -errno;

	return n;
}

const struct buffer_type buffer_type_linear = {
	.create = _buffer_linear_create,
	.destroy = _buffer_linear_destroy,
	.reset = _buffer_linear_reset,
	.add = _buffer_linear_add,
	.fmt_add = _buffer_linear_fmt_add,
	.rewind = _buffer_linear_rewind,
	.rewind_mem = _buffer_linear_rewind_mem,
	.is_complete = _buffer_linear_is_complete,
	.get_data = _buffer_linear_get_data,
	.read = _buffer_linear_read,
	.write = _buffer_linear_write
};
