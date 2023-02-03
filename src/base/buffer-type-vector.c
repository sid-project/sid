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

#include "config.h"

#include "base/buffer-type.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <unistd.h>

#define VECTOR_ITEM_SIZE sizeof(struct iovec)

static size_t _buffer_vector_count(struct sid_buffer *buf)
{
	switch (buf->stat.spec.mode) {
		case SID_BUFFER_MODE_PLAIN:
			return buf->stat.usage.used;
		case SID_BUFFER_MODE_SIZE_PREFIX:
			return buf->stat.usage.used ? buf->stat.usage.used - 1 : 0;
		default:
			return 0;
	}
}

static int _buffer_vector_realloc(struct sid_buffer *buf, size_t needed, int force)
{
	void  *p;
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
		case SID_BUFFER_BACKEND_MALLOC:
			if (!(p = realloc(buf->mem, needed * VECTOR_ITEM_SIZE)))
				return -errno;
			break;

		case SID_BUFFER_BACKEND_MEMFD:
			if (buf->fd == -1 && (buf->fd = memfd_create("buffer", MFD_CLOEXEC | MFD_ALLOW_SEALING)) < 0)
				return -errno;
			/* fall through */
		case SID_BUFFER_BACKEND_FILE:
			if (buf->fd == -1 &&
			    (buf->fd = open(buf->stat.spec.ext.file.path, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR)) < 0)
				return -errno;

			if (ftruncate(buf->fd, needed * VECTOR_ITEM_SIZE) < 0)
				return -errno;

			if (needed > 0) {
				if (buf->mem)
					p = mremap(buf->mem,
					           buf->stat.usage.allocated * VECTOR_ITEM_SIZE,
					           needed * VECTOR_ITEM_SIZE,
					           MREMAP_MAYMOVE);
				else
					p = mmap(NULL, needed * VECTOR_ITEM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, buf->fd, 0);

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

static int _buffer_vector_create(struct sid_buffer *buf)
{
	size_t needed = buf->stat.init.size;
	int    r;

	if (buf == NULL)
		return EINVAL;

	if (buf->stat.spec.mode == SID_BUFFER_MODE_SIZE_PREFIX)
		needed += 1;

	if ((r = _buffer_vector_realloc(buf, needed, 1)) < 0) {
		if (buf->fd > -1)
			(void) close(buf->fd);

		return r;
	}

	if (buf->stat.spec.mode == SID_BUFFER_MODE_SIZE_PREFIX) {
		if (!(((struct iovec *) buf->mem)[0].iov_base = malloc(SID_BUFFER_SIZE_PREFIX_LEN))) {
			if (buf->fd > -1)
				(void) close(buf->fd);
			free(buf->mem);
			return -ENOMEM;
		}

		((struct iovec *) buf->mem)[0].iov_len = SID_BUFFER_SIZE_PREFIX_LEN;
	}

	buf->stat.usage.allocated = needed;
	return 0;
}

static int _buffer_vector_destroy(struct sid_buffer *buf)
{
	struct iovec *iov;
	int           r;

	if (buf->stat.spec.mode == SID_BUFFER_MODE_SIZE_PREFIX) {
		iov = buf->mem;
		free(iov[0].iov_base);
	}
	switch (buf->stat.spec.backend) {
		case SID_BUFFER_BACKEND_MALLOC:
			free(buf->mem);
			r = 0;
			break;

		case SID_BUFFER_BACKEND_MEMFD:
		case SID_BUFFER_BACKEND_FILE:
			(void) close(buf->fd);
			r = munmap(buf->mem, buf->stat.usage.allocated);
			break;

		default:
			r = -ENOTSUP;
	}

	return r;
}

static int _buffer_vector_reset(struct sid_buffer *buf)
{
	size_t needed;

	buf->stat.usage.used = 0;

	needed               = buf->stat.init.size;

	if (!needed) {
		switch (buf->stat.spec.mode) {
			case SID_BUFFER_MODE_PLAIN:
				/* keep needed = 0 */
				break;
			case SID_BUFFER_MODE_SIZE_PREFIX:
				needed = 1;
				break;
			default:
				return -ENOTSUP;
		}
	}

	return _buffer_vector_realloc(buf, needed, 1);
}

static int _buffer_vector_add(struct sid_buffer *buf, void *data, size_t len, const void **mem, size_t *pos)
{
	size_t        used = buf->stat.usage.used;
	struct iovec *iov;
	size_t        start_pos;
	int           r;

	if (buf == NULL || buf->mem == NULL || data == NULL)
		return -EINVAL;

	if (!used && buf->stat.spec.mode == SID_BUFFER_MODE_SIZE_PREFIX)
		used = 1;

	if (pos)
		start_pos = _buffer_vector_count(buf);

	if ((r = _buffer_vector_realloc(buf, used + 1, 0)) < 0)
		goto out;

	iov                  = buf->mem;
	iov[used].iov_base   = data;
	iov[used].iov_len    = len;
	buf->stat.usage.used = used + 1;
out:
	if (r == 0) {
		if (mem)
			*mem = &iov[buf->stat.usage.used - 1];
		if (pos)
			*pos = start_pos;
	}
	return r;
}

static int _buffer_vector_fmt_add(struct sid_buffer *buf, const void **mem, size_t *pos, const char *fmt, va_list ap)
{
	return -ENOTSUP;
}

static int _buffer_vector_release(struct sid_buffer *buf, size_t pos, bool rewind)
{
	if (buf->mark.set && pos <= buf->mark.pos) {
		buf->mark.set = false;
		buf->mark.pos = 0;
	}

	if (rewind) {
		if (buf->stat.spec.mode == SID_BUFFER_MODE_SIZE_PREFIX)
			pos += 1;

		buf->stat.usage.used = pos;
	}

	return 0;
}

static int _buffer_vector_release_mem(struct sid_buffer *buf, const void *mem, bool rewind)
{
	size_t pos = (struct iovec *) mem - (struct iovec *) buf->mem;

	if (buf->stat.spec.mode == SID_BUFFER_MODE_SIZE_PREFIX)
		pos -= 1;

	return _buffer_vector_release(buf, pos, rewind);
}

static bool _buffer_vector_is_complete(struct sid_buffer *buf, int *ret_code)
{
	/*	struct iovec *iov;
	        SID_BUFFER_SIZE_PREFIX_TYPE size_prefix;
	        size_t size = 0;
	        unsigned i;

	        switch (buf->mode) {
	                case SID_BUFFER_MODE_PLAIN:
	                        return true;
	                case SID_BUFFER_MODE_SIZE_PREFIX:
	                        iov = buf->mem;
	                        size_prefix = *((SID_BUFFER_SIZE_PREFIX_TYPE *) iov[0].iov_base);
	                        for (i = 1; i < buf->used; i++)
	                                size += iov[i].iov_len;
	                        return buf->used && size_prefix == size;
	        }
	*/
	if (*ret_code)
		*ret_code = -ENOTSUP;
	return true;
}

static int _buffer_vector_get_data(struct sid_buffer *buf, const void **data, size_t *data_size)
{
	switch (buf->stat.spec.mode) {
		case SID_BUFFER_MODE_PLAIN:
			if (data)
				*data = buf->mem;
			if (data_size)
				*data_size = buf->stat.usage.used;
			break;
		case SID_BUFFER_MODE_SIZE_PREFIX:
			if (data)
				*data = buf->mem + VECTOR_ITEM_SIZE;
			if (data_size)
				*data_size = (buf->stat.usage.used) ? buf->stat.usage.used - 1 : 0;
			break;
		default:
			return -ENOTSUP;
	}

	return 0;
}

static void _update_size_prefix(struct sid_buffer *buf, size_t pos)
{
	struct iovec               *iov         = buf->mem;
	SID_BUFFER_SIZE_PREFIX_TYPE size_prefix = 0;
	size_t                      i;

	if ((pos == 0) && (buf->stat.spec.mode == SID_BUFFER_MODE_SIZE_PREFIX)) {
		for (i = 0; i < buf->stat.usage.used; i++)
			size_prefix += iov[i].iov_len;
		*((SID_BUFFER_SIZE_PREFIX_TYPE *) iov[0].iov_base) = size_prefix;
	}
}

static int _buffer_vector_get_fd(struct sid_buffer *buf)
{
	switch (buf->stat.spec.mode) {
		case SID_BUFFER_MODE_PLAIN:
			/* nothing to do here, just return the fd */
			break;
		case SID_BUFFER_MODE_SIZE_PREFIX:
			_update_size_prefix(buf, 0);
			break;
		default:
			return -ENOTSUP;
	}

	return buf->fd;
}

static ssize_t _buffer_vector_read_plain(struct sid_buffer *buf, int fd)
{
	return -ENOTSUP;
}

static ssize_t _buffer_vector_read_with_size_prefix(struct sid_buffer *buf, int fd)
{
	return -ENOTSUP;
}

static ssize_t _buffer_vector_read(struct sid_buffer *buf, int fd)
{
	switch (buf->stat.spec.mode) {
		case SID_BUFFER_MODE_PLAIN:
			return _buffer_vector_read_plain(buf, fd);
		case SID_BUFFER_MODE_SIZE_PREFIX:
			return _buffer_vector_read_with_size_prefix(buf, fd);
		default:
			return -ENOTSUP;
	}
}

static ssize_t _buffer_vector_write(struct sid_buffer *buf, int fd, size_t pos)
{
	struct iovec *iov = buf->mem;
	unsigned      i, start_idx = 0;
	void         *save_base = NULL;
	size_t        save_len = 0, start_off = pos;
	ssize_t       n;

	i = 0;
	if (pos) {
		for (; i < buf->stat.usage.used; i++) {
			if (iov[i].iov_len > start_off) {
				start_idx       = i;
				save_base       = iov[i].iov_base;
				save_len        = iov[i].iov_len;
				iov[i].iov_base += start_off;
				iov[i].iov_len  -= start_off;
				break;
			}
			start_off -= iov[i].iov_len;
		}
	}
	if (i == buf->stat.usage.used) {
		if (start_off == 0)
			return -ENODATA;
		else
			return -ERANGE;
	}

	if (buf->stat.spec.mode == SID_BUFFER_MODE_SIZE_PREFIX)
		_update_size_prefix(buf, pos);

	/*
	 * Be aware that if we have SID_BUFFER_BACKEND_MEMFD, we still have
	 * to use writev and not the sendfile. This is because the buf->fd
	 * only represents the memfd that stores the vector itself, but not
	 * the contents of the memory that each iov.base points to!
	 */
	n = writev(fd, &iov[start_idx], buf->stat.usage.used - start_idx);
	if (pos) {
		iov[start_idx].iov_base = save_base;
		iov[start_idx].iov_len  = save_len;
	}
	if (n < 0)
		n = -errno;

	return n;
}

const struct sid_buffer_type sid_buffer_type_vector = {.create      = _buffer_vector_create,
                                                       .destroy     = _buffer_vector_destroy,
                                                       .reset       = _buffer_vector_reset,
                                                       .add         = _buffer_vector_add,
                                                       .fmt_add     = _buffer_vector_fmt_add,
                                                       .release     = _buffer_vector_release,
                                                       .release_mem = _buffer_vector_release_mem,
                                                       .is_complete = _buffer_vector_is_complete,
                                                       .get_data    = _buffer_vector_get_data,
                                                       .get_fd      = _buffer_vector_get_fd,
                                                       .count       = _buffer_vector_count,
                                                       .read        = _buffer_vector_read,
                                                       .write       = _buffer_vector_write};
