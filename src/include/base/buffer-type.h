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

#ifndef _SID_BUFFER_TYPE_H
#define _SID_BUFFER_TYPE_H

#include "base/buffer-common.h"

#include <sys/types.h>

struct buffer {
	struct buffer_stat stat;
	void *             mem;
	int                fd;
};

struct buffer_type {
	int (*create)(struct buffer *buf);
	int (*destroy)(struct buffer *buf);
	int (*reset)(struct buffer *buf);
	const void *(*add)(struct buffer *buf, void *data, size_t len, int *ret_code);
	const void *(*fmt_add)(struct buffer *buf, int *ret_code, const char *fmt, va_list ap);
	int (*rewind)(struct buffer *buf, size_t pos);
	int (*rewind_mem)(struct buffer *buf, const void *mem);
	bool (*is_complete)(struct buffer *buf, int *ret_code);
	int (*get_data)(struct buffer *buf, const void **data, size_t *data_size);
	int (*get_fd)(struct buffer *buf);
	ssize_t (*read)(struct buffer *buf, int fd);
	ssize_t (*write)(struct buffer *buf, int fd, size_t pos);
};

extern const struct buffer_type sid_buffer_type_linear;
extern const struct buffer_type sid_buffer_type_vector;

#endif
