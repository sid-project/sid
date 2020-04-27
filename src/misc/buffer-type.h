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

#ifndef _SID_BUFFER_TYPE_H
#define _SID_BUFFER_TYPE_H

#include "buffer-common.h"

#include <sys/types.h>

struct buffer{
	buffer_type_t type;
        buffer_mode_t mode;
	void *mem;
	size_t alloc_step;
        size_t allocated;          /* bytes allocated */
        size_t used;               /* bytes used */
};

struct buffer_type {
	int (*create) (struct buffer *buf, size_t initial_size);
	int (*destroy) (struct buffer *buf);
	int (*reset) (struct buffer *buf, size_t initial_size);
	const void *(*add) (struct buffer *buf, void *data, size_t len);
	const void *(*fmt_add) (struct buffer *buf, const char *fmt, va_list ap);
	int (*rewind) (struct buffer *buf, size_t pos);
	int (*rewind_mem) (struct buffer *buf, const void *mem);
	bool (*is_complete) (struct buffer *buf);
	int (*get_data) (struct buffer *buf, const void **data, size_t *data_size);
	ssize_t (*read) (struct buffer *buf, int fd);
	ssize_t (*write) (struct buffer *buf, int fd);
};

extern const struct buffer_type buffer_type_linear;
extern const struct buffer_type buffer_type_vector;

#endif
