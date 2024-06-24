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

#include <stdarg.h>
#include <sys/types.h>

struct sid_buf {
	struct sid_buf_stat stat;
	void               *mem;
	int                 fd;

	struct {
		bool   set;
		size_t pos;
	} mark;
};

struct sid_buf_type {
	int (*create)(struct sid_buf *buf);
	int (*destroy)(struct sid_buf *buf);
	int (*reset)(struct sid_buf *buf);
	int (*add)(struct sid_buf *buf, const void *data, size_t len, const void **mem, size_t *pos);
	int (*add_fmt)(struct sid_buf *buf, const void **mem, size_t *pos, const char *fmt, va_list ap);
	int (*release)(struct sid_buf *buf, size_t pos, bool rewind);
	int (*release_mem)(struct sid_buf *buf, const void *mem, bool rewind);
	bool (*is_complete)(struct sid_buf *buf, int *ret_code);
	int (*get_data)(struct sid_buf *buf, size_t pos, const void **data, size_t *data_size);
	int (*get_fd)(struct sid_buf *buf);
	size_t (*count)(struct sid_buf *buf);
	ssize_t (*read)(struct sid_buf *buf, int fd);
	ssize_t (*write)(struct sid_buf *buf, int fd, size_t pos);
};

extern const struct sid_buf_type sid_buf_type_linear;
extern const struct sid_buf_type sid_buf_type_vector;

#endif
