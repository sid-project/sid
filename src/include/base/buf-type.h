/*
 * SPDX-FileCopyrightText: (C) 2017-2025 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _SID_BUF_TYPE_H
#define _SID_BUF_TYPE_H

#include "base/buf-common.h"

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
