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

#ifndef _SID_BUFFER_H
#define _SID_BUFFER_H

#include "base/buffer-common.h"

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct buffer;

typedef enum {
	BUFFER_POS_ABS,
	BUFFER_POS_REL,
} buffer_pos_t;

struct buffer *buffer_create(buffer_type_t type, buffer_mode_t mode, size_t initial_size, size_t alloc_step, size_t limit, int *ret_code);
void buffer_destroy(struct buffer *buf);
int buffer_reset(struct buffer *buf);
int buffer_reset_init(struct buffer *buf, size_t intial_size, size_t alloc_step, size_t limit);
const void *buffer_add(struct buffer *buf, void *data, size_t len, int *ret_code);
const void *buffer_fmt_add(struct buffer *buf, int *ret_code, const char *fmt, ...);
const void *buffer_vfmt_add(struct buffer *buf, int *ret_code, const char *fmt, va_list ap);
int buffer_rewind(struct buffer *buf, size_t pos, buffer_pos_t whence);
int buffer_rewind_mem(struct buffer *buf, const void *mem);
bool buffer_is_complete(struct buffer *buf, int *ret_code);
ssize_t buffer_read(struct buffer *buf, int fd);
ssize_t buffer_write(struct buffer *buf, int fd, size_t pos);
int buffer_get_data(struct buffer *buf, const void **data, size_t *data_size);
struct buffer_stat buffer_stat(struct buffer *buf);
int buffer_write_all(struct buffer *buf, int fd);

#ifdef __cplusplus
}
#endif

#endif
