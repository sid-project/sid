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

#include <stdarg.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct sid_buf;

typedef enum {
	SID_BUF_POS_ABS,
	SID_BUF_POS_REL,
} sid_buf_pos_t;

struct sid_buf     *sid_buf_create(const struct sid_buf_spec *spec, const struct sid_buf_init *init, int *ret_code);
void                sid_buf_destroy(struct sid_buf *buf);
int                 sid_buf_reset(struct sid_buf *buf);
int                 sid_buf_reset_init(struct sid_buf *buf, const struct sid_buf_init *init);
int                 sid_buf_add(struct sid_buf *buf, const void *data, size_t len, const void **mem, size_t *pos);
int                 sid_buf_add_fmt(struct sid_buf *buf, const void **mem, size_t *pos, const char *fmt, ...);
int                 sid_buf_add_vfmt(struct sid_buf *buf, const void **mem, size_t *pos, const char *fmt, va_list ap);
int                 sid_buf_unbind(struct sid_buf *buf, size_t pos, sid_buf_pos_t whence);
int                 sid_buf_rewind(struct sid_buf *buf, size_t pos, sid_buf_pos_t whence);
int                 sid_buf_unbind_mem(struct sid_buf *buf, const void *mem);
int                 sid_buf_rewind_mem(struct sid_buf *buf, const void *mem);
bool                sid_buf_is_complete(struct sid_buf *buf, int *ret_code);
ssize_t             sid_buf_read(struct sid_buf *buf, int fd);
ssize_t             sid_buf_write(struct sid_buf *buf, int fd, size_t pos);
int                 sid_buf_get_data_from(struct sid_buf *buf, size_t pos, const void **data, size_t *data_size);
int                 sid_buf_get_data(struct sid_buf *buf, const void **data, size_t *data_size);
int                 sid_buf_get_fd(struct sid_buf *buf);
size_t              sid_buf_count(struct sid_buf *buf);
struct sid_buf_stat sid_buf_stat(struct sid_buf *buf);
int                 sid_buf_write_all(struct sid_buf *buf, int fd);

#ifdef __cplusplus
}
#endif

#endif
