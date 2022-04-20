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

struct sid_buffer;

typedef enum
{
	SID_BUFFER_POS_ABS,
	SID_BUFFER_POS_REL,
} sid_buffer_pos_t;

struct sid_buffer *    sid_buffer_create(struct sid_buffer_spec *spec, struct sid_buffer_init *init, int *ret_code);
void                   sid_buffer_destroy(struct sid_buffer *buf);
int                    sid_buffer_reset(struct sid_buffer *buf);
int                    sid_buffer_reset_init(struct sid_buffer *buf, struct sid_buffer_init *init);
int                    sid_buffer_add(struct sid_buffer *buf, void *data, size_t len, const void **mem, size_t *pos);
int                    sid_buffer_fmt_add(struct sid_buffer *buf, const void **mem, size_t *pos, const char *fmt, ...);
int                    sid_buffer_vfmt_add(struct sid_buffer *buf, const void **mem, size_t *pos, const char *fmt, va_list ap);
int                    sid_buffer_unbind(struct sid_buffer *buf, size_t pos, sid_buffer_pos_t whence);
int                    sid_buffer_rewind(struct sid_buffer *buf, size_t pos, sid_buffer_pos_t whence);
int                    sid_buffer_unbind_mem(struct sid_buffer *buf, const void *mem);
int                    sid_buffer_rewind_mem(struct sid_buffer *buf, const void *mem);
bool                   sid_buffer_is_complete(struct sid_buffer *buf, int *ret_code);
ssize_t                sid_buffer_read(struct sid_buffer *buf, int fd);
ssize_t                sid_buffer_write(struct sid_buffer *buf, int fd, size_t pos);
int                    sid_buffer_get_data(struct sid_buffer *buf, const void **data, size_t *data_size);
int                    sid_buffer_get_fd(struct sid_buffer *buf);
size_t                 sid_buffer_count(struct sid_buffer *buf);
struct sid_buffer_stat sid_buffer_stat(struct sid_buffer *buf);
int                    sid_buffer_write_all(struct sid_buffer *buf, int fd);

#ifdef __cplusplus
}
#endif

#endif
