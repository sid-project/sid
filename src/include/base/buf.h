/*
 * SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _SID_BUF_H
#define _SID_BUF_H

#include "base/buf-common.h"

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
