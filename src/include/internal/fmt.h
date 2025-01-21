/*
 * SPDX-FileCopyrightText: (C) 2017-2025 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _SID_FMT_H
#define _SID_FMT_H

#include "base/buf.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	FMT_NONE = -1,
	FMT_TABLE,
	FMT_JSON,
	FMT_ENV,
} fmt_output_t;

int fmt_doc_start(fmt_output_t format, struct sid_buf *buf, int level);
int fmt_doc_end(fmt_output_t format, struct sid_buf *buf, int level);

int fmt_arr_start(fmt_output_t format, struct sid_buf *buf, int level, const char *array_name, bool with_comma);
int fmt_arr_end(fmt_output_t format, struct sid_buf *buf, int level);

int fmt_elm_start(fmt_output_t format, struct sid_buf *buf, int level, bool with_comma);
int fmt_elm_end(fmt_output_t format, struct sid_buf *buf, int level);

int fmt_elm_name(fmt_output_t format, struct sid_buf *buf, int level, const char *elem_name, bool with_comma);

int fmt_fld_str(fmt_output_t format, struct sid_buf *buf, int level, const char *field_name, const char *value, bool with_comma);

int fmt_fld_bin(fmt_output_t    format,
                struct sid_buf *buf,
                int             level,
                const char     *field_name,
                const char     *value,
                size_t          len,
                bool            with_comma);

int fmt_fld_uint(fmt_output_t format, struct sid_buf *buf, int level, const char *field_name, uint value, bool with_comma);

int fmt_fld_uint64(fmt_output_t format, struct sid_buf *buf, int level, const char *field_name, uint64_t value, bool with_comma);

int fmt_fld_int64(fmt_output_t format, struct sid_buf *buf, int level, const char *field_name, int64_t value, bool with_comma);

int fmt_fld_bool(fmt_output_t format, struct sid_buf *buf, int level, const char *field_name, bool value, bool with_comma);

int fmt_arr_fld_uint(fmt_output_t format, struct sid_buf *buf, int level, uint value, bool with_comma);

int fmt_arr_fld_str(fmt_output_t format, struct sid_buf *buf, int level, const char *value, bool with_comma);

int fmt_arr_fld_bin(fmt_output_t format, struct sid_buf *buf, int level, const char *value, size_t len, bool with_comma);

int fmt_null_byte(struct sid_buf *buf);

#ifdef __cplusplus
}
#endif

#endif
