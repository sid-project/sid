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

#ifndef _SID_FORMATTER_H
#define _SID_FORMATTER_H

#include "base/buffer.h"

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

int fmt_doc_start_print(fmt_output_t format, struct sid_buf *buf, int level);
int fmt_doc_end_print(fmt_output_t format, struct sid_buf *buf, int level);

int fmt_arr_start_print(fmt_output_t format, struct sid_buf *buf, int level, const char *array_name, bool with_comma);
int fmt_arr_end_print(fmt_output_t format, struct sid_buf *buf, int level);

int fmt_elm_start_print(fmt_output_t format, struct sid_buf *buf, int level, bool with_comma);
int fmt_elm_end_print(fmt_output_t format, struct sid_buf *buf, int level);

int fmt_elm_name_print(fmt_output_t format, struct sid_buf *buf, int level, const char *elem_name, bool with_comma);

int fmt_fld_str_print(fmt_output_t    format,
                      struct sid_buf *buf,
                      int             level,
                      const char     *field_name,
                      const char     *value,
                      bool            with_comma);

int fmt_fld_bin_print(fmt_output_t    format,
                      struct sid_buf *buf,
                      int             level,
                      const char     *field_name,
                      const char     *value,
                      size_t          len,
                      bool            with_comma);

int fmt_fld_uint_print(fmt_output_t format, struct sid_buf *buf, int level, const char *field_name, uint value, bool with_comma);

int fmt_fld_uint64_print(fmt_output_t    format,
                         struct sid_buf *buf,
                         int             level,
                         const char     *field_name,
                         uint64_t        value,
                         bool            with_comma);

int fmt_fld_int64_print(fmt_output_t    format,
                        struct sid_buf *buf,
                        int             level,
                        const char     *field_name,
                        int64_t         value,
                        bool            with_comma);

int fmt_arr_fld_bool_print(fmt_output_t    format,
                           struct sid_buf *buf,
                           int             level,
                           const char     *field_name,
                           bool            value,
                           bool            with_comma);

int fmt_arr_fld_uint_print(fmt_output_t format, struct sid_buf *buf, int level, uint value, bool with_comma);

int fmt_arr_fld_str_print(fmt_output_t format, struct sid_buf *buf, int level, const char *value, bool with_comma);

int fmt_arr_fld_bin_print(fmt_output_t format, struct sid_buf *buf, int level, const char *value, size_t len, bool with_comma);

int fmt_byte_null_print(struct sid_buf *buf);

#ifdef __cplusplus
}
#endif

#endif
