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
	NO_FORMAT = -1,
	TABLE,
	JSON,
	ENV,
} output_format_t;

int print_start_document(output_format_t format, struct sid_buf *buf, int level);
int print_end_document(output_format_t format, struct sid_buf *buf, int level);

int print_start_array(output_format_t format, struct sid_buf *buf, int level, const char *array_name, bool with_comma);
int print_end_array(output_format_t format, struct sid_buf *buf, int level);

int print_start_elem(output_format_t format, struct sid_buf *buf, int level, bool with_comma);
int print_end_elem(output_format_t format, struct sid_buf *buf, int level);

int print_elem_name(output_format_t format, struct sid_buf *buf, int level, const char *elem_name, bool with_comma);

int print_str_field(output_format_t format,
                    struct sid_buf *buf,
                    int             level,
                    const char     *field_name,
                    const char     *value,
                    bool            with_comma);

int print_binary_field(output_format_t format,
                       struct sid_buf *buf,
                       int             level,
                       const char     *field_name,
                       const char     *value,
                       size_t          len,
                       bool            with_comma);

int print_uint_field(output_format_t format, struct sid_buf *buf, int level, const char *field_name, uint value, bool with_comma);

int print_uint64_field(output_format_t format,
                       struct sid_buf *buf,
                       int             level,
                       const char     *field_name,
                       uint64_t        value,
                       bool            with_comma);

int print_int64_field(output_format_t format,
                      struct sid_buf *buf,
                      int             level,
                      const char     *field_name,
                      int64_t         value,
                      bool            with_comma);

int print_bool_array_elem(output_format_t format,
                          struct sid_buf *buf,
                          int             level,
                          const char     *field_name,
                          bool            value,
                          bool            with_comma);

int print_uint_array_elem(output_format_t format, struct sid_buf *buf, int level, uint value, bool with_comma);

int print_str_array_elem(output_format_t format, struct sid_buf *buf, int level, const char *value, bool with_comma);

int print_binary_array_elem(output_format_t format, struct sid_buf *buf, int level, const char *value, size_t len, bool with_comma);

int print_null_byte(struct sid_buf *buf);

#ifdef __cplusplus
}
#endif

#endif
