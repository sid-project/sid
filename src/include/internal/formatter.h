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

typedef enum
{
	NO_FORMAT = -1,
	TABLE,
	JSON,
	ENV,
} output_format_t;

int print_indent(int level, struct buffer *buf);
int print_start_document(output_format_t format, struct buffer *buf, int level);
int print_end_document(output_format_t format, struct buffer *buf, int level);
int print_start_array(const char *array_name, output_format_t format, struct buffer *buf, int level);
int print_end_array(bool needs_comma, output_format_t format, struct buffer *buf, int level);
int print_start_elem(bool needs_comma, output_format_t format, struct buffer *buf, int level);
int print_end_elem(output_format_t format, struct buffer *buf, int level);
int print_elem_name(bool needs_comma, const char *elem_name, output_format_t format, struct buffer *buf, int level);
int print_str_field(const char *    field_name,
                    const char *    value,
                    output_format_t format,
                    struct buffer * buf,
                    bool            trailing_comma,
                    int             level);
int print_binary_field(const char *    field_name,
                       const char *    value,
                       size_t          len,
                       output_format_t format,
                       struct buffer * buf,
                       bool            trailing_comma,
                       int             level);
int print_uint_field(const char *    field_name,
                     uint            value,
                     output_format_t format,
                     struct buffer * buf,
                     bool            trailing_comma,
                     int             level);
int print_uint64_field(const char *    field_name,
                       uint64_t        value,
                       output_format_t format,
                       struct buffer * buf,
                       bool            trailing_comma,
                       int             level);
int print_int64_field(const char *    field_name,
                      int64_t         value,
                      output_format_t format,
                      struct buffer * buf,
                      bool            trailing_comma,
                      int             level);
int print_bool_array_elem(const char *    field_name,
                          bool            value,
                          output_format_t format,
                          struct buffer * buf,
                          bool            trailing_comma,
                          int             level);
int print_uint_array_elem(uint value, output_format_t format, struct buffer *buf, bool trailing_comma, int level);
int print_str_array_elem(const char *value, output_format_t format, struct buffer *buf, bool trailing_comma, int level);
int print_binary_array_elem(const char *    value,
                            size_t          len,
                            output_format_t format,
                            struct buffer * buf,
                            bool            trailing_comma,
                            int             level);
int print_null_byte(struct buffer *buf);

#ifdef __cplusplus
}
#endif

#endif
