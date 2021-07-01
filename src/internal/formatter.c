/*
 * This file is part of SID.
 *
 * Copyright (C) 2001-2004 Sistina Software, Inc. All rights reserved.
 * Copyright (C) 2004-2021 Red Hat, Inc. All rights reserved.
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
#include "internal/formatter.h"

#include "base/binary.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>

#define PRINT_JSON_START_ARRAY "[\n"
#define PRINT_JSON_START_ELEM  "{\n"
#define PRINT_JSON_END_MAPS    "}\n"
#define PRINT_JSON_END_ELEM    "},\n"
#define PRINT_JSON_END_LAST    "}"
#define PRINT_JSON_END_ARRAY   "]"
#define PRINT_JSON_INDENT      "    "

#define JOIN_STR(format) ((format == TABLE) ? ": " : "=")

static int _print_fmt(struct buffer *buf, const char *fmt, ...)
{
	va_list ap;
	int     r;

	if (!buf || !fmt)
		return -EINVAL;
	va_start(ap, fmt);
	sid_buffer_vfmt_add(buf, &r, fmt, ap);
	if (!r)
		r = sid_buffer_rewind(buf, 1, BUFFER_POS_REL);
	va_end(ap);
	return r;
}

static int _print_binary(const unsigned char *value, size_t len, struct buffer *buf)
{
	int         r;
	size_t      enc_len = sid_binary_len_encode(len);
	const char *ptr;

	if ((len & !value) || !buf)
		return -EINVAL;
	if (enc_len == 0)
		return -ERANGE;
	ptr = sid_buffer_add(buf, NULL, enc_len, &r);
	if (!r)
		r = sid_binary_encode(value, len, (unsigned char *) ptr, enc_len);
	if (!r)
		r = sid_buffer_rewind(buf, 1, BUFFER_POS_REL);
	return r;
}

int print_indent(int level, struct buffer *buf)
{
	int r = 0;

	if (!buf)
		return -EINVAL;
	for (int i = 0; i < level && !r; i++) {
		r = _print_fmt(buf, PRINT_JSON_INDENT);
	}
	return r;
}

int print_start_document(output_format_t format, struct buffer *buf, int level)
{
	int r = 0;

	if (!buf)
		return -EINVAL;
	if (format == JSON) {
		r = print_indent(level, buf);
		if (!r)
			r = _print_fmt(buf, PRINT_JSON_START_ELEM);
	}
	return r;
}

int print_end_document(output_format_t format, struct buffer *buf, int level)
{
	int r = 0;

	if (!buf)
		return -EINVAL;
	if (format == JSON) {
		r = print_indent(level, buf);
		if (!r)
			r = _print_fmt(buf, PRINT_JSON_END_LAST "\n");
	}
	return r;
}

int print_start_array(const char *array_name, output_format_t format, struct buffer *buf, int level)
{
	int r = 0;

	if (!array_name || !buf)
		return -EINVAL;
	if (format == JSON) {
		r = print_indent(level, buf);
		if (!r)
			r = _print_fmt(buf, "\"%s\": %s", array_name, PRINT_JSON_START_ARRAY);
	} else if (format == TABLE)
		r = _print_fmt(buf, "%s:\n", array_name);

	return r;
}

int print_end_array(bool needs_comma, output_format_t format, struct buffer *buf, int level)
{
	int r = 0;

	if (!buf)
		return -EINVAL;
	if (format == JSON) {
		r = _print_fmt(buf, "\n");
		if (!r)
			r = print_indent(level, buf);
		if (!r)
			r = _print_fmt(buf, PRINT_JSON_END_ARRAY "%s\n", needs_comma ? "," : "");
	}
	return r;
}

int print_start_elem(bool needs_comma, output_format_t format, struct buffer *buf, int level)
{
	int r = 0;

	if (!buf)
		return -EINVAL;
	if (format == JSON) {
		if (needs_comma)
			r = _print_fmt(buf, ",\n");
		if (!r)
			r = print_indent(level, buf);
		if (!r)
			r = _print_fmt(buf, PRINT_JSON_START_ELEM);
	} else if (format == TABLE && needs_comma)
		r = _print_fmt(buf, "\n");

	return r;
}

int print_end_elem(output_format_t format, struct buffer *buf, int level)
{
	int r = 0;

	if (!buf)
		return -EINVAL;
	if (format == JSON) {
		r = print_indent(level, buf);
		if (!r)
			r = _print_fmt(buf, PRINT_JSON_END_LAST);
	}
	return r;
}

int print_elem_name(bool needs_comma, const char *elem_name, output_format_t format, struct buffer *buf, int level)
{
	int r = 0;

	if (!elem_name || !buf)
		return -EINVAL;
	if (format == JSON) {
		if (needs_comma)
			r = _print_fmt(buf, ",\n");
		if (!r)
			r = print_indent(level, buf);
		if (!r)
			r = _print_fmt(buf, "\"%s\":\n", elem_name);
	} else if (format == TABLE)
		r = _print_fmt(buf, "%s%s:\n", needs_comma ? "\n" : "", elem_name);

	return r;
}

int print_str_field(const char *    field_name,
                    const char *    value,
                    output_format_t format,
                    struct buffer * buf,
                    bool            trailing_comma,
                    int             level)
{
	int r = 0;

	if (!field_name || !value || !buf)
		return -EINVAL;
	if (format == JSON) {
		r = print_indent(level, buf);
		if (!r)
			r = _print_fmt(buf, "\"%s\": \"%s\"%s\n", field_name, value, trailing_comma ? "," : "");
	} else
		r = _print_fmt(buf, "%s%s%s\n", field_name, JOIN_STR(format), value);

	return r;
}

int print_binary_field(const char *    field_name,
                       const char *    value,
                       size_t          len,
                       output_format_t format,
                       struct buffer * buf,
                       bool            trailing_comma,
                       int             level)
{
	int r = 0;

	if (!field_name || !value || !buf)
		return -EINVAL;
	if (format == JSON) {
		r = print_indent(level, buf);
		if (!r)
			r = _print_fmt(buf, "\"%s\": \"", field_name);
		if (!r)
			r = _print_binary((const unsigned char *) value, len, buf);
		if (!r)
			r = _print_fmt(buf, "\"%s\n", trailing_comma ? "," : "");
	} else {
		_print_fmt(buf, "%s%s", field_name, JOIN_STR(format));
		_print_binary((const unsigned char *) value, len, buf);
		_print_fmt(buf, "\n");
	}
	return r;
}

int print_uint_field(const char *field_name, uint value, output_format_t format, struct buffer *buf, bool trailing_comma, int level)
{
	int r = 0;

	if (!field_name || !buf)
		return -EINVAL;
	if (format == JSON) {
		r = print_indent(level, buf);
		if (!r)
			r = _print_fmt(buf, "\"%s\": %u%s\n", field_name, value, trailing_comma ? "," : "");
	} else
		r = _print_fmt(buf, "%s%s%u\n", field_name, JOIN_STR(format), value);

	return r;
}

int print_uint64_field(const char *    field_name,
                       uint64_t        value,
                       output_format_t format,
                       struct buffer * buf,
                       bool            trailing_comma,
                       int             level)
{
	int r = 0;

	if (!field_name || !buf)
		return -EINVAL;
	if (format == JSON) {
		r = print_indent(level, buf);
		if (!r)
			r = _print_fmt(buf, "\"%s\": %" PRIu64 "%s\n", field_name, value, trailing_comma ? "," : "");
	} else
		r = _print_fmt(buf, "%s%s%" PRIu64 "\n", field_name, JOIN_STR(format), value);

	return r;
}

int print_int64_field(const char *    field_name,
                      int64_t         value,
                      output_format_t format,
                      struct buffer * buf,
                      bool            trailing_comma,
                      int             level)
{
	int r = 0;

	if (!field_name || !buf)
		return -EINVAL;
	if (format == JSON) {
		r = print_indent(level, buf);
		if (!r)
			r = _print_fmt(buf, "\"%s\": %" PRIi64 "%s\n", field_name, value, trailing_comma ? "," : "");
	} else
		r = _print_fmt(buf, "%s%s%" PRIi64 "\n", field_name, JOIN_STR(format), value);

	return r;
}

int print_bool_array_elem(const char *    field_name,
                          bool            value,
                          output_format_t format,
                          struct buffer * buf,
                          bool            trailing_comma,
                          int             level)
{
	int r = 0;

	if (!field_name || !buf)
		return -EINVAL;
	if (format == JSON) {
		r = print_indent(level, buf);
		if (!r)
			r = _print_fmt(buf, "{\"%s\": %s}%s", field_name, value ? "true" : "false", trailing_comma ? ",\n" : "");
	} else if (format == ENV) {
		r = _print_fmt(buf, "%s=%d\n", field_name, value);
	} else if (value)
		r = _print_fmt(buf, "%s\n", field_name);

	return r;
}

int print_uint_array_elem(uint value, output_format_t format, struct buffer *buf, bool trailing_comma, int level)
{
	int r = 0;

	if (!buf)
		return -EINVAL;
	if (format == JSON) {
		r = print_indent(level, buf);
		if (!r)
			r = _print_fmt(buf, "%u%s", value, trailing_comma ? ",\n" : "");
	} else if (format == TABLE)
		r = _print_fmt(buf, "%u\n", value);

	return r;
}

int print_str_array_elem(const char *value, output_format_t format, struct buffer *buf, bool trailing_comma, int level)
{
	int r = 0;

	if (!buf || !value)
		return -EINVAL;
	if (format == JSON) {
		r = print_indent(level, buf);
		if (!r)
			r = _print_fmt(buf, "\"%s\"%s", value, trailing_comma ? ",\n" : "");
	} else if (format == TABLE)
		r = _print_fmt(buf, "%s\n", value);

	return r;
}

int print_binary_array_elem(const char *    value,
                            size_t          len,
                            output_format_t format,
                            struct buffer * buf,
                            bool            trailing_comma,
                            int             level)
{
	int r = 0;

	if (!buf || !value)
		return -EINVAL;
	if (format == JSON) {
		r = print_indent(level, buf);
		if (!r)
			r = _print_fmt(buf, "\"");
		if (!r)
			r = _print_binary((const unsigned char *) value, len, buf);
		if (!r)
			r = _print_fmt(buf, "\"%s", trailing_comma ? ",\n" : "");
	} else if (format == TABLE) {
		r = _print_binary((const unsigned char *) value, len, buf);
		if (!r)
			r = _print_fmt(buf, "\n");
	}
	return r;
}

int print_null_byte(struct buffer *buf)
{
	int r;

	sid_buffer_fmt_add(buf, &r, "");
	return r;
}
