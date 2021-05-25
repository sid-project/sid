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
#include "base/formatter.h"

#include "base/base64.h"

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

static void _print_fmt(struct buffer *buf, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	buffer_vfmt_add(buf, NULL, fmt, ap);
	buffer_rewind(buf, 1, BUFFER_POS_REL);
	va_end(ap);
}

static void _print_binary(unsigned char *value, size_t len, struct buffer *buf)
{
	size_t      enc_len = base64_len_encode(len);
	const char *ptr     = buffer_add(buf, NULL, enc_len, NULL);
	base64_encode(value, len, (unsigned char *) ptr, enc_len);
	buffer_rewind(buf, 1, BUFFER_POS_REL);
}

void print_indent(int level, struct buffer *buf)
{
	for (int i = 0; i < level; i++) {
		_print_fmt(buf, PRINT_JSON_INDENT);
	}
}

void print_start_document(output_format_t format, struct buffer *buf, int level)
{
	if (format == JSON) {
		print_indent(level, buf);
		_print_fmt(buf, PRINT_JSON_START_ELEM);
	}
}

void print_end_document(output_format_t format, struct buffer *buf, int level)
{
	if (format == JSON) {
		print_indent(level, buf);
		_print_fmt(buf, PRINT_JSON_END_LAST "\n");
	}
}

void print_start_array(char *array_name, output_format_t format, struct buffer *buf, int level)
{
	if (format == JSON) {
		print_indent(level, buf);
		_print_fmt(buf, "\"%s\": %s", array_name, PRINT_JSON_START_ARRAY);
	} else if (format == TABLE)
		_print_fmt(buf, "%s:\n", array_name);
}

void print_end_array(bool needs_comma, output_format_t format, struct buffer *buf, int level)
{
	if (format == JSON) {
		_print_fmt(buf, "\n");
		print_indent(level, buf);
		_print_fmt(buf, PRINT_JSON_END_ARRAY "%s\n", needs_comma ? "," : "");
	}
}

void print_start_elem(bool needs_comma, output_format_t format, struct buffer *buf, int level)
{
	if (format == JSON) {
		if (needs_comma)
			_print_fmt(buf, ",\n");
		print_indent(level, buf);
		_print_fmt(buf, PRINT_JSON_START_ELEM);
	} else if (format == TABLE && needs_comma)
		_print_fmt(buf, "\n");
}

void print_end_elem(output_format_t format, struct buffer *buf, int level)
{
	if (format == JSON) {
		print_indent(level, buf);
		_print_fmt(buf, PRINT_JSON_END_LAST);
	}
}

void print_elem_name(bool needs_comma, char *elem_name, output_format_t format, struct buffer *buf, int level)
{
	if (format == JSON) {
		if (needs_comma)
			_print_fmt(buf, ",\n");
		print_indent(level, buf);
		_print_fmt(buf, "\"%s\":\n", elem_name);
	} else if (format == TABLE)
		_print_fmt(buf, "%s%s:\n", needs_comma ? "\n" : "", elem_name);
}

void print_str_field(char *field_name, char *value, output_format_t format, struct buffer *buf, bool trailing_comma, int level)
{
	if (format == JSON) {
		print_indent(level, buf);
		_print_fmt(buf, "\"%s\": \"%s\"%s\n", field_name, value, trailing_comma ? "," : "");
	} else
		_print_fmt(buf, "%s%s%s\n", field_name, JOIN_STR(format), value);
}

void print_binary_field(char *          field_name,
                        char *          value,
                        size_t          len,
                        output_format_t format,
                        struct buffer * buf,
                        bool            trailing_comma,
                        int             level)
{
	if (format == JSON) {
		print_indent(level, buf);
		_print_fmt(buf, "\"%s\": \"", field_name);
		_print_binary((unsigned char *) value, len, buf);
		_print_fmt(buf, "\"%s\n", trailing_comma ? "," : "");
	} else {
		_print_fmt(buf, "%s%s", field_name, JOIN_STR(format));
		_print_binary((unsigned char *) value, len, buf);
		_print_fmt(buf, "\n");
	}
}

void print_uint_field(char *field_name, uint value, output_format_t format, struct buffer *buf, bool trailing_comma, int level)
{
	if (format == JSON) {
		print_indent(level, buf);
		_print_fmt(buf, "\"%s\": %u%s\n", field_name, value, trailing_comma ? "," : "");
	} else
		_print_fmt(buf, "%s%s%u\n", field_name, JOIN_STR(format), value);
}

void print_uint64_field(char *          field_name,
                        uint64_t        value,
                        output_format_t format,
                        struct buffer * buf,
                        bool            trailing_comma,
                        int             level)
{
	if (format == JSON) {
		print_indent(level, buf);
		_print_fmt(buf, "\"%s\": %" PRIu64 "%s\n", field_name, value, trailing_comma ? "," : "");
	} else
		_print_fmt(buf, "%s%s%" PRIu64 "\n", field_name, JOIN_STR(format), value);
}

void print_int64_field(char *field_name, int64_t value, output_format_t format, struct buffer *buf, bool trailing_comma, int level)
{
	if (format == JSON) {
		print_indent(level, buf);
		_print_fmt(buf, "\"%s\": %" PRIi64 "%s\n", field_name, value, trailing_comma ? "," : "");
	} else
		_print_fmt(buf, "%s%s%" PRIi64 "\n", field_name, JOIN_STR(format), value);
}

void print_bool_array_elem(char *field_name, bool value, output_format_t format, struct buffer *buf, bool trailing_comma, int level)
{
	if (format == JSON) {
		print_indent(level, buf);
		_print_fmt(buf, "{\"%s\": %s}%s", field_name, value ? "true" : "false", trailing_comma ? ",\n" : "");
	} else if (format == ENV) {
		_print_fmt(buf, "%s=%d\n", field_name, value);
	} else if (value)
		_print_fmt(buf, "%s\n", field_name);
}

void print_uint_array_elem(uint value, output_format_t format, struct buffer *buf, bool trailing_comma, int level)
{
	if (format == JSON) {
		print_indent(level, buf);
		_print_fmt(buf, "%u%s", value, trailing_comma ? ",\n" : "");
	} else if (format == TABLE)
		_print_fmt(buf, "%u\n", value);
}

void print_str_array_elem(char *value, output_format_t format, struct buffer *buf, bool trailing_comma, int level)
{
	if (format == JSON) {
		print_indent(level, buf);
		_print_fmt(buf, "\"%s\"%s", value, trailing_comma ? ",\n" : "");
	} else if (format == TABLE)
		_print_fmt(buf, "%s\n", value);
}

void print_binary_array_elem(char *value, size_t len, output_format_t format, struct buffer *buf, bool trailing_comma, int level)
{
	if (format == JSON) {
		print_indent(level, buf);
		_print_fmt(buf, "\"");
		_print_binary((unsigned char *) value, len, buf);
		_print_fmt(buf, "\"%s", trailing_comma ? ",\n" : "");
	} else if (format == TABLE) {
		_print_binary((unsigned char *) value, len, buf);
		_print_fmt(buf, "\n");
	}
}

void print_null_byte(struct buffer *buf)
{
	buffer_fmt_add(buf, NULL, "");
}
