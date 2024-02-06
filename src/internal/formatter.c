/*
 * This file is part of SID.
 *
 * Copyright (C) 2020-2021 Red Hat, Inc. All rights reserved.
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

#define JSON_START_ELEM  "{"
#define JSON_END_ELEM    "}"
#define JSON_START_ARRAY "["
#define JSON_END_ARRAY   "]"
#define JSON_INDENT      "    "

#define JOIN_STR(format) ((format == TABLE) ? ": " : "=")

static int _print_fmt(struct sid_buf *buf, const char *fmt, ...)
{
	va_list ap;
	int     r;

	if (!buf || !fmt)
		return -EINVAL;

	va_start(ap, fmt);

	r = sid_buf_vfmt_add(buf, NULL, NULL, fmt, ap);
	if (!r)
		r = sid_buf_rewind(buf, 1, SID_BUF_POS_REL);

	va_end(ap);
	return r;
}

static int _print_binary(const unsigned char *value, size_t len, struct sid_buf *buf)
{
	int         r;
	size_t      enc_len;
	const char *ptr;

	if (!value || !buf)
		return -EINVAL;

	if ((enc_len = sid_conv_bin_len_encode(len)) == 0)
		return -ERANGE;

	r = sid_buf_add(buf, NULL, enc_len, (const void **) &ptr, NULL);
	if (!r)
		r = sid_conv_bin_encode(value, len, (unsigned char *) ptr, enc_len);
	if (!r)
		r = sid_buf_rewind(buf, 1, SID_BUF_POS_REL);

	sid_buf_mem_unbind(buf, ptr);
	return r;
}

static int _print_indent(struct sid_buf *buf, int level)
{
	int r = 0;

	if (!buf)
		return -EINVAL;

	for (int i = 0; i < level && !r; i++) {
		r = _print_fmt(buf, JSON_INDENT);
	}

	return r;
}

int print_start_document(output_format_t format, struct sid_buf *buf, int level)
{
	int r = 0;

	if (!buf)
		return -EINVAL;

	if (format == JSON) {
		r = _print_indent(buf, level);
		if (!r)
			r = _print_fmt(buf, JSON_START_ELEM);
	}

	return r;
}

int print_end_document(output_format_t format, struct sid_buf *buf, int level)
{
	int r = 0;

	if (!buf)
		return -EINVAL;

	if (format == JSON) {
		r = _print_fmt(buf, "\n");
		if (!r)
			r = _print_indent(buf, level);
		if (!r)
			r = _print_fmt(buf, JSON_END_ELEM "\n");
	}

	return r;
}

int print_start_array(output_format_t format, struct sid_buf *buf, int level, const char *array_name, bool with_comma)
{
	int r = 0;

	if (!array_name || !buf)
		return -EINVAL;

	if (format == JSON) {
		r = _print_fmt(buf, "%s\n", with_comma ? "," : "");
		if (!r)
			r = _print_indent(buf, level);
		if (!r)
			r = _print_fmt(buf, "\"%s\": %s", array_name, JSON_START_ARRAY);
	} else if (format == TABLE)
		r = _print_fmt(buf, "%s:\n", array_name);

	return r;
}

int print_end_array(output_format_t format, struct sid_buf *buf, int level)
{
	int r = 0;

	if (!buf)
		return -EINVAL;

	if (format == JSON) {
		r = _print_fmt(buf, "\n");
		if (!r)
			r = _print_indent(buf, level);
		if (!r)
			r = _print_fmt(buf, JSON_END_ARRAY);
	}

	return r;
}

int print_start_elem(output_format_t format, struct sid_buf *buf, int level, bool with_comma)
{
	int r = 0;

	if (!buf)
		return -EINVAL;

	if (format == JSON) {
		r = _print_fmt(buf, "%s\n", with_comma ? "," : "");
		if (!r)
			r = _print_indent(buf, level);
		if (!r)
			r = _print_fmt(buf, JSON_START_ELEM);
	} else if (format == TABLE && with_comma)
		r = _print_fmt(buf, "\n");

	return r;
}

int print_end_elem(output_format_t format, struct sid_buf *buf, int level)
{
	int r = 0;

	if (!buf)
		return -EINVAL;

	if (format == JSON) {
		r = _print_fmt(buf, "\n");
		if (!r)
			r = _print_indent(buf, level);
		if (!r)
			r = _print_fmt(buf, JSON_END_ELEM);
	}

	return r;
}

int print_elem_name(output_format_t format, struct sid_buf *buf, int level, const char *elem_name, bool with_comma)
{
	int r = 0;

	if (!elem_name || !buf)
		return -EINVAL;

	if (format == JSON) {
		r = _print_fmt(buf, "%s\n", with_comma ? "," : "");
		if (!r)
			r = _print_indent(buf, level);
		if (!r)
			r = _print_fmt(buf, "\"%s\":\n", elem_name);
	} else if (format == TABLE)
		r = _print_fmt(buf, "%s%s:\n", with_comma ? "\n" : "", elem_name);

	return r;
}

int print_str_field(output_format_t format,
                    struct sid_buf *buf,
                    int             level,
                    const char     *field_name,
                    const char     *value,
                    bool            with_comma)
{
	int r = 0;

	if (!field_name || !value || !buf)
		return -EINVAL;

	if (format == JSON) {
		r = _print_fmt(buf, "%s\n", with_comma ? "," : "");
		if (!r)
			r = _print_indent(buf, level);
		if (!r)
			r = _print_fmt(buf, "\"%s\": \"%s\"", field_name, value);
	} else
		r = _print_fmt(buf, "%s%s%s\n", field_name, JOIN_STR(format), value);

	return r;
}

int print_binary_field(output_format_t format,
                       struct sid_buf *buf,
                       int             level,
                       const char     *field_name,
                       const char     *value,
                       size_t          len,
                       bool            with_comma)
{
	int r = 0;

	if (!field_name || !value || !buf)
		return -EINVAL;

	if (format == JSON) {
		r = _print_fmt(buf, "%s\n", with_comma ? "," : "");
		if (!r)
			r = _print_indent(buf, level);
		if (!r)
			r = _print_fmt(buf, "\"%s\": \"", field_name);
		if (!r)
			r = _print_binary((const unsigned char *) value, len, buf);
		if (!r)
			r = _print_fmt(buf, "\"");
	} else {
		_print_fmt(buf, "%s%s", field_name, JOIN_STR(format));
		_print_binary((const unsigned char *) value, len, buf);
		_print_fmt(buf, "\n");
	}

	return r;
}

int print_uint_field(output_format_t format, struct sid_buf *buf, int level, const char *field_name, uint value, bool with_comma)
{
	int r = 0;

	if (!field_name || !buf)
		return -EINVAL;

	if (format == JSON) {
		r = _print_fmt(buf, "%s\n", with_comma ? "," : "");
		if (!r)
			r = _print_indent(buf, level);
		if (!r)
			r = _print_fmt(buf, "\"%s\": %u", field_name, value);
	} else
		r = _print_fmt(buf, "%s%s%u\n", field_name, JOIN_STR(format), value);

	return r;
}

int print_uint64_field(output_format_t format,
                       struct sid_buf *buf,
                       int             level,
                       const char     *field_name,
                       uint64_t        value,
                       bool            with_comma)
{
	int r = 0;

	if (!field_name || !buf)
		return -EINVAL;

	if (format == JSON) {
		r = _print_fmt(buf, "%s\n", with_comma ? "," : "");
		if (!r)
			r = _print_indent(buf, level);
		if (!r)
			r = _print_fmt(buf, "\"%s\": %" PRIu64, field_name, value);
	} else
		r = _print_fmt(buf, "%s%s%" PRIu64 "\n", field_name, JOIN_STR(format), value);

	return r;
}

int print_int64_field(output_format_t format,
                      struct sid_buf *buf,
                      int             level,
                      const char     *field_name,
                      int64_t         value,
                      bool            with_comma)
{
	int r = 0;

	if (!field_name || !buf)
		return -EINVAL;

	if (format == JSON) {
		r = _print_fmt(buf, "%s\n", with_comma ? "," : "");
		if (!r)
			r = _print_indent(buf, level);
		if (!r)
			r = _print_fmt(buf, "\"%s\": %" PRIi64, field_name, value);
	} else
		r = _print_fmt(buf, "%s%s%" PRIi64 "\n", field_name, JOIN_STR(format), value);

	return r;
}

int print_bool_array_elem(output_format_t format,
                          struct sid_buf *buf,
                          int             level,
                          const char     *field_name,
                          bool            value,
                          bool            with_comma)
{
	int r = 0;

	if (!field_name || !buf)
		return -EINVAL;

	if (format == JSON) {
		r = _print_fmt(buf, "%s\n", with_comma ? "," : "");
		if (!r)
			r = _print_indent(buf, level);
		if (!r)
			r = _print_fmt(buf, "{\"%s\": %s}", field_name, value ? "true" : "false");
	} else if (format == ENV) {
		r = _print_fmt(buf, "%s=%d\n", field_name, value);
	} else if (value)
		r = _print_fmt(buf, "%s\n", field_name);

	return r;
}

int print_uint_array_elem(output_format_t format, struct sid_buf *buf, int level, uint value, bool with_comma)
{
	int r = 0;

	if (!buf)
		return -EINVAL;

	if (format == JSON) {
		r = _print_fmt(buf, "%s\n", with_comma ? "," : "");
		if (!r)
			r = _print_indent(buf, level);
		if (!r)
			r = _print_fmt(buf, "%u", value);
	} else if (format == TABLE)
		r = _print_fmt(buf, "%u\n", value);

	return r;
}

int print_str_array_elem(output_format_t format, struct sid_buf *buf, int level, const char *value, bool with_comma)
{
	int r = 0;

	if (!buf || !value)
		return -EINVAL;

	if (format == JSON) {
		r = _print_fmt(buf, "%s\n", with_comma ? "," : "");
		if (!r)
			r = _print_indent(buf, level);
		if (!r)
			r = _print_fmt(buf, "\"%s\"", value);
	} else if (format == TABLE)
		r = _print_fmt(buf, "%s\n", value);

	return r;
}

int print_binary_array_elem(output_format_t format, struct sid_buf *buf, int level, const char *value, size_t len, bool with_comma)
{
	int r = 0;

	if (!buf || !value)
		return -EINVAL;

	if (format == JSON) {
		r = _print_fmt(buf, "%s\n", with_comma ? "," : "");
		if (!r)
			r = _print_indent(buf, level);
		if (!r)
			r = _print_fmt(buf, "\"");
		if (!r)
			r = _print_binary((const unsigned char *) value, len, buf);
		if (!r)
			r = _print_fmt(buf, "\"");
	} else if (format == TABLE) {
		r = _print_binary((const unsigned char *) value, len, buf);
		if (!r)
			r = _print_fmt(buf, "\n");
	}

	return r;
}

int print_null_byte(struct sid_buf *buf)
{
	return sid_buf_fmt_add(buf, NULL, NULL, "");
}
