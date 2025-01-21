/*
 * SPDX-FileCopyrightText: (C) 2017-2025 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "internal/fmt.h"

#include "base/conv.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>

#define JSON_START_ELEM  "{"
#define JSON_END_ELEM    "}"
#define JSON_START_ARRAY "["
#define JSON_END_ARRAY   "]"
#define JSON_INDENT      "    "

#define JOIN_STR(format) ((format == FMT_TABLE) ? ": " : "=")

static int _print_fmt(struct sid_buf *buf, const char *fmt, ...)
{
	va_list ap;
	int     r;

	if (!buf || !fmt)
		return -EINVAL;

	va_start(ap, fmt);

	r = sid_buf_add_vfmt(buf, NULL, NULL, fmt, ap);
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

	if ((enc_len = sid_conv_base64_encoded_len(len)) == 0)
		return -ERANGE;

	r = sid_buf_add(buf, NULL, enc_len, (const void **) &ptr, NULL);
	if (!r)
		r = sid_conv_base64_encode(value, len, (unsigned char *) ptr, enc_len);
	if (!r)
		r = sid_buf_rewind(buf, 1, SID_BUF_POS_REL);

	sid_buf_unbind_mem(buf, ptr);
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

int fmt_doc_start(fmt_output_t format, struct sid_buf *buf, int level)
{
	int r = 0;

	if (!buf)
		return -EINVAL;

	if (format == FMT_JSON) {
		r = _print_indent(buf, level);
		if (!r)
			r = _print_fmt(buf, JSON_START_ELEM);
	}

	return r;
}

int fmt_doc_end(fmt_output_t format, struct sid_buf *buf, int level)
{
	int r = 0;

	if (!buf)
		return -EINVAL;

	if (format == FMT_JSON) {
		r = _print_fmt(buf, "\n");
		if (!r)
			r = _print_indent(buf, level);
		if (!r)
			r = _print_fmt(buf, JSON_END_ELEM "\n");
	}

	return r;
}

int fmt_arr_start(fmt_output_t format, struct sid_buf *buf, int level, const char *array_name, bool with_comma)
{
	int r = 0;

	if (!array_name || !buf)
		return -EINVAL;

	if (format == FMT_JSON) {
		r = _print_fmt(buf, "%s\n", with_comma ? "," : "");
		if (!r)
			r = _print_indent(buf, level);
		if (!r)
			r = _print_fmt(buf, "\"%s\": %s", array_name, JSON_START_ARRAY);
	} else if (format == FMT_ENV) {
		r = _print_fmt(buf, "%s=\"", array_name);
	} else if (format == FMT_TABLE)
		r = _print_fmt(buf, "%s:\n", array_name);

	return r;
}

int fmt_arr_end(fmt_output_t format, struct sid_buf *buf, int level)
{
	int r = 0;

	if (!buf)
		return -EINVAL;

	if (format == FMT_JSON) {
		r = _print_fmt(buf, "\n");
		if (!r)
			r = _print_indent(buf, level);
		if (!r)
			r = _print_fmt(buf, JSON_END_ARRAY);
	} else if (format == FMT_ENV) {
		r = _print_fmt(buf, "\"\n");
	}

	return r;
}

int fmt_elm_start(fmt_output_t format, struct sid_buf *buf, int level, bool with_comma)
{
	int r = 0;

	if (!buf)
		return -EINVAL;

	if (format == FMT_JSON) {
		r = _print_fmt(buf, "%s\n", with_comma ? "," : "");
		if (!r)
			r = _print_indent(buf, level);
		if (!r)
			r = _print_fmt(buf, JSON_START_ELEM);
	} else if (format == FMT_TABLE && with_comma)
		r = _print_fmt(buf, "\n");

	return r;
}

int fmt_elm_end(fmt_output_t format, struct sid_buf *buf, int level)
{
	int r = 0;

	if (!buf)
		return -EINVAL;

	if (format == FMT_JSON) {
		r = _print_fmt(buf, "\n");
		if (!r)
			r = _print_indent(buf, level);
		if (!r)
			r = _print_fmt(buf, JSON_END_ELEM);
	}

	return r;
}

int fmt_elm_name(fmt_output_t format, struct sid_buf *buf, int level, const char *elem_name, bool with_comma)
{
	int r = 0;

	if (!elem_name || !buf)
		return -EINVAL;

	if (format == FMT_JSON) {
		r = _print_fmt(buf, "%s\n", with_comma ? "," : "");
		if (!r)
			r = _print_indent(buf, level);
		if (!r)
			r = _print_fmt(buf, "\"%s\":\n", elem_name);
	} else if (format == FMT_TABLE)
		r = _print_fmt(buf, "%s%s:\n", with_comma ? "\n" : "", elem_name);

	return r;
}

int fmt_fld_str(fmt_output_t format, struct sid_buf *buf, int level, const char *field_name, const char *value, bool with_comma)
{
	int r = 0;

	if (!field_name || !value || !buf)
		return -EINVAL;

	if (format == FMT_JSON) {
		r = _print_fmt(buf, "%s\n", with_comma ? "," : "");
		if (!r)
			r = _print_indent(buf, level);
		if (!r)
			r = _print_fmt(buf, "\"%s\": \"%s\"", field_name, value);
	} else
		r = _print_fmt(buf, "%s%s%s\n", field_name, JOIN_STR(format), value);

	return r;
}

int fmt_fld_bin(fmt_output_t    format,
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

	if (format == FMT_JSON) {
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

int fmt_fld_uint(fmt_output_t format, struct sid_buf *buf, int level, const char *field_name, uint value, bool with_comma)
{
	int r = 0;

	if (!field_name || !buf)
		return -EINVAL;

	if (format == FMT_JSON) {
		r = _print_fmt(buf, "%s\n", with_comma ? "," : "");
		if (!r)
			r = _print_indent(buf, level);
		if (!r)
			r = _print_fmt(buf, "\"%s\": %u", field_name, value);
	} else
		r = _print_fmt(buf, "%s%s%u\n", field_name, JOIN_STR(format), value);

	return r;
}

int fmt_fld_uint64(fmt_output_t format, struct sid_buf *buf, int level, const char *field_name, uint64_t value, bool with_comma)
{
	int r = 0;

	if (!field_name || !buf)
		return -EINVAL;

	if (format == FMT_JSON) {
		r = _print_fmt(buf, "%s\n", with_comma ? "," : "");
		if (!r)
			r = _print_indent(buf, level);
		if (!r)
			r = _print_fmt(buf, "\"%s\": %" PRIu64, field_name, value);
	} else
		r = _print_fmt(buf, "%s%s%" PRIu64 "\n", field_name, JOIN_STR(format), value);

	return r;
}

int fmt_fld_int64(fmt_output_t format, struct sid_buf *buf, int level, const char *field_name, int64_t value, bool with_comma)
{
	int r = 0;

	if (!field_name || !buf)
		return -EINVAL;

	if (format == FMT_JSON) {
		r = _print_fmt(buf, "%s\n", with_comma ? "," : "");
		if (!r)
			r = _print_indent(buf, level);
		if (!r)
			r = _print_fmt(buf, "\"%s\": %" PRIi64, field_name, value);
	} else
		r = _print_fmt(buf, "%s%s%" PRIi64 "\n", field_name, JOIN_STR(format), value);

	return r;
}

int fmt_fld_bool(fmt_output_t format, struct sid_buf *buf, int level, const char *field_name, bool value, bool with_comma)
{
	int r = 0;

	if (!field_name || !buf)
		return -EINVAL;

	if (format == FMT_JSON) {
		r = _print_fmt(buf, "%s\n", with_comma ? "," : "");
		if (!r)
			r = _print_indent(buf, level);
		if (!r)
			r = _print_fmt(buf, "{\"%s\": %s}", field_name, value ? "true" : "false");
	} else if (format == FMT_ENV) {
		r = _print_fmt(buf, "%s=%d\n", field_name, value);
	} else if (value)
		r = _print_fmt(buf, "%s\n", field_name);

	return r;
}

int fmt_arr_fld_uint(fmt_output_t format, struct sid_buf *buf, int level, uint value, bool with_comma)
{
	int r = 0;

	if (!buf)
		return -EINVAL;

	if (format == FMT_JSON) {
		r = _print_fmt(buf, "%s\n", with_comma ? "," : "");
		if (!r)
			r = _print_indent(buf, level);
		if (!r)
			r = _print_fmt(buf, "%u", value);
	} else if (format == FMT_TABLE)
		r = _print_fmt(buf, "%u\n", value);

	return r;
}

int fmt_arr_fld_str(fmt_output_t format, struct sid_buf *buf, int level, const char *value, bool with_comma)
{
	int r = 0;

	if (!buf || !value)
		return -EINVAL;

	if (format == FMT_JSON) {
		r = _print_fmt(buf, "%s\n", with_comma ? "," : "");
		if (!r)
			r = _print_indent(buf, level);
		if (!r)
			r = _print_fmt(buf, "\"%s\"", value);
	} else if (format == FMT_ENV) {
		r = _print_fmt(buf, "%s%s", with_comma ? "," : "", value);
	} else if (format == FMT_TABLE)
		r = _print_fmt(buf, "%s\n", value);

	return r;
}

int fmt_arr_fld_bin(fmt_output_t format, struct sid_buf *buf, int level, const char *value, size_t len, bool with_comma)
{
	int r = 0;

	if (!buf || !value)
		return -EINVAL;

	if (format == FMT_JSON) {
		r = _print_fmt(buf, "%s\n", with_comma ? "," : "");
		if (!r)
			r = _print_indent(buf, level);
		if (!r)
			r = _print_fmt(buf, "\"");
		if (!r)
			r = _print_binary((const unsigned char *) value, len, buf);
		if (!r)
			r = _print_fmt(buf, "\"");
	} else if (format == FMT_TABLE) {
		r = _print_binary((const unsigned char *) value, len, buf);
		if (!r)
			r = _print_fmt(buf, "\n");
	}

	return r;
}

int fmt_null_byte(struct sid_buf *buf)
{
	return sid_buf_add_fmt(buf, NULL, NULL, "");
}
