/*
 * This file is part of SID.
 *
 * Copyright (C) 2020 Red Hat, Inc. All rights reserved.
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

#include "base/common.h"

#include "base/buffer.h"
#include "base/util.h"
#include "iface/usid.h"
#include "log/log.h"
#include "resource/ucmd-module.h"

#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#define LOG_PREFIX "sidctl"

#define KEY_SIDCTL_PROTOCOL "SIDCTL_PROTOCOL"
#define KEY_SIDCTL_MAJOR    "SIDCTL_MAJOR"
#define KEY_SIDCTL_MINOR    "SIDCTL_MINOR"
#define KEY_SIDCTL_RELEASE  "SIDCTL_RELEASE"

#define KEY_SID_PROTOCOL "SID_PROTOCOL"
#define KEY_SID_MAJOR    "SID_MAJOR"
#define KEY_SID_MINOR    "SID_MINOR"
#define KEY_SID_RELEASE  "SID_RELEASE"

#define PRINT_JSON_START_ARRAY "[\n"
#define PRINT_JSON_START_ELEM  "{\n"
#define PRINT_JSON_END_MAPS    "}\n"
#define PRINT_JSON_END_ELEM    "},\n"
#define PRINT_JSON_END_LAST    "}"
#define PRINT_JSON_END_ARRAY   "]"
#define PRINT_JSON_INDENT      "    "

typedef enum
{
	TABLE,
	JSON,
} output_format_t;

struct args {
	int    argc;
	char **argv;
};

void print_indent(int level)
{
	for (int i = 0; i < level; i++) {
		printf(PRINT_JSON_INDENT);
	}
}

void print_start_document(output_format_t format, int level)
{
	if (format == JSON) {
		print_indent(level);
		printf(PRINT_JSON_START_ELEM);
	}
}

void print_end_document(output_format_t format, int level)
{
	if (format == JSON) {
		print_indent(level);
		printf("%s\n", PRINT_JSON_END_LAST);
	}
}

void print_start_array(char *array_name, output_format_t format, int level)
{
	if (format == JSON) {
		print_indent(level);
		printf("\"%s\": %s", array_name, PRINT_JSON_START_ARRAY);
	}
}

void print_end_array(bool needs_comma, output_format_t format, int level)
{
	if (format == JSON) {
		printf("\n");
		print_indent(level);
		printf(PRINT_JSON_END_ARRAY);
		if (needs_comma)
			printf(",\n");
		else
			printf("\n");
	}
}

void print_start_elem(bool needs_comma, output_format_t format, int level)
{
	if (format == JSON) {
		if (needs_comma)
			printf(",\n");
		print_indent(level);
		printf("%s", PRINT_JSON_START_ELEM);
	} else {
		printf("\n");
	}
}

void print_end_elem(output_format_t format, int level)
{
	if (format == JSON) {
		print_indent(level);
		printf("%s", PRINT_JSON_END_LAST);
	} else {
		printf("\n");
	}
}

void print_str_field(char *field_name, char *value, output_format_t format, bool trailing_comma, int level)
{
	if (format == JSON) {
		print_indent(level);
		printf("\"%s\": ", field_name);
		printf("\"%s\"", value);
		if (trailing_comma)
			printf(",");
		printf("\n");
	} else {
		printf("%s", field_name);
		printf("%s", ": ");
		printf("%s", value);
		printf("%s", "\n");
	}
}

void print_uint_field(char *field_name, uint value, output_format_t format, bool trailing_comma, int level)
{
	if (format == JSON) {
		print_indent(level);
		printf("\"%s\": ", field_name);
		printf("%u", value);
		if (trailing_comma)
			printf(",");
		printf("\n");
	} else {
		printf("%s", field_name);
		printf("%s", ": ");
		printf("%u", value);
		printf("%s", "\n");
	}
}

void print_int64_field(char *field_name, uint64_t value, output_format_t format, bool trailing_comma, int level)
{
	if (format == JSON) {
		print_indent(level);
		printf("\"%s\": ", field_name);
		printf("%" PRIu64, value);
		if (trailing_comma)
			printf(",");
		printf("\n");
	} else {
		printf("%s", field_name);
		printf("%s", ": ");
		printf("%" PRIu64, value);
		printf("%s", "\n");
	}
}

void print_bool_array_elem(char *field_name, bool value, output_format_t format, bool trailing_comma, int level)
{
	if (format == JSON) {
		print_indent(level);
		printf("{\"%s\": %s}", field_name, value ? "true" : "false");
		if (trailing_comma)
			printf(",\n");
	} else {
		if (value) {
			printf("%s", field_name);
			printf("\n");
		}
	}
}

void print_uint_array_elem(uint value, output_format_t format, bool trailing_comma, int level)
{
	if (format == JSON) {
		print_indent(level);
		printf("%u", value);
		if (trailing_comma)
			printf(",\n");
	} else {
		printf("%u", value);
	}
}

void print_str_array_elem(char *value, output_format_t format, bool trailing_comma, int level)
{
	if (format == JSON) {
		print_indent(level);
		printf("\"%s\"", value);
		if (trailing_comma)
			printf(",\n");
	} else {
		printf("%s", value);
		printf("\n");
	}
}

static int _usid_cmd_dump(struct args *args, output_format_t format)
{
	struct buffer *         buf = NULL;
	char *                  data, *ptr;
	size_t                  size;
	struct usid_msg_header *msg;
	struct usid_dump_header hdr;
	int                     r;
	unsigned int            i = 0, j;
	uint32_t                len;
	bool                    needs_comma = false;

	if ((r = usid_req(LOG_PREFIX, USID_CMD_DUMP, 0, NULL, NULL, &buf)) == 0) {
		buffer_get_data(buf, (const void **) &msg, &size);
		if (size < USID_MSG_HEADER_SIZE || msg->status & COMMAND_STATUS_FAILURE) {
			buffer_destroy(buf);
			return -1;
		}
		size -= USID_MSG_HEADER_SIZE;
		ptr = data = msg->data;
		print_start_document(format, 0);
		print_start_array("siddb", format, 1);
		while (ptr < data + size) {
			memcpy(&hdr, ptr, sizeof(hdr));
			if (hdr.data_count == 0) { /* check for dummy entry */
				break;
			}
			print_start_elem(needs_comma, format, 2);
			ptr += sizeof(hdr);
			memcpy(&len, ptr, sizeof(len)); /* get key */
			ptr += sizeof(len);
			print_uint_field("RECORD", i, format, true, 3);
			print_str_field("key", ptr, format, true, 3);

			ptr += len;
			memcpy(&len, ptr, sizeof(len)); /* get owner */
			ptr += sizeof(len);

			print_uint_field("seqnum", hdr.seqnum, format, true, 3);
			print_start_array("flags", format, 3);
			print_bool_array_elem("KV_PERSISTENT", hdr.flags & KV_PERSISTENT, format, true, 4);
			print_bool_array_elem("KV_MOD_PROTECTED", hdr.flags & KV_MOD_PROTECTED, format, true, 4);
			print_bool_array_elem("KV_MOD_PRIVATE", hdr.flags & KV_MOD_PRIVATE, format, true, 4);
			print_bool_array_elem("KV_MOD_RESERVED", hdr.flags & KV_MOD_RESERVED, format, false, 4);
			print_end_array(true, format, 3);
			print_str_field("owner", ptr, format, true, 3);

			ptr += len;
			print_start_array("values", format, 3);
			if (hdr.data_count == 1) {
				memcpy(&len, ptr, sizeof(len));
				ptr += sizeof(len);
				if (len == 0)
					print_str_array_elem("", format, false, 4);
				else
					print_str_array_elem(ptr, format, false, 4);
				ptr += len;
			} else {
				for (j = 0; j < hdr.data_count; j++) {
					memcpy(&len, ptr, sizeof(len));
					ptr += sizeof(len);
					if (len == 0)
						print_uint_array_elem(j, format, j + 1 < hdr.data_count, 4);
					else
						print_str_array_elem(ptr, format, j + 1 < hdr.data_count, 4);
					ptr += len;
				}
			}
			print_end_array(false, format, 3);
			i++;
			print_end_elem(format, 2);
			needs_comma = true;
		}
		print_end_array(false, format, 1);
		print_end_document(format, 0);
		buffer_destroy(buf);
	}
	return r;
}

static int _usid_cmd_version(struct args *args, output_format_t format)
{
	struct buffer *         buf = NULL;
	struct usid_msg_header *hdr;
	size_t                  size;
	struct usid_version *   vsn = NULL;
	int                     r;
	r = usid_req(LOG_PREFIX, USID_CMD_VERSION, 0, NULL, NULL, &buf);

	print_start_document(format, 0);

	print_uint_field("KEY_SIDCTL_PROTOCOL", USID_PROTOCOL, format, true, 1);
	print_uint_field("KEY_SIDCTL_MAJOR", SID_VERSION_MAJOR, format, true, 1);
	print_uint_field("KEY_SIDCTL_MINOR", SID_VERSION_MINOR, format, true, 1);
	print_uint_field("KEY_SIDCTL_RELEASE", SID_VERSION_RELEASE, format, r == 0, 1);

	if (r == 0) {
		buffer_get_data(buf, (const void **) &hdr, &size);

		if (size >= (USID_MSG_HEADER_SIZE + USID_VERSION_SIZE)) {
			vsn = (struct usid_version *) hdr->data;
			print_uint_field("KEY_SID_PROTOCOL", hdr->prot, format, true, 1);
			print_uint_field("KEY_SID_MAJOR", vsn->major, format, true, 1);
			print_uint_field("KEY_SID_MINOR", vsn->minor, format, true, 1);
			print_uint_field("KEY_SID_RELEASE", vsn->release, format, false, 1);
		}

		buffer_destroy(buf);
	}
	print_end_document(format, 0);
	return r;
}

static void _help(FILE *f)
{
	fprintf(f,
	        "Usage: sidctl [-h|--help] [-v|--verbose] [-V|--version] [-f|--format json] [command]\n"
	        "\n"
	        "Control and Query the SID daemon.\n"
	        "\n"
	        "Global options:\n"
	        "    -f|--format json  Show the output in JSON.\n"
	        "    -h|--help         Show this help information.\n"
	        "    -v|--verbose      Verbose mode, repeat to increase level.\n"
	        "    -V|--version      Show USID version.\n"
	        "\n"
	        "Commands and arguments:\n"
	        "\n"
	        "    version\n"
	        "      Get SIDCTL and SID daemon version.\n"
	        "      Input:  None.\n"
	        "      Output: USID_PROTOCOL/MAJOR/MINOR/RELEASE for USID version.\n"
	        "              SID_PROTOCOL/MAJOR/MINOR/RELEASE for SID version.\n"
	        "\n"
	        "    dump\n"
	        "      Dump the SID daemon database.\n"
	        "      Input:  None.\n"
	        "      Output: Listing of all database entries.\n"
	        "\n");
}

static void _version(FILE *f)
{
	fprintf(f, PACKAGE_STRING "\n");
	fprintf(f, "Configuration line: %s\n", SID_CONFIGURE_LINE);
	fprintf(f, "Compiled by: %s on %s with %s\n", SID_COMPILED_BY, SID_COMPILATION_HOST, SID_COMPILER);
}

int main(int argc, char *argv[])
{
	int             opt;
	int             verbose = 0;
	struct args     subcmd_args;
	int             r      = -1;
	output_format_t format = TABLE;

	struct option longopts[] = {
		{"format", required_argument, NULL, 'f'},
		{"help", no_argument, NULL, 'h'},
		{"verbose", no_argument, NULL, 'v'},
		{"version", no_argument, NULL, 'V'},
		{NULL, no_argument, NULL, 0},
	};

	while ((opt = getopt_long(argc, argv, "f:hvV", longopts, NULL)) != EOF) {
		switch (opt) {
			case 'h':
				_help(stdout);
				return EXIT_SUCCESS;
			case 'f':
				if (optarg == NULL || strcmp("json", optarg) != 0) {
					_help(stderr);
					return EXIT_FAILURE;
				}
				format = JSON;
				break;
			case 'v':
				verbose++;
				break;
			case 'V':
				_version(stdout);
				return EXIT_SUCCESS;
			default:
				_help(stderr);
				return EXIT_FAILURE;
		}
	}

	if (optind >= argc) {
		_help(stderr);
		return EXIT_FAILURE;
	}

	log_init(LOG_TARGET_STANDARD, verbose);

	subcmd_args.argc = argc - optind;
	subcmd_args.argv = &argv[optind];

	switch (usid_cmd_name_to_type(subcmd_args.argv[0])) {
		case USID_CMD_VERSION:
			r = _usid_cmd_version(&subcmd_args, format);
			break;
		case USID_CMD_DUMP:
			r = _usid_cmd_dump(&subcmd_args, format);
			break;
		default:
			_help(stderr);
	}

	return (r < 0) ? EXIT_FAILURE : EXIT_SUCCESS;
}
