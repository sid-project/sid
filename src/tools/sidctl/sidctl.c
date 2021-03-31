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
#include "base/formatter.h"
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

struct args {
	int    argc;
	char **argv;
};

static int _usid_cmd_tree(struct args *args, output_format_t format, struct buffer *outbuf)
{
	struct buffer *         readbuf = NULL;
	size_t                  size;
	struct usid_msg_header *msg;
	int                     r;

	if ((r = usid_req(LOG_PREFIX, USID_CMD_TREE, 0, NULL, NULL, &readbuf)) == 0) {
		buffer_get_data(readbuf, (const void **) &msg, &size);
		if (size < USID_MSG_HEADER_SIZE || msg->status & COMMAND_STATUS_FAILURE) {
			buffer_destroy(readbuf);
			return -1;
		}
		size -= USID_MSG_HEADER_SIZE;
		buffer_add(outbuf, msg->data, size, &r);
		buffer_destroy(readbuf);
		return r;
	}
	return -1;
}

static int _usid_cmd_dump(struct args *args, output_format_t format, struct buffer *outbuf)
{
	struct buffer *         readbuf = NULL;
	char *                  data, *ptr;
	size_t                  size;
	struct usid_msg_header *msg;
	struct usid_dump_header hdr;
	int                     r;
	unsigned int            i = 0, j;
	uint32_t                len;
	bool                    needs_comma = false;

	if ((r = usid_req(LOG_PREFIX, USID_CMD_DUMP, 0, NULL, NULL, &readbuf)) == 0) {
		buffer_get_data(readbuf, (const void **) &msg, &size);
		if (size < USID_MSG_HEADER_SIZE || msg->status & COMMAND_STATUS_FAILURE) {
			buffer_destroy(readbuf);
			return -1;
		}
		size -= USID_MSG_HEADER_SIZE;
		ptr = data = msg->data;
		print_start_document(format, outbuf, 0);
		print_start_array("siddb", format, outbuf, 1);
		while (ptr < data + size) {
			memcpy(&hdr, ptr, sizeof(hdr));
			if (hdr.data_count == 0) { /* check for dummy entry */
				break;
			}
			print_start_elem(needs_comma, format, outbuf, 2);
			ptr += sizeof(hdr);
			memcpy(&len, ptr, sizeof(len)); /* get key */
			ptr += sizeof(len);
			print_uint_field("RECORD", i, format, outbuf, true, 3);
			print_str_field("key", ptr, format, outbuf, true, 3);

			ptr += len;
			memcpy(&len, ptr, sizeof(len)); /* get owner */
			ptr += sizeof(len);

			print_uint_field("seqnum", hdr.seqnum, format, outbuf, true, 3);
			print_start_array("flags", format, outbuf, 3);
			print_bool_array_elem("KV_PERSISTENT", hdr.flags & KV_PERSISTENT, format, outbuf, true, 4);
			print_bool_array_elem("KV_MOD_PROTECTED", hdr.flags & KV_MOD_PROTECTED, format, outbuf, true, 4);
			print_bool_array_elem("KV_MOD_PRIVATE", hdr.flags & KV_MOD_PRIVATE, format, outbuf, true, 4);
			print_bool_array_elem("KV_MOD_RESERVED", hdr.flags & KV_MOD_RESERVED, format, outbuf, false, 4);
			print_end_array(true, format, outbuf, 3);
			print_str_field("owner", ptr, format, outbuf, true, 3);

			ptr += len;
			print_start_array("values", format, outbuf, 3);
			if (hdr.data_count == 1) {
				memcpy(&len, ptr, sizeof(len));
				ptr += sizeof(len);
				if (len == 0)
					print_str_array_elem("", format, outbuf, false, 4);
				else
					print_str_array_elem(ptr, format, outbuf, false, 4);
				ptr += len;
			} else {
				for (j = 0; j < hdr.data_count; j++) {
					memcpy(&len, ptr, sizeof(len));
					ptr += sizeof(len);
					if (len == 0)
						print_uint_array_elem(j, format, outbuf, j + 1 < hdr.data_count, 4);
					else
						print_str_array_elem(ptr, format, outbuf, j + 1 < hdr.data_count, 4);
					ptr += len;
				}
			}
			print_end_array(false, format, outbuf, 3);
			i++;
			print_end_elem(format, outbuf, 2);
			needs_comma = true;
		}
		print_end_array(false, format, outbuf, 1);
		print_end_document(format, outbuf, 0);
		buffer_destroy(readbuf);
	}
	return r;
}

static int _usid_cmd_stats(struct args *args, output_format_t format, struct buffer *outbuf)
{
	struct buffer *         buf = NULL;
	struct usid_msg_header *hdr;
	size_t                  size;
	struct usid_stats *     stats = NULL;
	int                     r;

	if ((r = usid_req(LOG_PREFIX, USID_CMD_STATS, 0, NULL, NULL, &buf)) == 0) {
		buffer_get_data(buf, (const void **) &hdr, &size);

		if (size >= (USID_MSG_HEADER_SIZE + USID_STATS_SIZE) &&
		    (hdr->status & COMMAND_STATUS_MASK_OVERALL) == COMMAND_STATUS_SUCCESS) {
			stats = (struct usid_stats *) hdr->data;
			print_start_document(format, outbuf, 0);
			print_uint64_field("KEYS_SIZE", stats->key_size, format, outbuf, true, 1);
			print_uint64_field("VALUES_INTERNAL_SIZE", stats->value_int_size, format, outbuf, true, 1);
			print_uint64_field("VALUES_INTERNAL_DATA_SIZE", stats->value_int_data_size, format, outbuf, true, 1);
			print_uint64_field("VALUES_EXTERNAL_SIZE", stats->value_ext_size, format, outbuf, true, 1);
			print_uint64_field("VALUES_EXTERNAL_DATA_SIZE", stats->value_ext_data_size, format, outbuf, true, 1);
			print_uint64_field("METADATA_SIZE", stats->meta_size, format, outbuf, true, 1);
			print_uint_field("NR_KEY_VALUE_PAIRS", stats->nr_kv_pairs, format, outbuf, true, 1);
			print_end_document(format, outbuf, 0);
		} else
			r = -1;

		buffer_destroy(buf);
	}
	return r;
}

static int _usid_cmd_version(struct args *args, output_format_t format, struct buffer *outbuf)
{
	struct buffer *         readbuf = NULL;
	struct usid_msg_header *hdr;
	size_t                  size;
	struct usid_version *   vsn = NULL;
	int                     r;
	r = usid_req(LOG_PREFIX, USID_CMD_VERSION, 0, NULL, NULL, &readbuf);

	print_start_document(format, outbuf, 0);

	print_uint_field(KEY_SIDCTL_PROTOCOL, USID_PROTOCOL, format, outbuf, true, 1);
	print_uint_field(KEY_SIDCTL_MAJOR, SID_VERSION_MAJOR, format, outbuf, true, 1);
	print_uint_field(KEY_SIDCTL_MINOR, SID_VERSION_MINOR, format, outbuf, true, 1);
	print_uint_field(KEY_SIDCTL_RELEASE, SID_VERSION_RELEASE, format, outbuf, r == 0, 1);

	if (r == 0) {
		buffer_get_data(readbuf, (const void **) &hdr, &size);

		if (size >= (USID_MSG_HEADER_SIZE + USID_VERSION_SIZE)) {
			vsn = (struct usid_version *) hdr->data;
			print_uint_field(KEY_SID_PROTOCOL, hdr->prot, format, outbuf, true, 1);
			print_uint_field(KEY_SID_MAJOR, vsn->major, format, outbuf, true, 1);
			print_uint_field(KEY_SID_MINOR, vsn->minor, format, outbuf, true, 1);
			print_uint_field(KEY_SID_RELEASE, vsn->release, format, outbuf, false, 1);
		}

		buffer_destroy(readbuf);
	}
	print_end_document(format, outbuf, 0);
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
	        "\n"
	        "    stats\n"
	        "      Show stats for the SID daemon key value store.\n"
	        "      Input:  None.\n"
	        "      Output: Key value store stats.\n"
	        "\n"
	        "    tree\n"
	        "      Show current SID resource tree.\n"
	        "      Input:  None.\n"
	        "      Output: Resource tree.\n"
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
	struct buffer * outbuf = NULL;

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

	outbuf = buffer_create(
		&((struct buffer_spec) {.backend = BUFFER_BACKEND_MALLOC, .type = BUFFER_TYPE_LINEAR, .mode = BUFFER_MODE_PLAIN}),
		&((struct buffer_init) {.size = 4096, .alloc_step = 1, .limit = 0}),
		NULL);

	switch (usid_cmd_name_to_type(subcmd_args.argv[0])) {
		case USID_CMD_VERSION:
			r = _usid_cmd_version(&subcmd_args, format, outbuf);
			break;
		case USID_CMD_DUMP:
			r = _usid_cmd_dump(&subcmd_args, format, outbuf);
			break;
		case USID_CMD_TREE:
			r = _usid_cmd_tree(&subcmd_args, format, outbuf);
			break;
		case USID_CMD_STATS:
			r = _usid_cmd_stats(&subcmd_args, format, outbuf);
			break;
		default:
			_help(stderr);
	}
	buffer_write_all(outbuf, fileno(stdout));
	buffer_destroy(outbuf);
	return (r < 0) ? EXIT_FAILURE : EXIT_SUCCESS;
}
