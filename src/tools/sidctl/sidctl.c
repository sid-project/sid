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

struct args {
	int    argc;
	char **argv;
};

static int _usid_cmd_dump(struct args *args)
{
	struct buffer *         buf = NULL;
	char *                  data, *ptr;
	size_t                  size;
	struct usid_msg_header *msg;
	struct usid_dump_header hdr;
	int                     r;
	unsigned int            i = 0, j;
	uint32_t                len;

	if ((r = usid_req(LOG_PREFIX, USID_CMD_DUMP, 0, NULL, NULL, &buf)) == 0) {
		buffer_get_data(buf, (const void **) &msg, &size);
		if (size < USID_MSG_HEADER_SIZE || msg->status & COMMAND_STATUS_FAILURE) {
			buffer_destroy(buf);
			return -1;
		}
		size -= USID_MSG_HEADER_SIZE;
		ptr = data = msg->data;

		while (ptr < data + size) {
			memcpy(&hdr, ptr, sizeof(hdr));
			if (hdr.data_count == 0) /* check for dummy entry */
				break;
			ptr += sizeof(hdr);
			memcpy(&len, ptr, sizeof(len)); /* get key */
			ptr += sizeof(len);
			printf("--- RECORD %u\n", i);
			printf("    key: %s\n", ptr);
			ptr += len;
			memcpy(&len, ptr, sizeof(len)); /* get owner */
			ptr += sizeof(len);
			printf("    seqnum: %" PRIu64 "  flags: %s%s%s%s  owner: %s\n",
			       hdr.seqnum,
			       hdr.flags & KV_PERSISTENT ? "KV_PERSISTENT " : "",
			       hdr.flags & KV_MOD_PROTECTED ? "KV_MOD_PROTECTED " : "",
			       hdr.flags & KV_MOD_PRIVATE ? "KV_MOD_PRIVATE " : "",
			       hdr.flags & KV_MOD_RESERVED ? "KV_MOD_RESERVED " : "",
			       ptr);
			ptr += len;
			if (hdr.data_count == 1) {
				memcpy(&len, ptr, sizeof(len));
				ptr += sizeof(len);
				if (len == 0)
					printf("    value:\n");
				else
					printf("    value: %s\n", ptr);
				ptr += len;
			} else {
				printf("    value: vector\n");
				for (j = 0; j < hdr.data_count; j++) {
					memcpy(&len, ptr, sizeof(len));
					ptr += sizeof(len);
					if (len == 0)
						printf("      [%u] =\n", j);
					else
						printf("      [%u] = %s\n", j, ptr);
					ptr += len;
				}
			}
			i++;
		}
		buffer_destroy(buf);
	}
	return r;
}

static int _usid_cmd_version(struct args *args)
{
	struct buffer *         buf = NULL;
	struct usid_msg_header *hdr;
	size_t                  size;
	struct usid_version *   vsn = NULL;
	int                     r;

	fprintf(stdout,
	        KEY_SIDCTL_PROTOCOL "=%" PRIu8 "\n" KEY_SIDCTL_MAJOR "=%" PRIu16 "\n" KEY_SIDCTL_MINOR "=%" PRIu16
	                            "\n" KEY_SIDCTL_RELEASE "=%" PRIu16 "\n",
	        USID_PROTOCOL,
	        SID_VERSION_MAJOR,
	        SID_VERSION_MINOR,
	        SID_VERSION_RELEASE);

	if ((r = usid_req(LOG_PREFIX, USID_CMD_VERSION, 0, NULL, NULL, &buf)) == 0) {
		buffer_get_data(buf, (const void **) &hdr, &size);

		if (size >= (USID_MSG_HEADER_SIZE + USID_VERSION_SIZE)) {
			vsn = (struct usid_version *) hdr->data;
			fprintf(stdout,
			        KEY_SID_PROTOCOL "=%" PRIu8 "\n" KEY_SID_MAJOR "=%" PRIu16 "\n" KEY_SID_MINOR "=%" PRIu16
			                         "\n" KEY_SID_RELEASE "=%" PRIu16 "\n",
			        hdr->prot,
			        vsn->major,
			        vsn->minor,
			        vsn->release);
		}

		buffer_destroy(buf);
	}

	return r;
}

static void _help(FILE *f)
{
	fprintf(f,
	        "Usage: sidctl [-h|--help] [-v|--verbose] [-V|--version] [command]\n"
	        "\n"
	        "Control and Query the SID daemon.\n"
	        "\n"
	        "Global options:\n"
	        "    -h|--help       Show this help information.\n"
	        "    -v|--verbose    Verbose mode, repeat to increase level.\n"
	        "    -V|--version    Show USID version.\n"
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
	int         opt;
	int         verbose = 0;
	struct args subcmd_args;
	int         r = -1;

	struct option longopts[] = {
		{"help", 0, NULL, 'h'},
		{"verbose", 0, NULL, 'v'},
		{"version", 0, NULL, 'V'},
		{NULL, 0, NULL, 0},
	};

	while ((opt = getopt_long(argc, argv, "hvV", longopts, NULL)) != EOF) {
		switch (opt) {
			case 'h':
				_help(stdout);
				return EXIT_SUCCESS;
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
			r = _usid_cmd_version(&subcmd_args);
			break;
		case USID_CMD_DUMP:
			r = _usid_cmd_dump(&subcmd_args);
			break;
		default:
			_help(stderr);
	}

	return (r < 0) ? EXIT_FAILURE : EXIT_SUCCESS;
}
