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
#include "iface/iface.h"
#include "log/log.h"
#include "resource/ucmd-module.h"

#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define LOG_PREFIX "sidctl"

#define KEY_SIDCTL_PROTOCOL "SIDCTL_PROTOCOL"
#define KEY_SIDCTL_MAJOR    "SIDCTL_MAJOR"
#define KEY_SIDCTL_MINOR    "SIDCTL_MINOR"
#define KEY_SIDCTL_RELEASE  "SIDCTL_RELEASE"

#define KEY_SID_PROTOCOL "SID_PROTOCOL"
#define KEY_SID_MAJOR    "SID_MAJOR"
#define KEY_SID_MINOR    "SID_MINOR"
#define KEY_SID_RELEASE  "SID_RELEASE"

static int _sid_cmd(sid_cmd_t cmd, uint16_t format)
{
	struct sid_result *res = NULL;
	const char *       data;
	size_t             size;
	int                r;
	struct sid_request req = {.cmd = cmd, .flags = format};

	if ((r = sid_req(&req, &res)) == 0) {
		if ((data = sid_result_data(res, &size)) != NULL)
			printf("%s", data);
		else {
			uint64_t status;
			if (sid_result_status(res, &status) != 0 || status & SID_CMD_STATUS_FAILURE) {
				log_error(LOG_PREFIX, "Command failed");
				r = -1;
			}
		}
		sid_result_free(res);
		return r;
	}
	log_error_errno(LOG_PREFIX, r, "Command request failed");
	return -1;
}

static int _sid_cmd_version(uint16_t format)
{
	struct buffer *outbuf = NULL;
	int            r;

	outbuf = sid_buffer_create(
		&((struct buffer_spec) {.backend = BUFFER_BACKEND_MALLOC, .type = BUFFER_TYPE_LINEAR, .mode = BUFFER_MODE_PLAIN}),
		&((struct buffer_init) {.size = 4096, .alloc_step = 1, .limit = 0}),
		NULL);
	if (!outbuf)
		return -1;

	print_start_document(format, outbuf, 0);

	print_elem_name(false, "SIDCTL_VERSION", format, outbuf, 0);
	print_start_elem(false, format, outbuf, 0);
	print_uint_field(KEY_SIDCTL_PROTOCOL, SID_PROTOCOL, format, outbuf, true, 1);
	print_uint_field(KEY_SIDCTL_MAJOR, SID_VERSION_MAJOR, format, outbuf, true, 1);
	print_uint_field(KEY_SIDCTL_MINOR, SID_VERSION_MINOR, format, outbuf, true, 1);
	print_uint_field(KEY_SIDCTL_RELEASE, SID_VERSION_RELEASE, format, outbuf, 0, 1);
	print_end_elem(format, outbuf, 0);
	print_elem_name(true, "SID_VERSION", format, outbuf, 0);
	if ((r = sid_buffer_write_all(outbuf, fileno(stdout))) < 0)
		log_error_errno(LOG_PREFIX, r, "failed to write version information");
	sid_buffer_reset(outbuf);
	if ((r = _sid_cmd(SID_CMD_VERSION, format)) < 0) {
		print_start_document(format, outbuf, 0);
		print_end_document(format, outbuf, 0);
	} else
		fflush(stdout);
	print_end_document(format, outbuf, 0);

	if ((r = sid_buffer_write_all(outbuf, fileno(stdout))) < 0)
		log_error_errno(LOG_PREFIX, r, "failed to write output ending");
	sid_buffer_destroy(outbuf);
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
	        "    -V|--version      Show SIDCTL version.\n"
	        "\n"
	        "Commands and arguments:\n"
	        "\n"
	        "    version\n"
	        "      Get SIDCTL and SID daemon version.\n"
	        "      Input:  None.\n"
	        "      Output: SID_PROTOCOL/MAJOR/MINOR/RELEASE for SIDCTL version.\n"
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

static int _get_format(char *format)
{
	if (format == NULL)
		return -1;
	if (!strcasecmp(format, "json"))
		return SID_CMD_FLAGS_FMT_JSON;
	if (!strcasecmp(format, "env"))
		return SID_CMD_FLAGS_FMT_ENV;
	if (!strcasecmp(format, "table"))
		return SID_CMD_FLAGS_FMT_TABLE;
	return -1;
}

int main(int argc, char *argv[])
{
	int       opt;
	int       verbose = 0;
	int       r       = -1;
	int       format  = SID_CMD_FLAGS_FMT_TABLE;
	sid_cmd_t cmd;

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
				if ((format = _get_format(optarg)) < 0) {
					_help(stderr);
					return EXIT_FAILURE;
				}
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

	if (optind != argc - 1) {
		_help(stderr);
		return EXIT_FAILURE;
	}

	log_init(LOG_TARGET_STANDARD, verbose);

	switch ((cmd = sid_cmd_name_to_type(argv[optind]))) {
		case SID_CMD_VERSION:
			r = _sid_cmd_version(format);
			break;
		case SID_CMD_DUMP:
		case SID_CMD_TREE:
		case SID_CMD_STATS:
			r = _sid_cmd(cmd, format);
			break;
		default:
			_help(stderr);
	}
	return (r < 0) ? EXIT_FAILURE : EXIT_SUCCESS;
}
