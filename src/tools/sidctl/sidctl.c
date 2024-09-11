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

#include "base/buf.h"
#include "iface/ifc.h"
#include "internal/fmt.h"
#include "log/log.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define LOG_PREFIX           "sidctl"

#define KEY_SIDCTL_PROTOCOL  "SIDCTL_PROTOCOL"
#define KEY_SIDCTL_MAJOR     "SIDCTL_MAJOR"
#define KEY_SIDCTL_MINOR     "SIDCTL_MINOR"
#define KEY_SIDCTL_RELEASE   "SIDCTL_RELEASE"

#define KEY_SID_IFC_PROTOCOL "SID_IFC_PROTOCOL"
#define KEY_SID_MAJOR        "SID_MAJOR"
#define KEY_SID_MINOR        "SID_MINOR"
#define KEY_SID_RELEASE      "SID_RELEASE"

static int _sid_cmd(sid_ifc_cmd_t cmd, uint16_t format)
{
	struct sid_ifc_rsl *rsl = NULL;
	const char         *data;
	size_t              size;
	int                 r;
	struct sid_ifc_req  req = {.cmd = cmd, .flags = format};

	if ((r = sid_ifc_req(&req, &rsl)) < 0) {
		sid_log_error_errno(LOG_PREFIX, r, "Command request failed");
		return -1;
	}

	if ((data = sid_ifc_rsl_get_data(rsl, &size)) != NULL)
		printf("%s", data);
	else {
		uint64_t status;
		if (sid_ifc_rsl_get_status(rsl, &status) != 0 || status & SID_IFC_CMD_STATUS_FAILURE) {
			sid_log_error(LOG_PREFIX, "Command failed");
			r = -1;
		}
	}

	sid_ifc_rsl_free(rsl);
	return r;
}

static int _sid_cmd_version(uint16_t format)
{
	struct sid_buf *outbuf = NULL;
	int             r;

	outbuf = sid_buf_create(&((struct sid_buf_spec) {.backend = SID_BUF_BACKEND_MALLOC,
	                                                 .type    = SID_BUF_TYPE_LINEAR,
	                                                 .mode    = SID_BUF_MODE_PLAIN}),
	                        &((struct sid_buf_init) {.size = 4096, .alloc_step = 1, .limit = 0}),
	                        NULL);
	if (!outbuf)
		return -1;

	fmt_doc_start(format, outbuf, 0);

	fmt_elm_name(format, outbuf, 0, "SIDCTL_VERSION", false);
	fmt_elm_start(format, outbuf, 0, false);
	fmt_fld_uint(format, outbuf, 1, KEY_SIDCTL_PROTOCOL, SID_IFC_PROTOCOL, false);
	fmt_fld_uint(format, outbuf, 1, KEY_SIDCTL_MAJOR, SID_VERSION_MAJOR, true);
	fmt_fld_uint(format, outbuf, 1, KEY_SIDCTL_MINOR, SID_VERSION_MINOR, true);
	fmt_fld_uint(format, outbuf, 1, KEY_SIDCTL_RELEASE, SID_VERSION_RELEASE, true);
	fmt_elm_end(format, outbuf, 0);
	fmt_elm_name(format, outbuf, 0, "SID_VERSION", true);
	if ((r = sid_buf_write_all(outbuf, fileno(stdout))) < 0)
		sid_log_error_errno(LOG_PREFIX, r, "failed to write version information");
	sid_buf_reset(outbuf);
	if (_sid_cmd(SID_IFC_CMD_VERSION, format) < 0) {
		fmt_doc_start(format, outbuf, 0);
		fmt_doc_end(format, outbuf, 0);
	} else
		fflush(stdout);
	fmt_doc_end(format, outbuf, 0);

	if ((r = sid_buf_write_all(outbuf, fileno(stdout))) < 0)
		sid_log_error_errno(LOG_PREFIX, r, "failed to write output ending");
	sid_buf_destroy(outbuf);
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
	        "    -f|--format env|json|table  Show the output in specified format.\n"
	        "    -h|--help                   Show this help information.\n"
	        "    -v|--verbose                Verbose mode, repeat to increase level.\n"
	        "    -V|--version                Show SIDCTL version.\n"
	        "\n"
	        "Commands and arguments:\n"
	        "\n"
	        "    version\n"
	        "      Get SIDCTL and SID daemon version.\n"
	        "      Input:  None.\n"
	        "      Output: SID_IFC_PROTOCOL/MAJOR/MINOR/RELEASE for SIDCTL version.\n"
	        "              SID_IFC_PROTOCOL/MAJOR/MINOR/RELEASE for SID version.\n"
	        "\n"
	        "    dbdump\n"
	        "      Dump the SID daemon database.\n"
	        "      Input:  None.\n"
	        "      Output: Listing of all database entries.\n"
	        "\n"
	        "    dbstats\n"
	        "      Show stats for the SID daemon database.\n"
	        "      Input:  None.\n"
	        "      Output: Database statistics.\n"
	        "\n"
	        "    devices\n"
	        "      List devices with basic set of properties.\n"
	        "      Input:  None.\n"
	        "      Output: Listing of all known devices and their basic properties.\n"
	        "\n"
	        "    resources\n"
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
		return SID_IFC_CMD_FL_FMT_JSON;
	if (!strcasecmp(format, "env"))
		return SID_IFC_CMD_FL_FMT_ENV;
	if (!strcasecmp(format, "table"))
		return SID_IFC_CMD_FL_FMT_TABLE;
	return -1;
}

int main(int argc, char *argv[])
{
	int           opt;
	int           verbose = 0;
	int           r       = -1;
	int           format  = SID_IFC_CMD_FL_FMT_TABLE;
	sid_ifc_cmd_t cmd;

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

	sid_log_init(SID_LOG_TGT_STANDARD, verbose);

	switch ((cmd = sid_ifc_cmd_name_to_type(argv[optind]))) {
		case SID_IFC_CMD_VERSION:
			r = _sid_cmd_version(format);
			break;
		case SID_IFC_CMD_DBDUMP:
		case SID_IFC_CMD_DBSTATS:
		case SID_IFC_CMD_RESOURCES:
		case SID_IFC_CMD_DEVICES:
			r = _sid_cmd(cmd, format);
			break;
		default:
			_help(stderr);
	}
	return (r < 0) ? EXIT_FAILURE : EXIT_SUCCESS;
}
