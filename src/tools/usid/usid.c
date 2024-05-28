/*
 * This file is part of SID.
 *
 * Copyright (C) 2019 Red Hat, Inc. All rights reserved.
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

#include "base/util.h"
#include "iface/iface.h"
#include "log/log.h"

#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysmacros.h>

#define LOG_PREFIX         "usid"

#define KEY_ENV_SEQNUM     "SEQNUM"

#define KEY_SID_UBR_STATUS "SID_UBR_STATUS"

typedef enum {
	UBR_STATUS_ERROR,
	UBR_STATUS_ACTIVE,
	UBR_STATUS_INACTIVE,
	UBR_STATUS_INCOMPATIBLE,
} ubr_status_t;

static const char *ubr_status_str[] = {
	[UBR_STATUS_ERROR]        = "error",
	[UBR_STATUS_ACTIVE]       = "active",
	[UBR_STATUS_INACTIVE]     = "inactive",
	[UBR_STATUS_INCOMPATIBLE] = "incompatible",
};

#define KEY_SID_IFC_PROTOCOL "SID_IFC_PROTOCOL"
#define KEY_SID_MAJOR        "SID_MAJOR"
#define KEY_SID_MINOR        "SID_MINOR"
#define KEY_SID_RELEASE      "SID_RELEASE"

#define KEY_SID_IFC_PROTOCOL "SID_IFC_PROTOCOL"
#define KEY_SID_MAJOR        "SID_MAJOR"
#define KEY_SID_MINOR        "SID_MINOR"
#define KEY_SID_RELEASE      "SID_RELEASE"

struct args {
	int    argc;
	char **argv;
};

static ubr_status_t _get_ubr_status(struct sid_ifc_result *res, int r)
{
	uint8_t prot;

	if (r < 0) {
		if (r == -ECONNREFUSED)
			return UBR_STATUS_INACTIVE;
		else if (r == -EBADMSG)
			return UBR_STATUS_INCOMPATIBLE;
		else
			return UBR_STATUS_ERROR;
	} else {
		if (sid_ifc_result_data_get(res, NULL) && sid_ifc_result_protocol_get(res, &prot) == 0 && prot == SID_IFC_PROTOCOL)
			return UBR_STATUS_ACTIVE;
		else
			return UBR_STATUS_INCOMPATIBLE;
	}
}

static int _usid_cmd_active(void)
{
	unsigned long long     val;
	ubr_status_t           ubr_status;
	struct sid_ifc_result *res;
	struct sid_ifc_request req = {.cmd = SID_IFC_CMD_VERSION, .flags = SID_IFC_CMD_FL_FMT_ENV};
	int                    r;

	req.seqnum = sid_util_env_ull_get(KEY_ENV_SEQNUM, 0, UINT64_MAX, &val) < 0 ? 0 : val;
	r          = sid_ifc_req(&req, &res);
	ubr_status = _get_ubr_status(res, r);
	if (r == 0)
		sid_ifc_result_free(res);
	fprintf(stdout, KEY_SID_UBR_STATUS "=%s\n", ubr_status_str[ubr_status]);

	return r;
}

static int _print_env_from_res(struct sid_ifc_result *res)
{
	size_t      size;
	const char *end, *kv;

	kv = sid_ifc_result_data_get(res, &size);
	if (!kv) {
		uint64_t status;
		if (sid_ifc_result_status_get(res, &status) < 0 || status & SID_IFC_CMD_STATUS_FAILURE) {
			sid_log_error(LOG_PREFIX, "Command failed");
			return -EBADMSG;
		}
		return 0;
	}
	for (end = kv + size; kv < end; kv += strlen(kv) + 1)
		fprintf(stdout, "%s\n", kv);

	return 0;
}

static int _usid_cmd_print_env(struct sid_ifc_request *req)
{
	unsigned long long     val;
	struct sid_ifc_result *res;
	int                    r;

	if ((r = sid_util_env_ull_get(KEY_ENV_SEQNUM, 0, UINT64_MAX, &val)) < 0) {
		sid_log_error_errno(LOG_PREFIX, r, "Failed to get value for %s key from environment", KEY_ENV_SEQNUM);
		return r;
	}
	req->seqnum = val;

	if ((r = sid_ifc_req(req, &res)) < 0)
		sid_log_error_errno(LOG_PREFIX, r, "Command request failed");
	else {
		r = _print_env_from_res(res);
		sid_ifc_result_free(res);
	}

	return r;
}

static int _usid_cmd_scan(void)
{
	struct sid_ifc_request req = {.cmd = SID_IFC_CMD_SCAN, .flags = SID_IFC_CMD_FL_FMT_ENV};

	return _usid_cmd_print_env(&req);
}

static int _usid_cmd_checkpoint(int argc, char **argv)
{
	struct sid_ifc_request req = {.cmd = SID_IFC_CMD_CHECKPOINT, .flags = SID_IFC_CMD_FL_FMT_ENV};

	if (argc < 2) {
		/* we need at least checkpoint name */
		sid_log_error(LOG_PREFIX, "Missing checkpoint name.");
		return -EINVAL;
	}
	req.data.checkpoint.name    = argv[1];
	req.data.checkpoint.nr_keys = argc - 2;
	if (argc > 2)
		req.data.checkpoint.keys = &argv[2];
	else
		req.data.checkpoint.keys = NULL;
	return _usid_cmd_print_env(&req);
}

static int _usid_cmd_version(void)
{
	unsigned long long     val;
	const char            *data;
	int                    r;
	struct sid_ifc_result *res;
	struct sid_ifc_request req = {.cmd = SID_IFC_CMD_VERSION, .flags = SID_IFC_CMD_FL_FMT_ENV};

	req.seqnum                 = sid_util_env_ull_get(KEY_ENV_SEQNUM, 0, UINT64_MAX, &val) < 0 ? 0 : val;

	fprintf(stdout,
	        KEY_SID_IFC_PROTOCOL "=%" PRIu8 "\n" KEY_SID_MAJOR "=%" PRIu16 "\n" KEY_SID_MINOR "=%" PRIu16 "\n" KEY_SID_RELEASE
	                             "=%" PRIu16 "\n",
	        SID_IFC_PROTOCOL,
	        SID_VERSION_MAJOR,
	        SID_VERSION_MINOR,
	        SID_VERSION_RELEASE);

	if ((r = sid_ifc_req(&req, &res)) < 0) {
		sid_log_error_errno(LOG_PREFIX, r, "Command request failed");
		return r;
	}

	if ((data = sid_ifc_result_data_get(res, NULL)) != NULL) {
		fprintf(stdout, "%s", data);
		r = 0;
	} else {
		uint64_t status;
		if (sid_ifc_result_status_get(res, &status) == 0 && (status & SID_IFC_CMD_STATUS_FAILURE) == 0)
			sid_log_error(LOG_PREFIX, "Missing reply data");
		else
			sid_log_error(LOG_PREFIX, "Command failed");
		r = -1;
	}

	sid_ifc_result_free(res);
	return r;
}

static int _init_usid()
{
	sigset_t sig_set;

	if (sigemptyset(&sig_set) < 0) {
		sid_log_error_errno(LOG_PREFIX, errno, "sigemptyset failed");
		goto fail;
	}

	if (sigaddset(&sig_set, SIGPIPE) < 0) {
		sid_log_error_errno(LOG_PREFIX, errno, "siggaddset failed");
		goto fail;
	}

	if (sigprocmask(SIG_BLOCK, &sig_set, NULL) < 0) {
		sid_log_error_errno(LOG_PREFIX, errno, "sigprocmask failed");
		goto fail;
	}

	return 0;
fail:
	return -1;
}

static void _help(FILE *f)
{
	fprintf(f,
	        "Usage: usid [-h|--help] [-v|--verbose] [-V|--version] [command] [arguments]\n"
	        "\n"
	        "Communicate with SID daemon and interchange information.\n"
	        "\n"
	        "Global options:\n"
	        "    -h|--help       Show this help information.\n"
	        "    -v|--verbose    Verbose mode, repeat to increase level.\n"
	        "    -V|--version    Show USID version.\n"
	        "\n"
	        "Commands and arguments:\n"
	        "\n"
	        "    active\n"
	        "      Get SID daemon readiness and compatibility state.\n"
	        "      Input:  None.\n"
	        "      Output: SID_UBR_STATUS=active if SID is active and compatible.\n"
	        "              SID_UBR_STATUS=incompatible if SID is active but incompatible.\n"
	        "              SID_UBR_STATUS=inactive if SID is not active.\n"
	        "              SID_UBR_STATUS=error on error.\n"
	        "\n"
	        "    checkpoint <checkpoint_name> [key1 key2 ...]\n"
	        "      Send information to SID about reached checkpoint with optional environment.\n"
	        "      Input:  Identification of checkpoint by checkpoint_name.\n"
	        "              Optional list of keys from current command environment.\n"
	        "      Output: Added or changed items in KEY=VALUE format.\n"
	        "\n"
	        "    scan\n"
	        "      Execute scanning phase in SID daemon with current environment.\n"
	        "      Input:  Current command environment in KEY=VALUE format.\n"
	        "      Output: Added or changed items in KEY=VALUE format.\n"
	        "\n"
	        "    version\n"
	        "      Get USID and SID daemon version.\n"
	        "      Input:  None.\n"
	        "      Output: USID_IFC_PROTOCOL/MAJOR/MINOR/RELEASE for USID version.\n"
	        "              SID_IFC_PROTOCOL/MAJOR/MINOR/RELEASE for SID version.\n"
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
	int opt;
	int verbose              = 0;
	int r                    = -1;

	struct option longopts[] = {{"help", 0, NULL, 'h'},
	                            {"verbose", 0, NULL, 'v'},
	                            {"version", 0, NULL, 'V'},
	                            {NULL, 0, NULL, 0}};

	for (;;) {
		opt = getopt_long(argc, argv, "hvV", longopts, NULL);

		if (opt == -1)
			break;

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

	sid_log_init(SID_LOG_TGT_STANDARD, verbose);

	if (_init_usid()) {
		sid_log_error(LOG_PREFIX, "_init_usid failed");
		return EXIT_FAILURE;
	}

	switch (sid_ifc_cmd_name_to_type(argv[optind])) {
		case SID_IFC_CMD_ACTIVE:
			r = _usid_cmd_active();
			break;
		case SID_IFC_CMD_CHECKPOINT:
			r = _usid_cmd_checkpoint(argc - optind, &argv[optind]);
			break;
		case SID_IFC_CMD_SCAN:
			r = _usid_cmd_scan();
			break;
		case SID_IFC_CMD_VERSION:
			r = _usid_cmd_version();
			break;
		default:
			_help(stderr);
	}

	return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
