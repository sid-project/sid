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

#include "base/common.h"

#include "base/buffer.h"
#include "base/util.h"
#include "iface/usid.h"
#include "log/log.h"

#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysmacros.h>

#define LOG_PREFIX "usid"

#define KEY_ENV_SEQNUM "SEQNUM"

#define KEY_USID_BRIDGE_STATUS          "USID_BRIDGE_STATUS"
#define USID_BRIDGE_STATUS_ERROR        "error"
#define USID_BRIDGE_STATUS_ACTIVE       "active"
#define USID_BRIDGE_STATUS_INACTIVE     "inactive"
#define USID_BRIDGE_STATUS_INCOMPATIBLE "incompatible"

#define KEY_USID_PROTOCOL "USID_PROTOCOL"
#define KEY_USID_MAJOR    "USID_MAJOR"
#define KEY_USID_MINOR    "USID_MINOR"
#define KEY_USID_RELEASE  "USID_RELEASE"

#define KEY_SID_PROTOCOL "SID_PROTOCOL"
#define KEY_SID_MAJOR    "SID_MAJOR"
#define KEY_SID_MINOR    "SID_MINOR"
#define KEY_SID_RELEASE  "SID_RELEASE"

struct args {
	int    argc;
	char **argv;
};

static int _usid_cmd_active(void)
{
	unsigned long long  val;
	uint8_t             prot;
	const char *        status;
	struct usid_result *res;
	struct usid_request req = {.cmd = USID_CMD_VERSION, .flags = USID_CMD_FLAGS_FMT_ENV};
	int                 r;

	req.seqnum = util_env_get_ull(KEY_ENV_SEQNUM, 0, UINT64_MAX, &val) < 0 ? 0 : val;

	if ((r = usid_req(&req, &res)) == 0) {
		if (usid_result_data(res, NULL) && usid_result_protocol(res, &prot) == 0 && prot == USID_PROTOCOL)
			status = USID_BRIDGE_STATUS_ACTIVE;
		else
			status = USID_BRIDGE_STATUS_INCOMPATIBLE;

		usid_result_free(res);
	} else {
		if (r == -ECONNREFUSED) {
			status = USID_BRIDGE_STATUS_INACTIVE;
			r      = 0;
		} else if (r == -EBADMSG)
			status = USID_BRIDGE_STATUS_INCOMPATIBLE;
		else
			status = USID_BRIDGE_STATUS_ERROR;
	}

	fprintf(stdout, KEY_USID_BRIDGE_STATUS "=%s\n", status);

	return r;
}

static int _print_env_from_res(struct usid_result *res)
{
	size_t      size;
	const char *end, *kv;

	kv = usid_result_data(res, &size);
	if (!kv)
		return -EBADMSG;

	for (end = kv + size; kv < end; kv += strlen(kv) + 1)
		fprintf(stdout, "%s\n", kv);

	return 0;
}

static int _usid_cmd_print_env(struct usid_request *req)
{
	unsigned long long  val;
	struct usid_result *res;
	int                 r;

	if ((r = util_env_get_ull(KEY_ENV_SEQNUM, 0, UINT64_MAX, &val)) < 0) {
		log_error_errno(LOG_PREFIX, r, "Failed to get value for %s key from environment", KEY_ENV_SEQNUM);
		return r;
	}
	req->seqnum = val;

	if ((r = usid_req(req, &res)) == 0) {
		r = _print_env_from_res(res);
		usid_result_free(res);
	}
out:
	return r;
}

static int _usid_cmd_scan(void)
{
	struct usid_request req = {.cmd = USID_CMD_SCAN, .flags = USID_CMD_FLAGS_FMT_ENV};

	return _usid_cmd_print_env(&req);
}

static int _usid_cmd_checkpoint(int argc, char **argv)
{
	struct usid_request req = {.cmd = USID_CMD_CHECKPOINT, .flags = USID_CMD_FLAGS_FMT_ENV};

	if (argc < 2) {
		/* we need at least checkpoint name */
		log_error(LOG_PREFIX, "Missing checkpoint name.");
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
	unsigned long long  val;
	uint64_t            seqnum;
	const char *        data;
	size_t              size;
	int                 r;
	struct usid_result *res;
	struct usid_request req = {.cmd = USID_CMD_VERSION, .flags = USID_CMD_FLAGS_FMT_ENV};

	req.seqnum = util_env_get_ull(KEY_ENV_SEQNUM, 0, UINT64_MAX, &val) < 0 ? 0 : val;

	fprintf(stdout,
	        KEY_USID_PROTOCOL "=%" PRIu8 "\n" KEY_USID_MAJOR "=%" PRIu16 "\n" KEY_USID_MINOR "=%" PRIu16 "\n" KEY_USID_RELEASE
	                          "=%" PRIu16 "\n",
	        USID_PROTOCOL,
	        SID_VERSION_MAJOR,
	        SID_VERSION_MINOR,
	        SID_VERSION_RELEASE);

	if ((r = usid_req(&req, &res)) == 0) {
		if ((data = usid_result_data(res, NULL)) != NULL)
			fprintf(stdout, "%s", data);
		else
			r = -1;
		usid_result_free(res);
	}

	return r;
}

static int _init_usid()
{
	sigset_t sig_set;

	if (sigemptyset(&sig_set) < 0) {
		log_error_errno(LOG_PREFIX, errno, "sigemptyset failed");
		goto fail;
	}

	if (sigaddset(&sig_set, SIGPIPE) < 0) {
		log_error_errno(LOG_PREFIX, errno, "siggaddset failed");
		goto fail;
	}

	if (sigprocmask(SIG_BLOCK, &sig_set, NULL) < 0) {
		log_error_errno(LOG_PREFIX, errno, "sigprocmask failed");
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
	        "      Output: USID_BRIDGE_STATUS=active if SID is active and compatible.\n"
	        "              USID_BRIDGE_STATUS=incompatible if SID is active but incompatible.\n"
	        "              USID_BRIDGE_STATUS=inactive if SID is not active.\n"
	        "              USID_BRIDGE_STATUS=error on error.\n"
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
	        "      Output: USID_PROTOCOL/MAJOR/MINOR/RELEASE for USID version.\n"
	        "              SID_PROTOCOL/MAJOR/MINOR/RELEASE for SID version.\n"
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
	usid_cmd_t cmd;
	int        opt;
	int        verbose = 0;
	int        r       = -1;

	if (_init_usid()) {
		log_error(LOG_PREFIX, "_init_usid failed");
		return EXIT_FAILURE;
	}

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

	log_init(LOG_TARGET_STANDARD, verbose);

	switch (usid_cmd_name_to_type(argv[optind])) {
		case USID_CMD_ACTIVE:
			r = _usid_cmd_active();
			break;
		case USID_CMD_CHECKPOINT:
			r = _usid_cmd_checkpoint(argc - optind, &argv[optind]);
			break;
		case USID_CMD_SCAN:
			r = _usid_cmd_scan();
			break;
		case USID_CMD_VERSION:
			r = _usid_cmd_version();
			break;
		default:
			_help(stderr);
	}

	return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
