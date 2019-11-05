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

#include "buffer.h"
#include "comms.h"
#include "configure.h"
#include "log.h"
#include "macros.h"
#include "usid-iface.h"

#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#define LOG_PREFIX                      "usid"

#define KEY_ENV_SEQNUM                  "SEQNUM"
#define KEY_ENV_MAJOR                   "MAJOR"
#define KEY_ENV_MINOR                   "MINOR"

#define KEY_USID_BRIDGE_STATUS          "USID_BRIDGE_STATUS"
#define USID_BRIDGE_STATUS_ACTIVE       "active"
#define USID_BRIDGE_STATUS_INACTIVE     "inactive"
#define USID_BRIDGE_STATUS_INCOMPATIBLE "incompatible"

#define KEY_USID_PROTOCOL               "USID_PROTOCOL"
#define KEY_USID_MAJOR                  "USID_MAJOR"
#define KEY_USID_MINOR                  "USID_MINOR"
#define KEY_USID_RELEASE                "USID_RELEASE"

#define KEY_SID_PROTOCOL                "SID_PROTOCOL"
#define KEY_SID_MAJOR                   "SID_MAJOR"
#define KEY_SID_MINOR                   "SID_MINOR"
#define KEY_SID_RELEASE                 "SID_RELEASE"

typedef int (*sid_req_data_fn_t) (struct buffer *buf, void *data);

struct args {
	int argc;
	char **argv;
};

static int _sid_req(usid_cmd_t cmd, uint64_t status, sid_req_data_fn_t data_fn, void *data_fn_arg, struct buffer **resp_buf)
{
	int socket_fd = -1;
	struct buffer *buf = NULL;
	ssize_t n;
	int r = -1;

	if ((socket_fd = comms_unix_init(UBRIDGE_SOCKET_PATH, SOCK_STREAM | SOCK_CLOEXEC)) < 0)
		goto out;

	if (!(buf = buffer_create(BUFFER_TYPE_LINEAR, BUFFER_MODE_SIZE_PREFIX, 0, 1))) {
		log_error(LOG_PREFIX, "Failed to create message buffer.");
		goto out;
	}

	buffer_add(buf,
	&((struct usid_msg_header) {
		.prot = UBRIDGE_PROTOCOL,
		.cmd = cmd,
		.status = status
	}), USID_MSG_HEADER_SIZE);

	if (data_fn && (data_fn(buf, data_fn_arg) < 0))
		goto out;

	if (buffer_write(buf, socket_fd) < 0) {
		log_error(LOG_PREFIX, "Failed to send request to SID daemon.");
		goto out;
	}

	buffer_reset(buf, 0, 1);

	for (;;) {
		n = buffer_read(buf, socket_fd);
		if (n > 0) {
			if (buffer_is_complete(buf)) {
				r = 0;
				break;
			}
		} else if (n < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			r = -EBADMSG;
			break;
		} else
			break;
	}
out:
	if (socket_fd >= 0)
		close(socket_fd);

	if (r < 0) {
		if (buf)
			buffer_destroy(buf);
	} else
		*resp_buf = buf;

	return r;
}

int _get_env_ul(const char *key, unsigned long *val)
{
	unsigned long ret;
	char *env_val;
	char *p;

	if (!(env_val = getenv(key)))
		return -ENOKEY;

	errno = 0;
	ret = strtoul(env_val, &p, 10);
	if (errno || !p || *p)
		return -ERANGE;

	*val = ret;
	return 0;
}

static int _usid_cmd_active(struct args *args)
{
	uint64_t seqnum;
	struct buffer *buf = NULL;
	struct usid_msg_header *hdr;
	size_t size;
	const char *status;
	int r;

	if (_get_env_ul(KEY_ENV_SEQNUM, &seqnum) < 0)
		seqnum = 0;

	if ((r = _sid_req(USID_CMD_VERSION, seqnum, NULL, NULL, &buf)) == 0) {
		buffer_get_data(buf, (const void **) &hdr, &size);

		if ((size >= (USID_MSG_HEADER_SIZE + USID_VERSION_SIZE)) &&
		    (hdr->prot == UBRIDGE_PROTOCOL))
			status = USID_BRIDGE_STATUS_ACTIVE;
		else
			status = USID_BRIDGE_STATUS_INCOMPATIBLE;

		buffer_destroy(buf);
	} else
		status = USID_BRIDGE_STATUS_INACTIVE;

	fprintf(stdout, KEY_USID_BRIDGE_STATUS "=%s\n", status);

	return 0;
}

static int _print_env_from_buffer(struct buffer *buf)
{
	struct usid_msg_header *hdr;
	size_t size;
	const char *end, *kv;

	buffer_get_data(buf, (const void **) &hdr, &size);
	if (size < USID_MSG_HEADER_SIZE)
		return -EBADMSG;

	size -= USID_MSG_HEADER_SIZE;

	for (kv = hdr->data, end = hdr->data + size; kv < end; kv += strlen(kv) + 1)
		fprintf(stdout, "%s\n", kv);

	return 0;
}

static int _add_devt_env_to_buffer(struct buffer *buf)
{
	unsigned long major, minor;
	dev_t devnum;

	if ((_get_env_ul(KEY_ENV_MAJOR, &major) < 0) ||
	    (_get_env_ul(KEY_ENV_MINOR, &minor) < 0))
		return -ENOKEY;

	devnum = makedev(major, minor);
	buffer_add(buf, &devnum, sizeof(devnum));

	return 0;
}

static int _add_checkpoint_env_to_buf(struct buffer *buf, void *data)
{
	struct args *args = data;
	const char *key, *val;
	int i, r;

	if ((r = _add_devt_env_to_buffer(buf)) < 0)
		return r;

	if (args->argc < 2)
		/* we need at least checkpoint name */
		return -EINVAL;

	/* add checkpoint name */
	buffer_add(buf, args->argv[1], strlen(args->argv[1]));

	/* add key=value pairs from current environment */
	for (i = 2; i < args->argc; i++) {
		key = args->argv[i];
		if (!(val = getenv(key)))
			continue;

		buffer_fmt_add(buf, "%s=%s", key, val);
	}

	return 0;
}

static int _usid_cmd_checkpoint(struct args *args)
{
	uint64_t seqnum;
	struct buffer *buf = NULL;
	int r;

	if ((r = _get_env_ul(KEY_ENV_SEQNUM, &seqnum)) < 0)
		return r;

	if ((r = _sid_req(USID_CMD_CHECKPOINT, seqnum, _add_checkpoint_env_to_buf, args, &buf) == 0)) {
		r = _print_env_from_buffer(buf);
		buffer_destroy(buf);
	}

	return r;
}

static int _add_scan_env_to_buf(struct buffer *buf, void *data)
{
	extern char **environ;
	char **kv;
	int r;

	if ((r = _add_devt_env_to_buffer(buf)) < 0)
		return r;

	for (kv = environ; *kv; kv++)
		buffer_add(buf, *kv, strlen(*kv) + 1);

	return 0;
}

static int _usid_cmd_scan(struct args *args)
{
	uint64_t seqnum;
	struct buffer *buf = NULL;
	int r;

	if ((r = _get_env_ul(KEY_ENV_SEQNUM, &seqnum)) < 0)
		return r;

	if ((r = _sid_req(USID_CMD_SCAN, seqnum, _add_scan_env_to_buf, NULL, &buf) == 0)) {
		r = _print_env_from_buffer(buf);
		buffer_destroy(buf);
	}

	return r;
}

static int _usid_cmd_version(struct args *args)
{
	uint64_t seqnum;
	struct buffer *buf = NULL;
	struct usid_msg_header *hdr;
	size_t size;
	struct usid_version *vsn = NULL;
	int r;

	if (_get_env_ul(KEY_ENV_SEQNUM, &seqnum) < 0)
		seqnum = 0;

	fprintf(stdout, KEY_USID_PROTOCOL "=%" PRIu8 "\n"
	        KEY_USID_MAJOR "=%" PRIu16 "\n"
	        KEY_USID_MINOR "=%" PRIu16 "\n"
	        KEY_USID_RELEASE "=%" PRIu16 "\n",
	        UBRIDGE_PROTOCOL,
	        SID_VERSION_MAJOR,
	        SID_VERSION_MINOR,
	        SID_VERSION_RELEASE);

	if ((r = _sid_req(USID_CMD_VERSION, seqnum, NULL, NULL, &buf)) == 0) {
		buffer_get_data(buf, (const void **) &hdr, &size);

		if (size >= (USID_MSG_HEADER_SIZE + USID_VERSION_SIZE)) {
			vsn = (struct usid_version *) hdr->data;
			fprintf(stdout, KEY_SID_PROTOCOL "=%" PRIu8 "\n"
			        KEY_SID_MAJOR "=%" PRIu16 "\n"
			        KEY_SID_MINOR "=%" PRIu16 "\n"
			        KEY_SID_RELEASE "=%" PRIu16 "\n",
			        hdr->prot,
			        vsn->major,
			        vsn->minor,
			        vsn->release);
		}

		buffer_destroy(buf);
	} else
		log_error(LOG_PREFIX, "Unexpected response from SID daemon for version request.");

	return r;
}

static void _help(FILE *f)
{
	fprintf(f, "Usage: usid [--help] [--verbose] [--version] [command] [command_options]\n"
	        "\n"
	        "Communicate with SID daemon and interchange information.\n"
	        "\n"
	        "Global options:\n"
	        "    -h|--help       Show this help information.\n"
	        "    -v|--verbose    Verbose mode, repeat to increase level.\n"
	        "    -V|--version    Show USID version.\n"
	        "\n"
	        "Commands:\n"
	        "\n"
	        "    active\n"
	        "      Get SID daemon readiness and compatibility state.\n"
	        "      Input:  None.\n"
	        "      Output: USID_BRIDGE_STATUS=active if SID active and compatible.\n"
	        "              USID_BRIDGE_STATUS=incompatible if SID active but incompatible.\n"
	        "              USID_BRIDGE_STATUS=inactive is SID not active.\n"
	        "\n"
	        "    checkpoint <checkpoint_name> [key1 key2 ...]\n"
	        "      Send information to SID about reaching a checkpoint.\n"
	        "      Input:  Identification of checkpoint by checkpoint_name.\n"
	        "              List of keys from current command environment.\n"
	        "      Output: Added or changed items in KEY=VALUE format.\n"
	        "\n"
	        "    scan\n"
	        "      Execute scanning phase in SID daemon for current environment.\n"
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
	fprintf(f, "Compiled by: %s on %s with %s\n", SID_COMPILED_BY,
	        SID_COMPILATION_HOST, SID_COMPILER);
}

int main(int argc, char *argv[])
{
	int opt;
	int verbose = 0;
	struct args subcmd_args;
	int r = -1;

	struct option longopts[] = {
		{ "help",       0, NULL, 'h'},
		{ "verbose",    0, NULL, 'v'},
		{ "version",    0, NULL, 'V'},
		{ NULL,         0, NULL,  0 }
	};

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
				return -EINVAL;
		}
	}

	log_init(LOG_TARGET_STANDARD, verbose);

	subcmd_args.argc = argc - optind;
	subcmd_args.argv = &argv[optind];

	switch (usid_cmd_name_to_type(subcmd_args.argv[0])) {
		case USID_CMD_ACTIVE:
			r = _usid_cmd_active(&subcmd_args);
			break;
		case USID_CMD_CHECKPOINT:
			r = _usid_cmd_checkpoint(&subcmd_args);
			break;
		case USID_CMD_SCAN:
			r = _usid_cmd_scan(&subcmd_args);
			break;
		case USID_CMD_VERSION:
			r = _usid_cmd_version(&subcmd_args);
			break;
		default:
			_help(stderr);
	}

	return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
