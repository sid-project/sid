/*
 * This file is part of SID.
 *
 * Copyright (C) 2017-2019 Red Hat, Inc. All rights reserved.
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

#include "internal/common.h"

#include "base/util.h"
#include "log/log.h"
#include "resource/resource.h"
#include "resource/worker-control.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define SID_DEFAULT_UMASK 0077
#define LOG_PREFIX        "main"

#define KEY_VERBOSE       "VERBOSE"

static void _help(FILE *f)
{
	fprintf(f,
	        "Usage: sid [options]\n"
	        "\n"
	        "    -f|--foreground  Run in foreground.\n"
	        "    -j|--journal     Log to the journal.\n"
	        "    -h|--help        Show this help information.\n"
	        "    -v|--verbose     Verbose mode, repeat to increase level.\n"
	        "    -V|--version     Show SID version.\n"
	        "\n");
}

static void _version(FILE *f)
{
	fprintf(f, PACKAGE_STRING "\n");
	fprintf(f, "Configuration line: %s\n", SID_CONFIGURE_LINE);
	fprintf(f, "Compiled by: %s on %s with %s\n", SID_COMPILED_BY, SID_COMPILATION_HOST, SID_COMPILER);
}

static void _become_daemon()
{
	int fd;

	switch (fork()) {
		case -1:
			log_error_errno(LOG_PREFIX, errno, "Failed to fork daemon");
			exit(EXIT_FAILURE);
		case 0:
			break;
		default:
			exit(EXIT_SUCCESS);
	}

	if (!setsid()) {
		log_error_errno(LOG_PREFIX, errno, "Failed to set session ID");
		exit(EXIT_FAILURE);
	}

	if (chdir("/")) {
		log_error_errno(LOG_PREFIX, errno, "Failed to change working directory");
		exit(EXIT_FAILURE);
	}

	if ((fd = open("/dev/null", O_RDWR)) == -1) {
		log_error_errno(LOG_PREFIX, errno, "Failed to open /dev/null");
		exit(EXIT_FAILURE);
	}

	if ((dup2(fd, STDIN_FILENO) < 0) || (dup2(fd, STDOUT_FILENO) < 0) || (dup2(fd, STDERR_FILENO) < 0)) {
		log_error_errno(LOG_PREFIX, errno, "Failed to duplicate standard IO streams");
		(void) close(fd);
		exit(EXIT_FAILURE);
	}

	(void) close(fd);

	for (fd = sysconf(_SC_OPEN_MAX) - 1; fd > STDERR_FILENO; fd--) {
		if (close(fd)) {
			if (errno == EBADF)
				continue;
			log_error_errno(LOG_PREFIX, errno, "Failed to close FD %d", fd);
		}
	}

	umask(SID_DEFAULT_UMASK);
}

int main(int argc, char *argv[])
{
	unsigned long long val;
	int                opt;
	int                verbose    = 0;
	int                foreground = 0;
	int                journal    = 0;
	sid_resource_t    *sid_res    = NULL;
	log_t             *log;
	int                r     = -1;

	struct option longopts[] = {{"foreground", 0, NULL, 'f'},
	                            {"journal", 0, NULL, 'j'},
	                            {"help", 0, NULL, 'h'},
	                            {"verbose", 0, NULL, 'v'},
	                            {"version", 0, NULL, 'V'},
	                            {NULL, 0, NULL, 0}};

	while ((opt = getopt_long(argc, argv, "fjhvV", longopts, NULL)) != -1) {
		switch (opt) {
			case 'f':
				foreground = 1;
				break;
			case 'h':
				_help(stdout);
				return EXIT_SUCCESS;
			case 'j':
				journal = 1;
				break;
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

	if (sid_util_env_get_ull(KEY_VERBOSE, 0, INT_MAX, &val) == 0)
		verbose = val;

	if (foreground) {
		if (journal)
			log = log_init_with_handle(LOG_TARGET_JOURNAL, verbose);
		else
			log = log_init_with_handle(LOG_TARGET_STANDARD, verbose);
	} else {
		if (journal)
			log = log_init_with_handle(LOG_TARGET_JOURNAL, verbose);
		else
			log = log_init_with_handle(LOG_TARGET_SYSLOG, verbose);
		_become_daemon();
	}

	sid_res = sid_resource_create(SID_RESOURCE_NO_PARENT,
	                              &sid_resource_type_sid,
	                              SID_RESOURCE_NO_FLAGS,
	                              SID_RESOURCE_NO_CUSTOM_ID,
	                              SID_RESOURCE_NO_PARAMS,
	                              SID_RESOURCE_PRIO_NORMAL,
	                              (sid_resource_service_link_def_t[]) {
					      {
						      .name         = "systemd",
						      .type         = SERVICE_TYPE_SYSTEMD,
						      .notification = SERVICE_NOTIFICATION_READY,
						      .data         = NULL,
					      },
					      {
						      .name         = "logger",
						      .type         = SERVICE_TYPE_LOGGER,
						      .notification = SERVICE_NOTIFICATION_READY | SERVICE_NOTIFICATION_MESSAGE,
						      .data         = log,
					      },
					      NULL_SERVICE_LINK});

	if (!sid_res)
		goto out;

	sid_resource_ref(sid_res);

	r = sid_resource_run_event_loop(sid_res);
	if (r == -ECHILD) {
		sid_resource_t *worker_control_res;

		if (!(worker_control_res = sid_resource_search(sid_res,
		                                               SID_RESOURCE_SEARCH_WIDE_DFS,
		                                               &sid_resource_type_worker_control,
		                                               NULL))) {
			log_error(LOG_PREFIX, INTERNAL_ERROR "%s: Failed to find worker control resource.", __func__);
			goto out;
		}
		sid_res = NULL;
		r       = worker_control_run_worker(worker_control_res);
	}

out:
	if (sid_res)
		sid_resource_unref(sid_res);

	return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
