/*
 * SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "base/util.h"
#include "internal/util.h"
#include "log/log.h"
#include "resource/res.h"
#include "resource/wrk-ctl.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define SID_DEFAULT_UMASK 0077
#define LOG_PREFIX        "main"

#define KEY_VERBOSE       "VERBOSE"

static sid_log_t *_log = NULL;

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
			sid_log_herror_errno(_log, LOG_PREFIX, errno, "Failed to fork the first time to become daemon");
			exit(EXIT_FAILURE);
		case 0:
			break;
		default:
			exit(EXIT_SUCCESS);
	}

	if (!setsid()) {
		sid_log_herror_errno(_log, LOG_PREFIX, errno, "Failed to create a new session to become daemon");
		exit(EXIT_FAILURE);
	}

	switch (fork()) {
		case -1:
			sid_log_herror_errno(_log, LOG_PREFIX, errno, "Failed to fork the second time to become daemon");
			exit(EXIT_FAILURE);
		case 0:
			break;
		default:
			exit(EXIT_SUCCESS);
	}

	if (chdir("/")) {
		sid_log_herror_errno(_log, LOG_PREFIX, errno, "Failed to change working directory");
		exit(EXIT_FAILURE);
	}

	if ((fd = open("/dev/null", O_RDWR)) == -1) {
		sid_log_herror_errno(_log, LOG_PREFIX, errno, "Failed to open /dev/null");
		exit(EXIT_FAILURE);
	}

	if ((dup2(fd, STDIN_FILENO) < 0) || (dup2(fd, STDOUT_FILENO) < 0) || (dup2(fd, STDERR_FILENO) < 0)) {
		sid_log_herror_errno(_log, LOG_PREFIX, errno, "Failed to duplicate standard IO streams");
		(void) close(fd);
		exit(EXIT_FAILURE);
	}

	(void) close(fd);

	for (fd = sysconf(_SC_OPEN_MAX) - 1; fd > STDERR_FILENO; fd--) {
		if (close(fd)) {
			if (errno == EBADF)
				continue;
			sid_log_herror_errno(_log, LOG_PREFIX, errno, "Failed to close FD %d", fd);
		}
	}

	umask(SID_DEFAULT_UMASK);
}

static void _close_log()
{
	sid_log_close(_log);
}

/*
 * This is pthread_atfork's callback.
 * We're still running with signals blocked and no other threads at this moment
 * if we used wrk_ctl interface to get a new worker. Therefore, it should be OK
 * to call getpid() and possibly other functions from here even if not listed as
 * async-thread-safe.
 */
static void _set_log_prefix()
{
	static char buf[16] = "c ";

	if (util_proc_pid_to_str(getpid(), buf + 2, sizeof(buf) - 2) < 0)
		return;

	sid_log_set_pfx(_log, buf);
}

int main(int argc, char *argv[])
{
	unsigned long long val;
	int                opt;
	int                verbose    = 0;
	int                foreground = 0;
	int                journal    = 0;
	sid_res_t         *sid_res    = NULL;
	int                r          = -1;

	struct option longopts[]      = {{"foreground", 0, NULL, 'f'},
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
				return EINVAL;
		}
	}

	if (sid_util_env_get_ull(KEY_VERBOSE, 0, INT_MAX, &val) == 0)
		verbose = val;

	if (atexit(_close_log) < 0)
		return EXIT_FAILURE;

	if (journal)
		_log = sid_log_init_with_handle(SID_LOG_TGT_JOURNAL, verbose);
	else {
		if (foreground)
			_log = sid_log_init_with_handle(SID_LOG_TGT_STANDARD, verbose);
		else
			_log = sid_log_init_with_handle(SID_LOG_TGT_SYSLOG, verbose);
	}

	if (!_log) {
		fprintf(stderr, "Failed to initialize logging.");
		return EXIT_FAILURE;
	}

	if (!foreground)
		_become_daemon();

	if ((r = pthread_atfork(NULL, NULL, _set_log_prefix)) < 0) {
		sid_log_herror_errno(_log, LOG_PREFIX, r, "Failed to register fork handler.");
		return EXIT_FAILURE;
	}

	sid_res = sid_res_create(
		SID_RES_NO_PARENT,
		&sid_res_type_sid,
		SID_RES_FL_NONE,
		SID_RES_NO_CUSTOM_ID,
		SID_RES_NO_PARAMS,
		SID_RES_PRIO_NORMAL,
		SID_RES_SRV_LNK_DEF_ARRAY(SID_RES_SRV_LNK_DEF(.name         = "systemd",
	                                                      .type         = SID_SRV_LNK_TYPE_SYSTEMD,
	                                                      .notification = SID_SRV_LNK_NOTIF_READY | SID_SRV_LNK_NOTIF_STATUS,
	                                                      .flags        = SID_SRV_LNK_FL_NONE,
	                                                      .data         = NULL),
	                                  SID_RES_SRV_LNK_DEF(.name         = "logger",
	                                                      .type         = SID_SRV_LNK_TYPE_LOGGER,
	                                                      .notification = SID_SRV_LNK_NOTIF_READY | SID_SRV_LNK_NOTIF_MESSAGE,
	                                                      .flags        = SID_SRV_LNK_FL_CLONEABLE,
	                                                      .data         = _log)));

	if (!sid_res_ref(sid_res))
		goto out;

	r = sid_res_ev_loop_run(sid_res);

	if (r == -ECHILD) {
		sid_res_t *worker_control_res;

		if (!(worker_control_res = sid_res_search(sid_res, SID_RES_SEARCH_WIDE_DFS, &sid_res_type_wrk_ctl, NULL))) {
			sid_log_herror(_log,
			               LOG_PREFIX,
			               SID_INTERNAL_ERROR "%s: Failed to find worker control resource.",
			               __func__);
			goto out;
		}

		sid_res = NULL;

		r       = sid_wrk_ctl_run_worker(worker_control_res,
                                           SID_RES_SRV_LNK_DEF_ARRAY(SID_RES_SRV_LNK_DEF(.name         = "worker-logger",
                                                                                         .type         = SID_SRV_LNK_TYPE_LOGGER,
                                                                                         .notification = SID_SRV_LNK_NOTIF_MESSAGE,
                                                                                         .flags        = SID_SRV_LNK_FL_CLONEABLE,
                                                                                         .data         = _log)));
	}

out:
	sid_res_unref(sid_res);
	return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
