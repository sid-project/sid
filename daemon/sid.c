/*
 * This file is part of SID.
 *
 * Copyright (C) 2017-2018 Red Hat, Inc. All rights reserved.
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

#include "configure.h"
#include "log.h"
#include "resource.h"

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>

#define SID_DEFAULT_UMASK 0077
#define LOG_PREFIX "main"

static volatile sig_atomic_t _shutdown_requested = 0;

const sid_resource_reg_t sid_resource_reg_sid;

static void _help(FILE *f)
{
	fprintf(f, "Usage: sid [options]\n"
		"\n"
		"    -f|--foreground  Run in foreground.\n"
		"    -h|--help        Show this help information.\n"
		"    -v|--verbose     Verbose mode, repeat to increase level.\n"
		"    -V|--version     Show SID version.\n"
		"\n");
}

static void _version(FILE *f)
{
	fprintf(f, PACKAGE_STRING "\n");
	fprintf(f, "Configuration line: %s\n", SID_CONFIGURE_LINE);
	fprintf(f, "Compiled by: %s on %s with %s\n", SID_COMPILED_BY,
		SID_COMPILATION_HOST, SID_COMPILER);
}

static void _shutdown_signal_handler(int sig __attribute__((unused)))
{
	_shutdown_requested = 1;
}

static void _become_daemon()
{
	pid_t pid = 0;
	int child_status;
	struct timeval tval;
	int fd;

	signal(SIGTERM, &_shutdown_signal_handler);

	if ((pid = fork()) < 0) {
		log_error_errno(LOG_PREFIX, errno, "Failed to fork daemon");
		exit(EXIT_FAILURE);
	}

	if (pid > 0) {
		log_debug(LOG_PREFIX, "Forked SID with pid=%d", pid);
		while (!waitpid(pid, &child_status, WNOHANG) && !_shutdown_requested) {
			tval.tv_sec = 1;
			tval.tv_usec = 0;
			select(0, NULL, NULL, NULL, &tval);
		}

		exit(_shutdown_requested ? EXIT_SUCCESS : WEXITSTATUS(child_status));
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

	if ((dup2(fd, STDIN_FILENO) < 0) ||
	    (dup2(fd, STDOUT_FILENO) < 0) ||
	    (dup2(fd, STDERR_FILENO) < 0)) {
		log_error_errno(LOG_PREFIX, errno, "Failed to duplicate standard IO streams");
		exit(EXIT_FAILURE);
	}

        for (fd = sysconf(_SC_OPEN_MAX) - 1; fd > STDERR_FILENO; fd--) {
                if (close(fd)) {
			if (errno == EBADF)
				continue;
			log_error_errno(LOG_PREFIX, errno, "Failed to close FD %d", fd);
		}
	}

	umask(SID_DEFAULT_UMASK);

	if (kill(getppid(), SIGTERM) < 0)
		log_error_errno(LOG_PREFIX, errno, "Failed to send SIGTERM signal to parent");
}

int main(int argc, char *argv[])
{
	int opt;
	int verbose = 0;
	int foreground = 0;
	sid_resource_t *sid_res = NULL;
	int r = -1;

	struct option longopts[] = {
		{ "foreground",         0, NULL, 'f' },
		{ "help",		0, NULL, 'h' },
		{ "verbose",            0, NULL, 'v' },
		{ "version",		0, NULL, 'V' },
		{ NULL,			0, NULL,  0  }
	};

	while ((opt = getopt_long(argc, argv, "fhvV", longopts, NULL)) != -1) {
		switch(opt) {
			case 'f':
				foreground = 1;
				break;
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

	if (foreground)
		log_init(LOG_TARGET_STANDARD, verbose);
	else {
		log_init(LOG_TARGET_SYSLOG, verbose);
		_become_daemon();
	}


	if (!(sid_res = sid_resource_create(NULL, &sid_resource_reg_sid, 0, NULL, NULL)))
		goto out;

	r = sid_resource_run_event_loop(sid_res);
out:
	if (sid_res)
		(void) sid_resource_destroy(sid_res);

	return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
