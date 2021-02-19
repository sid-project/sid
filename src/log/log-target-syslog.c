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

#include "log/log.h"

#include <stdio.h>

#define SID_SYSLOG_IDENT "sid"

static int _max_level_id = -1;

void log_syslog_open(int verbose_mode)
{
	switch (verbose_mode) {
		case 0:
			_max_level_id = LOG_NOTICE;
			break;
		case 1:
			_max_level_id = LOG_INFO;
			break;
		default:
			_max_level_id = LOG_DEBUG;
			break;
	}

	openlog(SID_SYSLOG_IDENT, LOG_PID, LOG_DAEMON);
}

void log_syslog_close(void)
{
	closelog();
}

void log_syslog_output(int         level_id,
                       const char *prefix,
                       int         class_id,
                       int         errno_id,
                       const char *src_file_name,
                       int         src_line_number,
                       const char *function_name,
                       const char *format,
                       va_list     ap)
{
	char   msg[4096];
	size_t prefix_len, remaining_len;
	int    r;

	if (level_id > _max_level_id)
		return;

	/* +1 for '<', +1 for '>' and +1 for '\0' at the end */
	prefix_len = strlen(prefix) + 3;

	if (prefix_len >= sizeof(msg)) {
		syslog(level_id, INTERNAL_ERROR "%s: (log prefix too long)", __func__);
		vsyslog(level_id, format, ap);
		return;
	}

	remaining_len = sizeof(msg) - prefix_len;

	(void) snprintf(msg, sizeof(msg), "<%s> ", prefix);
	r = vsnprintf(msg + prefix_len, remaining_len, format, ap);

	if (r < 0 || r >= remaining_len)
		syslog(level_id, INTERNAL_ERROR "%s: (log message truncated)", __func__);

	if (r > 0)
		syslog(level_id, "%s", msg);
}

const struct log_target log_target_syslog = {.name   = "syslog",
                                             .open   = log_syslog_open,
                                             .close  = log_syslog_close,
                                             .output = log_syslog_output};
