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

#include <limits.h>
#include <stdio.h>
#include <systemd/sd-journal.h>
#include <unistd.h>

static int _max_level_id  = -1;
static int _force_err_out = 0;
static int _with_pids     = 0;
static int _with_src_info = 1;

void log_journal_open(int verbose_mode)
{
	switch (verbose_mode) {
		case 0:
			_max_level_id = LOG_NOTICE;
			break;
		case 1:
			_max_level_id = LOG_INFO;
			break;
		case 2:
			_max_level_id = LOG_DEBUG;
			break;
		case 3:
			_max_level_id  = LOG_DEBUG;
			_with_src_info = 1;
			_force_err_out = 1;
			break;
		default:
			_max_level_id  = LOG_DEBUG;
			_with_src_info = 1;
			_force_err_out = 1;
			_with_pids     = 1;
			break;
	}
}

void log_journal_close(void)
{
	fflush(stdout);
	fflush(stderr);
}

void log_journal_output(const log_req_t *req, const char *format, va_list ap)
{
	char   msg[LINE_MAX];
	size_t prefix_len, remaining_len;
	int    r;

	if (req->ctx->level_id > _max_level_id)
		return;

	/* +1 for '<', +1 for '>' and +1 for '\0' at the end */
	prefix_len = req->pfx ? strlen(req->pfx->s) + 3 : 3;

	if (prefix_len >= sizeof(msg)) {
		sd_journal_send("MESSAGE=%s: (log prefix too long)",
		                "PRIORITY=%d",
		                req->ctx->level_id,
		                "CODE_FILE=%s",
		                req->ctx->src_file,
		                "CODE_LINE=%d",
		                req->ctx->src_line,
		                "CODE_FUNC=%s",
		                req->ctx->src_func,
		                NULL);

		return;
	}

	remaining_len = sizeof(msg) - prefix_len;

	if (req->pfx)
		(void) snprintf(msg, sizeof(msg), "<%s> ", req->pfx->s);
	r = vsnprintf(msg + prefix_len, remaining_len, format, ap);

	if (r < 0 || r >= remaining_len)
		sd_journal_send("MESSAGE=%s: (log message truncated)",
		                "PRIORITY=%d",
		                req->ctx->level_id,
		                "CODE_FILE=%s",
		                req->ctx->src_file,
		                "CODE_LINE=%d",
		                req->ctx->src_line,
		                "CODE_FUNC=%s",
		                req->ctx->src_func,
		                NULL);

	if (r > 0) {
		if (_with_src_info)
			sd_journal_send("MESSAGE=%s",
			                msg,
			                "PREFIX=%s",
			                req->pfx ? req->pfx->s : "",
			                "PRIORITY=%d",
			                req->ctx->level_id,
			                "CODE_FILE=%s",
			                req->ctx->src_file,
			                "CODE_LINE=%d",
			                req->ctx->src_line,
			                "CODE_FUNC=%s",
			                req->ctx->src_func,
			                NULL);
		else
			sd_journal_send("MESSAGE=%s",
			                msg,
			                "PREFIX=%s",
			                req->pfx ? req->pfx->s : "",
			                "PRIORITY=%d",
			                req->ctx->level_id,
			                NULL);
	}
}

const struct log_target log_target_journal = {.name   = "journal",
                                              .open   = log_journal_open,
                                              .close  = log_journal_close,
                                              .output = log_journal_output};
