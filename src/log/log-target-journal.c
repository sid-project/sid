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

static void _log_journal_open(int verbose_mode)
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

static void _log_journal_close(void)
{
	fflush(stdout);
	fflush(stderr);
}

static void _log_journal_output(const log_req_t *req, const char *format, va_list ap)
{
	char       msg[LINE_MAX];
	log_pfx_t *pfx;
	size_t     printed, remaining;
	int        r;

	if (req->ctx->level_id > _max_level_id)
		return;

	for (printed = 0, remaining = sizeof(msg), pfx = req->pfx; pfx; pfx = pfx->n) {
		r = snprintf(msg + printed, remaining, "<%s> ", pfx->s ?: "");

		if (r >= remaining) {
			sd_journal_send("MESSAGE=(log prefix too long)",
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

		remaining -= r;
		printed   += r;
	}

	r = vsnprintf(msg + printed, remaining, format, ap);

	if (r < 0 || r >= remaining)
		sd_journal_send("MESSAGE=(log message truncated)",
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
                                              .open   = _log_journal_open,
                                              .close  = _log_journal_close,
                                              .output = _log_journal_output};
