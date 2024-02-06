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
#include <unistd.h>

static int _max_level_id  = -1;
static int _force_err_out = 0;
static int _with_pids     = 0;
static int _with_src_info = 0;

static void _log_standard_open(int verbose_mode)
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

static void _log_standard_close(void)
{
	fflush(stdout);
	fflush(stderr);
}

static void _log_standard_output(const sid_log_req_t *req, const char *format, va_list ap)
{
	FILE          *out_file;
	sid_log_pfx_t *pfx;

	if (req->ctx->level_id > _max_level_id && req->ctx->level_id != SID_LOG_PRINT)
		return;

	out_file = _force_err_out ? stderr : req->ctx->level_id <= LOG_WARNING ? stderr : stdout;

	if (_with_pids)
		fprintf(out_file, "[%d:%d]:", getppid(), getpid());

	if (_with_src_info)
		fprintf(out_file,
		        "%s:%d%s%s\t",
		        req->ctx->src_file,
		        req->ctx->src_line,
		        req->ctx->src_func ? ":" : "",
		        req->ctx->src_func ?: "");

	for (pfx = req->pfx; pfx; pfx = pfx->n)
		fprintf(out_file, "<%s> ", pfx->s ?: "");

	vfprintf(out_file, format, ap);

	if (req->ctx->errno_id)
		fprintf(out_file, ": %s.", strerror(req->ctx->errno_id));

	fputc('\n', out_file);
}

const struct sid_log_tgt log_target_standard = {.name   = "standard",
                                                .open   = _log_standard_open,
                                                .close  = _log_standard_close,
                                                .output = _log_standard_output};
