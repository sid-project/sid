/*
 * This file is part of SID.
 *
 * Copyright (C) 2017-2020 Red Hat, Inc. All rights reserved.
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

struct sid_log {
	int           handle_required;
	sid_log_tgt_t target;
	int           verbose_mode;
	const char   *prefix;
} _log                                                 = {SID_LOG_TGT_NONE, 0};

static const struct sid_log_tgt *log_target_registry[] = {[SID_LOG_TGT_STANDARD] = &log_target_standard,
                                                          [SID_LOG_TGT_SYSLOG]   = &log_target_syslog,
                                                          [SID_LOG_TGT_JOURNAL]  = &log_target_journal};

void sid_log_init(sid_log_tgt_t target, int verbose_mode)
{
	if (_log.target != SID_LOG_TGT_NONE)
		return;

	_log.handle_required = 0;
	_log.target          = target;
	_log.verbose_mode    = verbose_mode;

	if (target != SID_LOG_TGT_NONE)
		log_target_registry[_log.target]->open(verbose_mode);
}

sid_log_t *sid_log_init_with_handle(sid_log_tgt_t target, int verbose_mode)
{
	sid_log_init(target, verbose_mode);
	_log.handle_required = 1;

	return &_log;
}

void sid_log_close(sid_log_t *log)
{
	if (log && log != &_log)
		return;

	if (_log.target != SID_LOG_TGT_NONE)
		log_target_registry[_log.target]->close();
}

void sid_log_change_tgt(sid_log_t *log, sid_log_tgt_t new_target)
{
	if (!log || log->target == new_target)
		return;

	if (log->target != SID_LOG_TGT_NONE)
		log_target_registry[log->target]->close();
	if (new_target != SID_LOG_TGT_NONE)
		log_target_registry[new_target]->open(log->verbose_mode);

	log->target = new_target;
}

void sid_log_set_pfx(sid_log_t *log, const char *prefix)
{
	if (!log)
		return;

	log->prefix = prefix;
}

void sid_log_voutput(sid_log_t *log, sid_log_req_t *req, const char *format, va_list ap)
{
	static int    log_ignored = 0;
	int           orig_errno  = errno;
	sid_log_req_t tmp_req;
	sid_log_pfx_t pfx;

	if (log && log->prefix) {
		pfx.s       = log->prefix;
		pfx.n       = req->pfx;
		tmp_req.pfx = &pfx;
		tmp_req.ctx = req->ctx;
		req         = &tmp_req;
	}

	if (_log.handle_required && (log != &_log)) {
		if (!log_ignored) {
			tmp_req.pfx = NULL;
			tmp_req.ctx = &((sid_log_ctx_t) {.level_id = LOG_ERR,
			                                 .errno_id = 0,
			                                 .src_file = req->ctx->src_file,
			                                 .src_line = req->ctx->src_line,
			                                 .src_func = req->ctx->src_func});
			sid_log_voutput(&_log,
			                &tmp_req,
			                SID_INTERNAL_ERROR "Incorrect or missing log handle, skipping log messages.",
			                ap);
			log_ignored = 1;
		}
		goto out;
	}

	if (_log.target == SID_LOG_TGT_NONE)
		return;

	if (req->ctx->errno_id < 0)
		req->ctx->errno_id = -req->ctx->errno_id;

	log_target_registry[_log.target]->output(req, format, ap);
out:
	errno = orig_errno;
}

void sid_log_output(sid_log_t *log, sid_log_req_t *req, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	sid_log_voutput(log, req, format, ap);
	va_end(ap);
}
