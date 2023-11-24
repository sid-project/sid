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

struct log {
	int          handle_required;
	log_target_t target;
	int          verbose_mode;
} _log                                                = {LOG_TARGET_NONE, 0};

static const struct log_target *log_target_registry[] = {[LOG_TARGET_STANDARD] = &log_target_standard,
                                                         [LOG_TARGET_SYSLOG]   = &log_target_syslog,
                                                         [LOG_TARGET_JOURNAL]  = &log_target_journal};

void log_init(log_target_t target, int verbose_mode)
{
	if (_log.target != LOG_TARGET_NONE)
		return;

	_log.handle_required = 0;
	_log.target          = target;
	_log.verbose_mode    = verbose_mode;

	if (target != LOG_TARGET_NONE)
		log_target_registry[_log.target]->open(verbose_mode);
}

log_t *log_init_with_handle(log_target_t target, int verbose_mode)
{
	log_init(target, verbose_mode);
	_log.handle_required = 1;

	return &_log;
}

void log_change_target(log_t *log, log_target_t new_target)
{
	if (!log || log->target == new_target)
		return;

	if (log->target != LOG_TARGET_NONE)
		log_target_registry[log->target]->close();
	if (new_target != LOG_TARGET_NONE)
		log_target_registry[new_target]->open(log->verbose_mode);

	log->target = new_target;
}

void log_voutput(log_t *log, struct log_ctx *ctx, const char *format, va_list ap)
{
	static int log_ignored = 0;
	int        orig_errno  = errno;

	if (_log.handle_required && (log != &_log)) {
		if (!log_ignored) {
			log_voutput(&_log,
			            &((struct log_ctx) {.level_id = LOG_ERR,
			                                .class_id = LOG_CLASS_UNCLASSIFIED,
			                                .prefix   = "",
			                                .errno_id = 0,
			                                .src_file = ctx->src_file,
			                                .src_line = ctx->src_line,
			                                .src_func = ctx->src_func}),
			            INTERNAL_ERROR "Incorrect or missing log handle, skipping log messages.",
			            ap);
			log_ignored = 1;
		}
		goto out;
	}

	if (_log.target == LOG_TARGET_NONE)
		return;

	if (ctx->errno_id < 0)
		ctx->errno_id = -ctx->errno_id;

	log_target_registry[_log.target]->output(ctx, format, ap);
out:
	errno = orig_errno;
}

void log_output(log_t *log, struct log_ctx *ctx, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	log_voutput(log, ctx, format, ap);
	va_end(ap);
}
