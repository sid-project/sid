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
	log_target_t target;
	int          verbose_mode;
} _log                                                = {LOG_TARGET_NONE, 0};

static const struct log_target *log_target_registry[] = {[LOG_TARGET_STANDARD] = &log_target_standard,
                                                         [LOG_TARGET_SYSLOG]   = &log_target_syslog,
                                                         [LOG_TARGET_JOURNAL]  = &log_target_journal};

void log_init(log_target_t target, int verbose_mode)
{
	_log.target       = target;
	_log.verbose_mode = verbose_mode;

	if (_log.target != LOG_TARGET_NONE)
		log_target_registry[_log.target]->open(verbose_mode);
}

void log_change_target(log_target_t new_target)
{
	if (_log.target == new_target)
		return;

	if (_log.target != LOG_TARGET_NONE)
		log_target_registry[_log.target]->close();
	if (new_target != LOG_TARGET_NONE)
		log_target_registry[new_target]->open(_log.verbose_mode);

	_log.target = new_target;
}

void log_output(struct log_ctx *ctx, const char *format, ...)
{
	int     orig_errno;
	va_list ap;

	if (_log.target == LOG_TARGET_NONE)
		return;

	if (ctx->errno_id < 0)
		ctx->errno_id = -ctx->errno_id;

	orig_errno = errno;
	va_start(ap, format);
	log_target_registry[_log.target]->output(ctx, format, ap);
	va_end(ap);
	errno = orig_errno;
}
