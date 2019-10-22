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

#include "log.h"

static log_target_t _current_target = LOG_TARGET_NONE;
static int _current_verbose_mode = 0;

static const struct log_target *log_target_registry[] = {
	[LOG_TARGET_STANDARD] = &log_target_standard,
	[LOG_TARGET_SYSLOG] = &log_target_syslog
};

void log_init(log_target_t target, int verbose_mode)
{
	_current_target = target;
	_current_verbose_mode = verbose_mode;
	log_target_registry[_current_target]->open(verbose_mode);
}

void log_change_target(log_target_t new_target)
{
	if (_current_target == new_target)
		return;

	if (_current_target != LOG_TARGET_NONE)
		log_target_registry[_current_target]->close();
	if (new_target != LOG_TARGET_NONE)
		log_target_registry[new_target]->open(_current_verbose_mode);

	_current_target = new_target;
}

void log_output(int level_id, const char *prefix, int class_id, int errno_id,
                const char *file_name, int line_number, const char *function_name,
                const char *format, ...)
{
	int orig_errno;
	va_list ap;

	if (_current_target == LOG_TARGET_NONE)
		return;

	orig_errno = errno;
	va_start(ap, format);
	log_target_registry[_current_target]->output(level_id,
	                                             prefix,
	                                             class_id,
	                                             errno_id,
	                                             file_name,
	                                             line_number,
	                                             function_name,
	                                             format, ap);
	va_end(ap);
	errno = orig_errno;
}
