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

#ifndef _SID_LOG_H
#define _SID_LOG_H

#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>

typedef enum {
	LOG_TARGET_NONE,
	LOG_TARGET_STANDARD,
	LOG_TARGET_SYSLOG,
	_LOG_TARGET_COUNT
} log_target_t;

struct log_target {
	const char *name;
	void (*open) (int verbose_mode);
	void (*close) (void);
	void (*output) (int level_id,
			const char *prefix,
			int class_id,
			int errno_id,
			const char *src_file_name,
			int src_line_number,
			const char *function_name,
			const char *format,
			va_list ap);
};

extern const struct log_target log_target_standard;
extern const struct log_target log_target_syslog;

void log_init(log_target_t target, int verbose_mode);
void log_change_target(log_target_t new_target);

__attribute__ ((format(printf, 8, 9)))
void log_output(int level_id, const char *prefix, int class_id, int errno_id,
		const char *file_name, int line_number, const char *function_name,
		const char *format, ...);

#define LOG_CLASS_UNCLASSIFIED          0x0001

#define LOG_PRINT                       LOG_LOCAL0

#define LOG_LINE(l, p, c, e, ...)	log_output(l, p, c, e, __FILE__, __LINE__, __func__, __VA_ARGS__)

#define log_debug(p, ...)               LOG_LINE(LOG_DEBUG,   p, LOG_CLASS_UNCLASSIFIED, 0, __VA_ARGS__)
#define log_info(p, ...)                LOG_LINE(LOG_INFO,    p, LOG_CLASS_UNCLASSIFIED, 0, __VA_ARGS__)
#define log_notice(p, ...)              LOG_LINE(LOG_NOTICE,  p, LOG_CLASS_UNCLASSIFIED, 0, __VA_ARGS__)
#define log_warning(p, ...)             LOG_LINE(LOG_WARNING, p, LOG_CLASS_UNCLASSIFIED, 0, __VA_ARGS__)
#define log_error(p, ...)               LOG_LINE(LOG_ERR,     p, LOG_CLASS_UNCLASSIFIED, 0, __VA_ARGS__)
#define log_print(p, ...)               LOG_LINE(LOG_PRINT,   p, LOG_CLASS_UNCLASSIFIED, 0, __VA_ARGS__)
#define log_error_errno(p, e, ...)      LOG_LINE(LOG_ERR,     p, LOG_CLASS_UNCLASSIFIED, e, __VA_ARGS__)
#define log_sys_error(p, x, y)          log_error_errno(p, errno, "%s%s%s failed", y, *y ? ": " : "", x)

#define INTERNAL_ERROR                  "Internal error: "

#endif
