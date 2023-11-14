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

#include "internal/comp-attrs.h"

#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct log log_t;

typedef enum {
	LOG_TARGET_NONE,
	LOG_TARGET_STANDARD,
	LOG_TARGET_SYSLOG,
	LOG_TARGET_JOURNAL,
	_LOG_TARGET_COUNT
} log_target_t;

struct log_ctx {
	int         level_id;
	int         class_id;
	const char *prefix;
	int         errno_id;
	const char *src_file;
	int         src_line;
	const char *src_func;
};

struct log_target {
	const char *name;
	void (*open)(int verbose_mode);
	void (*close)(void);
	void (*output)(const struct log_ctx *ctx, const char *format, va_list ap);
};

extern const struct log_target log_target_standard;
extern const struct log_target log_target_syslog;
extern const struct log_target log_target_journal;

void   log_init(log_target_t target, int verbose_mode);
log_t *log_init_with_handle(log_target_t target, int verbose_mode);
void   log_change_target(log_target_t new_target);

__format_printf(3, 4) void log_output(log_t *log, struct log_ctx *ctx, const char *format, ...);

#define LOG_CLASS_UNCLASSIFIED 0x0001

#define LOG_PRINT              LOG_LOCAL0

#define LOG_LINE(h, l, p, e, ...)                                                                                                  \
	log_output(h,                                                                                                              \
	           &((struct log_ctx) {.level_id = l,                                                                              \
	                               .prefix   = p,                                                                              \
	                               .class_id = LOG_CLASS_UNCLASSIFIED,                                                         \
	                               .errno_id = e,                                                                              \
	                               .src_file = __FILE__,                                                                       \
	                               .src_line = __LINE__,                                                                       \
	                               .src_func = __func__}),                                                                     \
	           __VA_ARGS__)

#define log_debug(p, ...)          LOG_LINE(NULL, LOG_DEBUG, p, 0, __VA_ARGS__)
#define log_info(p, ...)           LOG_LINE(NULL, LOG_INFO, p, 0, __VA_ARGS__)
#define log_notice(p, ...)         LOG_LINE(NULL, LOG_NOTICE, p, 0, __VA_ARGS__)
#define log_warning(p, ...)        LOG_LINE(NULL, LOG_WARNING, p, 0, __VA_ARGS__)
#define log_error(p, ...)          LOG_LINE(NULL, LOG_ERR, p, 0, __VA_ARGS__)
#define log_print(p, ...)          LOG_LINE(NULL, LOG_PRINT, p, 0, __VA_ARGS__)
#define log_error_errno(p, e, ...) LOG_LINE(NULL, LOG_ERR, p, e, __VA_ARGS__)
#define log_sys_error(p, x, y)     log_error_errno(p, errno, "%s%s%s failed", y, *y ? ": " : "", x)

#define INTERNAL_ERROR             "Internal error: "

#ifdef __cplusplus
}
#endif

#endif
