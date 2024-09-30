/*
 * SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _SID_LOG_H
#define _SID_LOG_H

#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sid_log sid_log_t;

typedef enum {
	SID_LOG_TGT_NONE,
	SID_LOG_TGT_STANDARD,
	SID_LOG_TGT_SYSLOG,
	SID_LOG_TGT_JOURNAL,
} sid_log_tgt_t;

typedef struct sid_log_pfx sid_log_pfx_t;

typedef struct sid_log_pfx {
	const char    *s;
	sid_log_pfx_t *n;
} sid_log_pfx_t;

typedef struct sid_log_ctx {
	int         level_id;
	int         errno_id;
	const char *src_file;
	int         src_line;
	const char *src_func;
} sid_log_ctx_t;

typedef struct sid_log_req {
	sid_log_pfx_t *pfx;
	sid_log_ctx_t *ctx;
} sid_log_req_t;

struct sid_log_tgt {
	const char *name;
	void (*open)(int verbose_mode);
	void (*close)(void);
	void (*output)(const sid_log_req_t *req, const char *format, va_list ap);
};

extern const struct sid_log_tgt log_target_standard;
extern const struct sid_log_tgt log_target_syslog;
extern const struct sid_log_tgt log_target_journal;

void       sid_log_init(sid_log_tgt_t target, int verbose_mode);
sid_log_t *sid_log_init_with_handle(sid_log_tgt_t target, int verbose_mode);
void       sid_log_close(sid_log_t *log);
void       sid_log_change_tgt(sid_log_t *log, sid_log_tgt_t new_target);
void       sid_log_set_pfx(sid_log_t *log, const char *prefix);

__attribute__((format(printf, 3, 4))) void sid_log_output(sid_log_t *log, sid_log_req_t *req, const char *format, ...);
void                                       sid_log_voutput(sid_log_t *log, sid_log_req_t *req, const char *format, va_list ap);

#define SID_LOG_PRINT LOG_LOCAL0

#define SID_LOG_LINE(h, l, p, e, ...)                                                                                              \
	sid_log_output(h,                                                                                                          \
	               &(struct sid_log_req) {.pfx = p ? &(sid_log_pfx_t) {.s = p, .n = NULL} : NULL,                              \
	                                      .ctx = &((sid_log_ctx_t) {.level_id = l,                                             \
	                                                                .errno_id = e,                                             \
	                                                                .src_file = __FILE__,                                      \
	                                                                .src_line = __LINE__,                                      \
	                                                                .src_func = __func__})},                                   \
	               __VA_ARGS__)

#define sid_log_debug(p, ...)              SID_LOG_LINE(NULL, LOG_DEBUG, p, 0, __VA_ARGS__)
#define sid_log_info(p, ...)               SID_LOG_LINE(NULL, LOG_INFO, p, 0, __VA_ARGS__)
#define sid_log_notice(p, ...)             SID_LOG_LINE(NULL, LOG_NOTICE, p, 0, __VA_ARGS__)
#define sid_log_warning(p, ...)            SID_LOG_LINE(NULL, LOG_WARNING, p, 0, __VA_ARGS__)
#define sid_log_error(p, ...)              SID_LOG_LINE(NULL, LOG_ERR, p, 0, __VA_ARGS__)
#define sid_log_print(p, ...)              SID_LOG_LINE(NULL, SID_LOG_PRINT, p, 0, __VA_ARGS__)
#define sid_log_error_errno(p, e, ...)     SID_LOG_LINE(NULL, LOG_ERR, p, e, __VA_ARGS__)
#define sid_log_sys_error(p, x, y)         log_error_errno(p, errno, "%s%s%s failed", y, *y ? ": " : "", x)

#define sid_log_hdebug(h, p, ...)          SID_LOG_LINE(h, LOG_DEBUG, p, 0, __VA_ARGS__)
#define sid_log_hinfo(h, p, ...)           SID_LOG_LINE(h, LOG_INFO, p, 0, __VA_ARGS__)
#define sid_log_hnotice(h, p, ...)         SID_LOG_LINE(h, LOG_NOTICE, p, 0, __VA_ARGS__)
#define sid_log_hwarning(h, p, ...)        SID_LOG_LINE(h, LOG_WARNING, p, 0, __VA_ARGS__)
#define sid_log_herror(h, p, ...)          SID_LOG_LINE(h, LOG_ERR, p, 0, __VA_ARGS__)
#define sid_log_hprint(h, p, ...)          SID_LOG_LINE(h, SID_LOG_PRINT, p, 0, __VA_ARGS__)
#define sid_log_herror_errno(h, p, e, ...) SID_LOG_LINE(h, LOG_ERR, p, e, __VA_ARGS__)
#define sid_log_hsys_error(h, p, x, y)     sid_log_herror_errno(h, p, errno, "%s%s%s failed", y, *y ? ": " : "", x)

#define SID_INTERNAL_ERROR                 "Internal error: "

#ifdef __cplusplus
}
#endif

#endif
