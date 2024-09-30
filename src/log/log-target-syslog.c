/*
 * SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "log/log.h"

#include <limits.h>
#include <stdio.h>

#define SID_SYSLOG_IDENT "sid"

static int _max_level_id = -1;

static void _log_syslog_open(int verbose_mode)
{
	switch (verbose_mode) {
		case 0:
			_max_level_id = LOG_NOTICE;
			break;
		case 1:
			_max_level_id = LOG_INFO;
			break;
		default:
			_max_level_id = LOG_DEBUG;
			break;
	}

	openlog(SID_SYSLOG_IDENT, LOG_PID, LOG_DAEMON);
}

static void _log_syslog_close(void)
{
	closelog();
}

static void _log_syslog_output(const sid_log_req_t *req, const char *format, va_list ap)
{
	char           msg[LINE_MAX];
	sid_log_pfx_t *pfx;
	size_t         printed, remaining;
	int            r;

	if (req->ctx->level_id > _max_level_id)
		return;

	for (printed = 0, remaining = sizeof(msg), pfx = req->pfx; pfx; pfx = pfx->n) {
		r = snprintf(msg, sizeof(msg), "<%s> ", pfx->s ?: "");

		if (r >= remaining) {
			syslog(req->ctx->level_id, SID_INTERNAL_ERROR "%s: (log prefix too long)", __func__);
			vsyslog(req->ctx->level_id, format, ap);
			return;
		}

		remaining -= r;
		printed   += r;
	}

	r = vsnprintf(msg + printed, remaining, format, ap);

	if (r < 0 || r >= remaining)
		syslog(req->ctx->level_id, SID_INTERNAL_ERROR "%s: (log message truncated)", __func__);

	if (r > 0)
		syslog(req->ctx->level_id, "%s", msg);
}

const struct sid_log_tgt log_target_syslog = {.name   = "syslog",
                                              .open   = _log_syslog_open,
                                              .close  = _log_syslog_close,
                                              .output = _log_syslog_output};
