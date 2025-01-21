/*
 * SPDX-FileCopyrightText: (C) 2017-2025 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "resource/res.h"
#include "resource/ubr.h"

#include <signal.h>

static int _on_sid_signal_event(sid_res_ev_src_t *es, const struct signalfd_siginfo *si, void *arg)
{
	sid_res_t *res = arg;
	sid_res_t *ubridge_res;

	switch (si->ssi_signo) {
		case SIGTERM:
		case SIGINT:
			sid_res_ev_loop_exit(res);
			break;
		case SIGPIPE:
			break;
		case SIGHUP: /* TODO: Reload config on SIGHUP? */
			break;
		case SIGUSR1:
			if ((ubridge_res = sid_res_search(res, SID_RES_SEARCH_IMM_DESC, &sid_res_type_ubr, NULL)))
				(void) sid_ubr_cmd_dbdump(ubridge_res, NULL);
		default:
			break;
	};

	return 0;
}

static int _init_sid(sid_res_t *res, const void *kickstart_data, void **data)
{
	sigset_t mask;

	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		sid_res_log_error(res, "Failed to block SIGCHLD signal.");
		goto fail;
	}

	sigemptyset(&mask);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGPIPE);
	sigaddset(&mask, SIGHUP);
	sigaddset(&mask, SIGUSR1);

	if (sid_res_ev_create_signal(res, NULL, mask, _on_sid_signal_event, 0, "signal_handler", res) < 0) {
		sid_res_log_error(res, "Failed to create signal handlers.");
		goto fail;
	}

	if (!sid_res_create(res,
	                    &sid_res_type_ubr,
	                    SID_RES_FL_NONE,
	                    SID_RES_NO_CUSTOM_ID,
	                    SID_RES_NO_PARAMS,
	                    SID_RES_PRIO_NORMAL,
	                    SID_RES_NO_SERVICE_LINKS)) {
		sid_res_log_error(res, "Failed to create udev bridge interface.");
		goto fail;
	}

	return 0;
fail:
	return -1;
}

const sid_res_type_t sid_res_type_sid = {
	.name            = "Storage Instantiation Daemon",
	.short_name      = "sid",
	.description     = "Top level resource representing Storage Instantiation Daemon.",
	.with_event_loop = 1,
	.with_watchdog   = 1,
	.init            = _init_sid,
};
