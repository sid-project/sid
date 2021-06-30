/*
 * This file is part of SID.
 *
 * Copyright (C) 2017-2019 Red Hat, Inc. All rights reserved.
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

#include "base/buffer.h"
#include "internal/mem.h"
#include "log/log.h"
#include "resource/resource.h"

#include <signal.h>

#define SID_NAME "sid"

static int _on_sid_signal_event(sid_resource_event_source_t *es, const struct signalfd_siginfo *si, void *arg)
{
	sid_resource_t *res = arg;

	switch (si->ssi_signo) {
		case SIGTERM:
		case SIGINT:
			sid_resource_exit_event_loop(res);
			break;
		case SIGPIPE:
			break;
		case SIGHUP: /* TODO: Reload config on SIGHUP? */
			break;
		case SIGCHLD:
			break;
		default:
			break;
	};

	return 0;
}

static int _init_sid(sid_resource_t *res, const void *kickstart_data, void **data)
{
	sigset_t mask;

	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		log_error(ID(res), "Failed to block SIGCHLD signal.");
		goto fail;
	}

	sigemptyset(&mask);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGPIPE);
	sigaddset(&mask, SIGHUP);

	if (sid_resource_create_signal_event_source(res, NULL, mask, _on_sid_signal_event, 0, "signal_handler", res) < 0) {
		log_error(ID(res), "Failed to create signal handlers.");
		goto fail;
	}

	if (!sid_resource_create(res,
	                         &sid_resource_type_ubridge,
	                         SID_RESOURCE_NO_FLAGS,
	                         SID_RESOURCE_NO_CUSTOM_ID,
	                         SID_RESOURCE_NO_PARAMS,
	                         SID_RESOURCE_PRIO_NORMAL,
	                         SID_RESOURCE_NO_SERVICE_LINKS)) {
		log_error(ID(res), "Failed to create udev bridge interface.");
		goto fail;
	}

	return 0;
fail:
	return -1;
}

const sid_resource_type_t sid_resource_type_sid = {
	.name            = SID_NAME,
	.with_event_loop = 1,
	.with_watchdog   = 1,
	.init            = _init_sid,
};
