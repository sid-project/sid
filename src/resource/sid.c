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
#include "base/mem.h"
#include "log/log.h"
#include "resource/resource.h"

#define SID_NAME "sid"

static int _init_sid(sid_resource_t *res, const void *kickstart_data, void **data)
{
	sigset_t sig_set;

	if (sigemptyset(&sig_set) < 0) {
		log_sys_error(ID(res), "sigemptyset", "");
		goto fail;
	}

	if (sigaddset(&sig_set, SIGTERM) < 0 ||
	    sigaddset(&sig_set, SIGINT) < 0) {
		log_sys_error(ID(res), "siggaddset", "");
		goto fail;
	}

	if (sigprocmask(SIG_BLOCK, &sig_set, NULL) < 0) {
		log_sys_error(ID(res), "sigprocmask", "");
		goto fail;
	}

	if (sid_resource_create_signal_event_source(res, NULL, SIGTERM, NULL, 0, "sigterm", NULL) < 0 ||
	    sid_resource_create_signal_event_source(res, NULL, SIGINT, NULL, 0, "sigint", NULL) < 0) {
		log_error(ID(res), "Failed to create signal handlers.");
		goto fail;
	}

	if (!sid_resource_create(res,
	                         &sid_resource_type_ubridge,
	                         SID_RESOURCE_RESTRICT_WALK_UP,
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
	.name = SID_NAME,
	.with_event_loop = 1,
	.with_watchdog = 1,
	.init = _init_sid,
};
