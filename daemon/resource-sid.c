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

#include "buffer.h"
#include "list.h"
#include "log.h"
#include "mem.h"
#include "resource.h"

#define SID_NAME "sid"

struct sid_data {
	sid_event_source *sigint_es;
	sid_event_source *sigterm_es;
};

static int _init_sid(sid_resource_t *res, const void *kickstart_data, void **data)
{
	struct sid_data *sid;
	sigset_t sig_set;

	if (!(sid = zalloc(sizeof(*sid)))) {
		log_error(ID(res), "Failed to allocate %s structure.", SID_NAME);
		goto fail;
	}

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

	if (sid_resource_create_signal_event_source(res, &sid->sigterm_es, SIGTERM, NULL, NULL, NULL) < 0 ||
	    sid_resource_create_signal_event_source(res, &sid->sigint_es, SIGINT, NULL, NULL, NULL) < 0) {
		log_error(ID(res), "Failed to create signal handlers.");
		goto fail;
	}

	if (!sid_resource_create(res, &sid_resource_type_ubridge, SID_RESOURCE_RESTRICT_WALK_UP, NULL, NULL)) {
		log_error(ID(res), "Failed to create udev bridge interface.");
		goto fail;
	}

	*data = sid;
	return 0;
fail:
	if (sid) {
		if (sid->sigterm_es)
			(void) sid_resource_destroy_event_source(res, &sid->sigterm_es);
		if (sid->sigint_es)
			(void) sid_resource_destroy_event_source(res, &sid->sigint_es);
		free(sid);
	}
	return -1;
}

static int _destroy_sid(sid_resource_t *res)
{
	struct sid_data *sid = sid_resource_get_data(res);

	(void) sid_resource_destroy_event_source(res, &sid->sigterm_es);
	(void) sid_resource_destroy_event_source(res, &sid->sigint_es);

	free(sid);
	return 0;
}

const sid_resource_type_t sid_resource_type_sid = {
	.name = SID_NAME,
	.with_event_loop = 1,
	.with_watchdog = 1,
	.init = _init_sid,
	.destroy = _destroy_sid,
};
