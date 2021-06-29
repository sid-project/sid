/*
 * This file is part of SID.
 *
 * Copyright (C) 2019 Red Hat, Inc. All rights reserved.
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

#include "iface/service-link.h"

#include "base/buffer.h"
#include "base/list.h"

#include <stdlib.h>
#include <string.h>

#define SERVICE_READY_LINE            "READY=1\n"
#define SERVICE_RELOADING_LINE        "RELOADING=1\n"
#define SERVICE_STOPPING_LINE         "STOPPING=1\n"
#define SERVICE_WATCHDOG_REFRESH_LINE "WATCHDOG=1\n"
#define SERVICE_WATCHDOG_TRIGGER_LINE "WATCHDOG=trigger\n"

#define EQ "="

struct service_link {
	struct list                 list;
	struct service_link_group * group;
	const char *                name;
	service_link_type_t         type;
	service_link_notification_t notification;
};

struct service_link_group {
	const char *name;
	struct list members;
};

struct service_link *service_link_create(service_link_type_t type, const char *name)
{
	struct service_link *sl;

	if (!(sl = malloc(sizeof(*sl))))
		return NULL;

	list_init(&sl->list);
	sl->group        = NULL;
	sl->name         = name;
	sl->type         = type;
	sl->notification = SERVICE_NOTIFICATION_NONE;

	return sl;
}

void service_link_destroy(struct service_link *sl)
{
	if (sl->group)
		service_link_group_remove_member(sl->group, sl);

	free(sl);
}

int service_link_add_notification(struct service_link *sl, service_link_notification_t notification)
{
	sl->notification |= notification;
	return 0;
}

int service_link_remove_notification(struct service_link *sl, service_link_notification_t notification)
{
	sl->notification &= ~notification;
	return 0;
}

struct service_link_group *service_link_group_create(const char *name)
{
	struct service_link_group *slg;

	if (!(slg = malloc(sizeof(*slg))))
		return NULL;

	slg->name = name;
	list_init(&slg->members);

	return slg;
}

void service_link_group_destroy(struct service_link_group *slg)
{
	struct service_link *sl, *tmp_sl;

	list_iterate_items_safe (sl, tmp_sl, &slg->members)
		list_del(&sl->list);

	free(slg);
}

void service_link_group_destroy_with_members(struct service_link_group *slg)
{
	struct service_link *sl, *tmp_sl;

	list_iterate_items_safe (sl, tmp_sl, &slg->members)
		service_link_destroy(sl);

	free(slg);
}

int service_link_group_add_member(struct service_link_group *slg, struct service_link *sl)
{
	list_add(&slg->members, &sl->list);
	sl->group = slg;

	return 0;
}

int service_link_group_remove_member(struct service_link_group *slg, struct service_link *sl)
{
	if (sl->group != slg)
		return -EINVAL;

	list_del(&sl->list);
	sl->group = NULL;

	return 0;
}

static const char *_get_arg_value(const char *str, const char *key_eq, size_t *size)
{
	const char *str_end;
	const char *line_end;

	if (!size)
		return NULL;
	if (!str || !key_eq)
		goto out;

	for (str_end = str + strlen(str); str < str_end; str = line_end + 1) {
		line_end = strchr(str, '\n') ?: str_end;

		if (!strncmp(key_eq, str, strlen(key_eq))) {
			/* get the value and its size */
			str += strlen(key_eq);
			*size = line_end - str;
			return str;
		}
	}
out:
	*size = 0;
	return NULL;
}

/*
 * FIXME: For now, we have notification for systemd only, but to support more types,
 * 	  we need to separate this function into distinct functions per each type.
 */
int _do_service_link_notify(struct service_link *       sl,
                            struct service_link_group * slg,
                            service_link_notification_t notification,
                            const char *                fmt,
                            va_list                     ap)
{
	struct buffer *buf = NULL, *fmt_buf = NULL;
	const char *   arg_str, *arg_value;
	size_t         size;
	int            unset = 0;
	int            iter_r, r = 0;

	if (!(buf = sid_buffer_create(&((struct buffer_spec) {.backend = BUFFER_BACKEND_MALLOC,
	                                                      .type    = BUFFER_TYPE_LINEAR,
	                                                      .mode    = BUFFER_MODE_PLAIN}),
	                              &((struct buffer_init) {.size = 0, .alloc_step = 1, .limit = 0}),
	                              &r)))
		goto out;

	if (fmt && *fmt) {
		if (!(fmt_buf = sid_buffer_create(&((struct buffer_spec) {.backend = BUFFER_BACKEND_MALLOC,
		                                                          .type    = BUFFER_TYPE_LINEAR,
		                                                          .mode    = BUFFER_MODE_PLAIN}),
		                                  &((struct buffer_init) {.size = 0, .alloc_step = 1, .limit = 0}),
		                                  &r)))
			goto out;

		if (!(arg_str = sid_buffer_vfmt_add(fmt_buf, &r, fmt, ap)))
			goto out;
	} else
		arg_str = NULL;

	if (notification & SERVICE_NOTIFICATION_UNSET)
		unset = 1;

	if (notification & SERVICE_NOTIFICATION_STATUS) {
		if ((arg_value = _get_arg_value(arg_str, SERVICE_KEY_STATUS EQ, &size))) {
			if (!sid_buffer_fmt_add(buf, &r, SERVICE_KEY_STATUS EQ "%.*s\n", size, arg_value))
				goto out;

			if ((r = sid_buffer_rewind(buf, 1, BUFFER_POS_REL)) < 0)
				goto out;
		}
	}

	if (notification & SERVICE_NOTIFICATION_ERRNO) {
		if ((arg_value = _get_arg_value(arg_str, SERVICE_KEY_ERRNO EQ, &size))) {
			if (!sid_buffer_fmt_add(buf, &r, SERVICE_KEY_ERRNO EQ "%.*s\n", size, arg_value))
				goto out;

			if ((r = sid_buffer_rewind(buf, 1, BUFFER_POS_REL)) < 0)
				goto out;
		}
	}

	if (notification & SERVICE_NOTIFICATION_READY)
		if (!sid_buffer_add(buf, (void *) SERVICE_READY_LINE, sizeof(SERVICE_READY_LINE) - 1, &r))
			goto out;

	if (notification & SERVICE_NOTIFICATION_RELOADING)
		if (!sid_buffer_add(buf, (void *) SERVICE_RELOADING_LINE, sizeof(SERVICE_RELOADING_LINE) - 1, &r))
			goto out;

	if (notification & SERVICE_NOTIFICATION_STOPPING)
		if (!sid_buffer_add(buf, (void *) SERVICE_STOPPING_LINE, sizeof(SERVICE_STOPPING_LINE) - 1, &r))
			goto out;

	if (notification & SERVICE_NOTIFICATION_WATCHDOG_REFRESH)
		if (!sid_buffer_add(buf, (void *) SERVICE_WATCHDOG_REFRESH_LINE, sizeof(SERVICE_WATCHDOG_REFRESH_LINE) - 1, &r))
			goto out;

	if (notification & SERVICE_NOTIFICATION_WATCHDOG_TRIGGER)
		if (!sid_buffer_add(buf, (void *) SERVICE_WATCHDOG_TRIGGER_LINE, sizeof(SERVICE_WATCHDOG_TRIGGER_LINE) - 1, &r))
			goto out;

	/* NULL termintate string, or create empty string */
	if (!sid_buffer_add(buf, (void *) "", 1, &r))
		goto out;

	sid_buffer_get_data(buf, (const void **) &arg_str, &size);

	if (sl) {
		if (!(sl->notification & notification))
			goto out;
		r = sd_notify(unset, arg_str);
	} else if (slg) {
		list_iterate_items (sl, &slg->members) {
			if (!(sl->notification & notification))
				continue;
			if ((iter_r = sd_notify(unset, arg_str)) < 0)
				r = iter_r;
		}
	}
out:
	if (fmt_buf)
		sid_buffer_destroy(fmt_buf);
	if (buf)
		sid_buffer_destroy(buf);

	return r;
}

int service_link_notify(struct service_link *sl, service_link_notification_t notification, const char *fmt, ...)
{
	va_list ap;
	int     r;

	va_start(ap, fmt);
	r = _do_service_link_notify(sl, NULL, notification, fmt, ap);
	va_end(ap);

	return r;
}

int service_link_group_notify(struct service_link_group *slg, service_link_notification_t notification, const char *fmt, ...)
{
	va_list ap;
	int     r;

	va_start(ap, fmt);
	r = _do_service_link_notify(NULL, slg, notification, fmt, ap);
	va_end(ap);

	return r;
}
