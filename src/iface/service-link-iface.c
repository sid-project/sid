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

#include "buffer.h"
#include "list.h"
#include "service-link-iface.h"

#include <stdlib.h>
#include <string.h>

#define SERVICE_READY_LINE		"READY=1\n"
#define SERVICE_RELOADING_LINE		"RELOADING=1\n"
#define SERVICE_STOPPING_LINE		"STOPPING=1\n"
#define SERVICE_WATCHDOG_REFRESH_LINE	"WATCHDOG=1\n"
#define SERVICE_WATCHDOG_TRIGGER_LINE	"WATCHDOG=trigger\n"

#define EQ "="

struct service_link {
	struct list list;
	struct service_link_group *group;
	const char *name;
	service_link_type_t type;
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
	sl->group = NULL;
	sl->name = name;
	sl->type = type;
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

	list_iterate_items_safe(sl, tmp_sl, &slg->members)
	list_del(&sl->list);

	free(slg);
}

void service_link_group_destroy_with_members(struct service_link_group *slg)
{
	struct service_link *sl, *tmp_sl;

	list_iterate_items_safe(sl, tmp_sl, &slg->members)
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

static const char *_get_arg_line(const char *str, const char *key_eq, size_t *size)
{
	const char *str_end;
	const char *line_end;

	if (!size)
		return NULL;
	if (!str || !key_eq)
		goto out;

	str_end = str + strlen(str);
	for (str_end = str + strlen(str); str < str_end; str = line_end + 1) {
		line_end = strchr(str, '\n') ? : str_end;

		if (!strcmp(key_eq, str)) {
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
int _do_service_link_notify(struct service_link *sl, struct service_link_group *slg,
                            service_link_notification_t notification, const char *fmt, va_list ap)
{
	struct buffer *buf = NULL, *fmt_buf = NULL;
	const char *arg_str, *arg_line;
	size_t size;
	int unset = 0;
	int iter_r, r = 0;

	if (!(buf = buffer_create(BUFFER_TYPE_LINEAR, BUFFER_MODE_PLAIN, 0, 1))) {
		r = -ENOMEM;
		goto out;
	}

	if (fmt && *fmt) {
		if (!(fmt_buf = buffer_create(BUFFER_TYPE_LINEAR, BUFFER_MODE_PLAIN, 0, 1))) {
			r = -ENOMEM;
			goto out;
		}

		arg_str = buffer_vfmt_add(fmt_buf, fmt, ap);

		if (!arg_str) {
			r = -ENOMEM;
			goto out;
		}
	} else
		arg_str = NULL;

	if (notification & SERVICE_NOTIFICATION_UNSET)
		unset = 1;

	if (notification & SERVICE_NOTIFICATION_STATUS) {
		if ((arg_line = _get_arg_line(arg_str, SERVICE_KEY_STATUS EQ, &size)))
			if (!buffer_add(buf, (void *) arg_line, size)) {
				r = -ENOMEM;
				goto out;
			}
	}

	if (notification & SERVICE_NOTIFICATION_ERRNO) {
		if ((arg_line = _get_arg_line(arg_str, SERVICE_KEY_ERRNO EQ, &size)))
			if (!buffer_add(buf, (void *) arg_line, size)) {
				r = -ENOMEM;
				goto out;
			}
	}

	if (notification & SERVICE_NOTIFICATION_READY)
		if (!buffer_add(buf, (void *)SERVICE_READY_LINE,
		                sizeof(SERVICE_READY_LINE) - 1)) {
			r = -ENOMEM;
			goto out;
		}

	if (notification & SERVICE_NOTIFICATION_RELOADING)
		if (!buffer_add(buf, (void *)SERVICE_RELOADING_LINE,
		                sizeof(SERVICE_RELOADING_LINE) - 1)) {
			r = -ENOMEM;
			goto out;
		}

	if (notification & SERVICE_NOTIFICATION_STOPPING)
		if (!buffer_add(buf, (void *)SERVICE_STOPPING_LINE,
		                sizeof(SERVICE_STOPPING_LINE) - 1)) {
			r = -ENOMEM;
			goto out;
		}

	if (notification & SERVICE_NOTIFICATION_WATCHDOG_REFRESH)
		if (!buffer_add(buf, (void *)SERVICE_WATCHDOG_REFRESH_LINE,
		                sizeof(SERVICE_WATCHDOG_REFRESH_LINE) - 1)) {
			r = -ENOMEM;
			goto out;
		}

	if (notification & SERVICE_NOTIFICATION_WATCHDOG_TRIGGER)
		if (!buffer_add(buf, (void *)SERVICE_WATCHDOG_TRIGGER_LINE,
		                sizeof(SERVICE_WATCHDOG_TRIGGER_LINE) - 1)) {
			r = -ENOMEM;
			goto out;
		}

	/* NULL termintate string, or create empty string */
	if (!buffer_add(buf, (void *)"", 1)) {
		r = -ENOMEM;
		goto out;
	}
	buffer_get_data(buf, (const void **) &arg_str, &size);

	if (sl) {
		if (!(sl->notification & notification))
			goto out;
		r = sd_notify(unset, arg_str);
	} else if (slg) {
		list_iterate_items(sl, &slg->members) {
			if (!(sl->notification & notification))
				continue;
			if ((iter_r = sd_notify(unset, arg_str)) < 0)
				r = iter_r;
		}
	}
out:
	if (fmt_buf)
		buffer_destroy(fmt_buf);
	if (buf)
		buffer_destroy(buf);

	return r;
}

int service_link_notify(struct service_link *sl, service_link_notification_t notification, const char *fmt, ...)
{
	va_list ap;
	int r;

	va_start(ap, fmt);
	r = _do_service_link_notify(sl, NULL, notification, fmt, ap);
	va_end(ap);

	return r;
}

int service_link_group_notify(struct service_link_group *slg, service_link_notification_t notification, const char *fmt, ...)
{
	va_list ap;
	int r;

	va_start(ap, fmt);
	r = _do_service_link_notify(NULL, slg, notification, fmt, ap);
	va_end(ap);

	return r;
}
