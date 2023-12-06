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
#include "internal/list.h"

#include <stdlib.h>
#include <string.h>

#define SERVICE_READY_LINE            "READY=1\n"
#define SERVICE_RELOADING_LINE        "RELOADING=1\n"
#define SERVICE_STOPPING_LINE         "STOPPING=1\n"
#define SERVICE_WATCHDOG_REFRESH_LINE "WATCHDOG=1\n"
#define SERVICE_WATCHDOG_TRIGGER_LINE "WATCHDOG=trigger\n"

#define EQ                            "="

struct service_link {
	struct list                 list;
	struct service_link_group  *group;
	const char                 *name;
	service_link_type_t         type;
	service_link_notification_t notification;
	service_link_flags_t        flags;
	void                       *data;
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

	if (!(sl->name = strdup(name))) {
		free(sl);
		return NULL;
	}

	sl->group        = NULL;
	sl->type         = type;
	sl->flags        = SERVICE_FLAG_NONE;
	sl->data         = NULL;
	sl->notification = SERVICE_NOTIFICATION_NONE;
	list_init(&sl->list);

	return sl;
}

struct service_link *service_link_clone(struct service_link *sl, const char *name)
{
	struct service_link *sl_clone;

	if (!(sl_clone = malloc(sizeof(*sl))))
		return NULL;

	if (!name)
		name = sl->name;

	if (!(sl_clone->name = strdup(name))) {
		free(sl_clone);
		return NULL;
	}

	sl_clone->group        = NULL;
	sl_clone->type         = sl->type;
	sl_clone->flags        = sl->flags;
	sl_clone->data         = sl->data;
	sl_clone->notification = sl->notification;
	list_init(&sl_clone->list);

	return sl_clone;
}

void service_link_destroy(struct service_link *sl)
{
	if (sl->group)
		service_link_group_remove_member(sl->group, sl);

	free((void *) sl->name);
	free(sl);
}

void service_link_set_flags(struct service_link *sl, service_link_flags_t flags)
{
	sl->flags = flags;
}

void service_link_set_data(struct service_link *sl, void *data)
{
	sl->data = data;
}

void service_link_add_notification(struct service_link *sl, service_link_notification_t notification)
{
	sl->notification |= notification;
}

void service_link_remove_notification(struct service_link *sl, service_link_notification_t notification)
{
	sl->notification &= ~notification;
}

struct service_link_group *service_link_group_create(const char *name)
{
	struct service_link_group *slg;

	if (!(slg = malloc(sizeof(*slg))))
		return NULL;

	if (!(slg->name = strdup(name))) {
		free(slg);
		return NULL;
	}

	list_init(&slg->members);

	return slg;
}

struct service_link_group *service_link_group_clone(struct service_link_group *slg, const char *name)
{
	struct service_link_group *slg_clone;
	struct service_link       *sl, *sl_clone;

	if (!slg)
		return NULL;

	if (!name)
		name = slg->name;

	if (!(slg_clone = service_link_group_create(name)))
		return NULL;

	list_iterate_items (sl, &slg->members) {
		if (!(sl->flags & SERVICE_FLAG_CLONEABLE))
			continue;

		if (!(sl_clone = service_link_clone(sl, NULL)))
			goto fail;

		service_link_group_add_member(slg_clone, sl_clone);
	}

	return slg_clone;
fail:
	service_link_group_destroy_with_members(slg_clone);
	return NULL;
}

void service_link_group_destroy(struct service_link_group *slg)
{
	struct service_link *sl, *tmp_sl;

	list_iterate_items_safe (sl, tmp_sl, &slg->members) {
		list_del(&sl->list);
		sl->group = NULL;
	}

	free((void *) slg->name);
	free(slg);
}

void service_link_group_destroy_with_members(struct service_link_group *slg)
{
	struct service_link *sl, *tmp_sl;

	list_iterate_items_safe (sl, tmp_sl, &slg->members)
		service_link_destroy(sl);

	free((void *) slg->name);
	free(slg);
}

void service_link_group_add_member(struct service_link_group *slg, struct service_link *sl)
{
	list_add(&slg->members, &sl->list);
	sl->group = slg;
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
			str   += strlen(key_eq);
			*size  = line_end - str;
			return str;
		}
	}
out:
	*size = 0;
	return NULL;
}

static int _notify_systemd(struct service_link        *sl,
                           service_link_notification_t notification,
                           log_req_t                  *log_req,
                           const char                 *fmt,
                           va_list                     ap)
{
	struct sid_buffer *buf = NULL, *fmt_buf = NULL;
	const char        *arg_str, *arg_value;
	size_t             size;
	int                unset = 0;
	int                r     = 0;

	if (!(buf = sid_buffer_create(&((struct sid_buffer_spec) {.backend = SID_BUFFER_BACKEND_MALLOC,
	                                                          .type    = SID_BUFFER_TYPE_LINEAR,
	                                                          .mode    = SID_BUFFER_MODE_PLAIN}),
	                              &((struct sid_buffer_init) {.size = 0, .alloc_step = 1, .limit = 0}),
	                              &r)))
		goto out;

	if (fmt && *fmt) {
		if (!(fmt_buf = sid_buffer_create(&((struct sid_buffer_spec) {.backend = SID_BUFFER_BACKEND_MALLOC,
		                                                              .type    = SID_BUFFER_TYPE_LINEAR,
		                                                              .mode    = SID_BUFFER_MODE_PLAIN}),
		                                  &((struct sid_buffer_init) {.size = 0, .alloc_step = 1, .limit = 0}),
		                                  &r)))
			goto out;

		if ((r = sid_buffer_vfmt_add(fmt_buf, (const void **) &arg_str, NULL, fmt, ap)) < 0)
			goto out;
	} else
		arg_str = NULL;

	if (notification & SERVICE_NOTIFICATION_UNSET)
		unset = 1;

	if (notification & SERVICE_NOTIFICATION_STATUS) {
		if ((arg_value = _get_arg_value(arg_str, SERVICE_KEY_STATUS EQ, &size))) {
			if ((r = sid_buffer_fmt_add(buf, NULL, NULL, SERVICE_KEY_STATUS EQ "%.*s\n", size, arg_value)) < 0)
				goto out;

			if ((r = sid_buffer_rewind(buf, 1, SID_BUFFER_POS_REL)) < 0)
				goto out;
		}
	}

	if (notification & SERVICE_NOTIFICATION_ERRNO) {
		if ((arg_value = _get_arg_value(arg_str, SERVICE_KEY_ERRNO EQ, &size))) {
			if ((r = sid_buffer_fmt_add(buf, NULL, NULL, SERVICE_KEY_ERRNO EQ "%.*s\n", size, arg_value)) < 0)
				goto out;

			if ((r = sid_buffer_rewind(buf, 1, SID_BUFFER_POS_REL)) < 0)
				goto out;
		}
	}

	if (notification & SERVICE_NOTIFICATION_READY)
		if ((r = sid_buffer_add(buf, (void *) SERVICE_READY_LINE, sizeof(SERVICE_READY_LINE) - 1, NULL, NULL)) < 0)
			goto out;

	if (notification & SERVICE_NOTIFICATION_RELOADING)
		if ((r = sid_buffer_add(buf, (void *) SERVICE_RELOADING_LINE, sizeof(SERVICE_RELOADING_LINE) - 1, NULL, NULL)) < 0)
			goto out;

	if (notification & SERVICE_NOTIFICATION_STOPPING)
		if ((r = sid_buffer_add(buf, (void *) SERVICE_STOPPING_LINE, sizeof(SERVICE_STOPPING_LINE) - 1, NULL, NULL)) < 0)
			goto out;

	if (notification & SERVICE_NOTIFICATION_WATCHDOG_REFRESH)
		if ((r = sid_buffer_add(buf,
		                        (void *) SERVICE_WATCHDOG_REFRESH_LINE,
		                        sizeof(SERVICE_WATCHDOG_REFRESH_LINE) - 1,
		                        NULL,
		                        NULL)) < 0)
			goto out;

	if (notification & SERVICE_NOTIFICATION_WATCHDOG_TRIGGER)
		if ((r = sid_buffer_add(buf,
		                        (void *) SERVICE_WATCHDOG_TRIGGER_LINE,
		                        sizeof(SERVICE_WATCHDOG_TRIGGER_LINE) - 1,
		                        NULL,
		                        NULL)) < 0)
			goto out;

	/* NULL termintate string, or create empty string */
	if ((r = sid_buffer_add(buf, (void *) "", 1, NULL, NULL)) < 0)
		goto out;

	sid_buffer_get_data(buf, (const void **) &arg_str, &size);

	r = sd_notify(unset, arg_str);
out:
	if (fmt_buf)
		sid_buffer_destroy(fmt_buf);
	if (buf)
		sid_buffer_destroy(buf);

	return r;
}

static int _notify_logger(struct service_link        *sl,
                          service_link_notification_t notification,
                          log_req_t                  *log_req,
                          const char                 *fmt,
                          va_list                     ap)
{
	switch (notification) {
		case SERVICE_NOTIFICATION_MESSAGE:
			log_voutput((log_t *) sl->data, log_req, fmt, ap);
			break;
		case SERVICE_NOTIFICATION_STATUS:
			// TODO: add output
			break;
		case SERVICE_NOTIFICATION_ERRNO:
			// TODO: add output
			break;
		case SERVICE_NOTIFICATION_READY:
			log_output((log_t *) sl->data, log_req, "| READY |");
			break;
		case SERVICE_NOTIFICATION_RELOADING:
			log_output((log_t *) sl->data, log_req, "| RELOADING |");
			break;
		case SERVICE_NOTIFICATION_STOPPING:
			log_output((log_t *) sl->data, log_req, "| STOPPING |");
			break;
		case SERVICE_NOTIFICATION_WATCHDOG_REFRESH:
			log_output((log_t *) sl->data, log_req, "| WATCHDOG_REFRESH |");
			break;
		case SERVICE_NOTIFICATION_WATCHDOG_TRIGGER:
			log_output((log_t *) sl->data, log_req, "| WATCHDOG_TRIGGER |");
			break;
		case SERVICE_NOTIFICATION_NONE:
		case SERVICE_NOTIFICATION_UNSET:
			break;
	}

	return 0;
}

static int _do_service_link_notify(struct service_link        *sl,
                                   struct service_link_group  *slg,
                                   service_link_notification_t notification,
                                   log_req_t                  *log_req,
                                   const char                 *fmt,
                                   va_list                     ap)
{
	int iter_r = 0, r = 0;

	if (sl) {
		if (sl->notification & notification) {
			switch (sl->type) {
				case SERVICE_TYPE_SYSTEMD:
					r = _notify_systemd(sl, notification, log_req, fmt, ap);
					break;
				case SERVICE_TYPE_LOGGER:
					r = _notify_logger(sl, notification, log_req, fmt, ap);
					break;
				case SERVICE_TYPE_NONE:
					break;
			}
		}
	} else if (slg) {
		list_iterate_items (sl, &slg->members) {
			if (!(sl->notification & notification))
				continue;

			switch (sl->type) {
				case SERVICE_TYPE_SYSTEMD:
					iter_r = _notify_systemd(sl, notification, log_req, fmt, ap);
					break;
				case SERVICE_TYPE_LOGGER:
					iter_r = _notify_logger(sl, notification, log_req, fmt, ap);
					break;
				case SERVICE_TYPE_NONE:
					break;
			}

			if (iter_r < 0)
				r = iter_r;
		}
	}

	return r;
}

int service_link_vnotify(struct service_link        *sl,
                         service_link_notification_t notification,
                         log_req_t                  *log_req,
                         const char                 *fmt,
                         va_list                     ap)
{
	return _do_service_link_notify(sl, NULL, notification, log_req, fmt, ap);
}

int service_link_notify(struct service_link *sl, service_link_notification_t notification, log_req_t *log_req, const char *fmt, ...)
{
	va_list ap;
	int     r;

	va_start(ap, fmt);
	r = _do_service_link_notify(sl, NULL, notification, log_req, fmt, ap);
	va_end(ap);

	return r;
}

int service_link_group_vnotify(struct service_link_group  *slg,
                               service_link_notification_t notification,
                               log_req_t                  *log_req,
                               const char                 *fmt,
                               va_list                     ap)
{
	return _do_service_link_notify(NULL, slg, notification, log_req, fmt, ap);
}

int service_link_group_notify(struct service_link_group  *slg,
                              service_link_notification_t notification,
                              log_req_t                  *log_req,
                              const char                 *fmt,
                              ...)
{
	va_list ap;
	int     r;

	va_start(ap, fmt);
	r = _do_service_link_notify(NULL, slg, notification, log_req, fmt, ap);
	va_end(ap);

	return r;
}
