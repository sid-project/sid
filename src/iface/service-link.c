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

struct sid_srv_lnk {
	struct list             list;
	struct sid_srv_lnk_grp *group;
	const char             *name;
	sid_srv_lnk_type_t      type;
	sid_srv_lnk_notif_t     notification;
	sid_srv_lnk_fl_t        flags;
	void                   *data;
};

struct sid_srv_lnk_grp {
	const char *name;
	struct list members;
};

struct sid_srv_lnk *sid_srv_lnk_create(sid_srv_lnk_type_t type, const char *name)
{
	struct sid_srv_lnk *sl;

	if (!(sl = malloc(sizeof(*sl))))
		return NULL;

	if (!(sl->name = strdup(name))) {
		free(sl);
		return NULL;
	}

	sl->group        = NULL;
	sl->type         = type;
	sl->flags        = SID_SRV_LNK_FL_NONE;
	sl->data         = NULL;
	sl->notification = SID_SRV_LNK_NOTIF_NONE;
	list_init(&sl->list);

	return sl;
}

struct sid_srv_lnk *sid_srv_lnk_clone(struct sid_srv_lnk *sl, const char *name)
{
	struct sid_srv_lnk *sl_clone;

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

void sid_srv_lnk_destroy(struct sid_srv_lnk *sl)
{
	if (sl->group)
		sid_srv_lnk_grp_del(sl->group, sl);

	free((void *) sl->name);
	free(sl);
}

void sid_srv_lnk_set_flags(struct sid_srv_lnk *sl, sid_srv_lnk_fl_t flags)
{
	sl->flags = flags;
}

void sid_srv_lnk_set_data(struct sid_srv_lnk *sl, void *data)
{
	sl->data = data;
}

void sid_srv_lnk_notif_add(struct sid_srv_lnk *sl, sid_srv_lnk_notif_t notification)
{
	sl->notification |= notification;
}

void sid_srv_lnk_notif_del(struct sid_srv_lnk *sl, sid_srv_lnk_notif_t notification)
{
	sl->notification &= ~notification;
}

struct sid_srv_lnk_grp *sid_srv_lnk_grp_create(const char *name)
{
	struct sid_srv_lnk_grp *slg;

	if (!(slg = malloc(sizeof(*slg))))
		return NULL;

	if (!(slg->name = strdup(name))) {
		free(slg);
		return NULL;
	}

	list_init(&slg->members);

	return slg;
}

struct sid_srv_lnk_grp *sid_srv_lnk_grp_clone(struct sid_srv_lnk_grp *slg, const char *name)
{
	struct sid_srv_lnk_grp *slg_clone;
	struct sid_srv_lnk     *sl, *sl_clone;

	if (!slg)
		return NULL;

	if (!name)
		name = slg->name;

	if (!(slg_clone = sid_srv_lnk_grp_create(name)))
		return NULL;

	list_iterate_items (sl, &slg->members) {
		if (!(sl->flags & SID_SRV_LNK_FL_CLONEABLE))
			continue;

		if (!(sl_clone = sid_srv_lnk_clone(sl, NULL)))
			goto fail;

		sid_srv_lnk_grp_add(slg_clone, sl_clone);
	}

	return slg_clone;
fail:
	sid_srv_lnk_grp_destroy_with_members(slg_clone);
	return NULL;
}

struct sid_srv_lnk_grp *sid_srv_lnk_grp_merge(struct sid_srv_lnk_grp *dest_slg, struct sid_srv_lnk_grp *src_slg)
{
	struct sid_srv_lnk *sl, *tmp_sl;

	if (!src_slg || !dest_slg)
		return NULL;

	list_iterate_items_safe (sl, tmp_sl, &src_slg->members)
		sid_srv_lnk_grp_add(dest_slg, sl);

	sid_srv_lnk_grp_destroy(src_slg);
	return dest_slg;
}

void sid_srv_lnk_grp_destroy(struct sid_srv_lnk_grp *slg)
{
	struct sid_srv_lnk *sl, *tmp_sl;

	list_iterate_items_safe (sl, tmp_sl, &slg->members) {
		list_del(&sl->list);
		sl->group = NULL;
	}

	free((void *) slg->name);
	free(slg);
}

void sid_srv_lnk_grp_destroy_with_members(struct sid_srv_lnk_grp *slg)
{
	struct sid_srv_lnk *sl, *tmp_sl;

	list_iterate_items_safe (sl, tmp_sl, &slg->members)
		sid_srv_lnk_destroy(sl);

	free((void *) slg->name);
	free(slg);
}

void sid_srv_lnk_grp_add(struct sid_srv_lnk_grp *slg, struct sid_srv_lnk *sl)
{
	list_add(&slg->members, &sl->list);
	sl->group = slg;
}

int sid_srv_lnk_grp_del(struct sid_srv_lnk_grp *slg, struct sid_srv_lnk *sl)
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

static int _notify_systemd(struct sid_srv_lnk *sl,
                           sid_srv_lnk_notif_t notification,
                           sid_log_req_t      *log_req,
                           const char         *fmt,
                           va_list             ap)
{
	struct sid_buf *buf = NULL, *fmt_buf = NULL;
	const char     *arg_str, *arg_value;
	size_t          size;
	int             unset = 0;
	int             r     = 0;

	if (!(buf = sid_buf_create(&((struct sid_buf_spec) {.backend = SID_BUF_BACKEND_MALLOC,
	                                                    .type    = SID_BUF_TYPE_LINEAR,
	                                                    .mode    = SID_BUF_MODE_PLAIN}),
	                           &((struct sid_buf_init) {.size = 0, .alloc_step = 1, .limit = 0}),
	                           &r)))
		goto out;

	if (fmt && *fmt) {
		if (!(fmt_buf = sid_buf_create(&((struct sid_buf_spec) {.backend = SID_BUF_BACKEND_MALLOC,
		                                                        .type    = SID_BUF_TYPE_LINEAR,
		                                                        .mode    = SID_BUF_MODE_PLAIN}),
		                               &((struct sid_buf_init) {.size = 0, .alloc_step = 1, .limit = 0}),
		                               &r)))
			goto out;

		if ((r = sid_buf_add_vfmt(fmt_buf, (const void **) &arg_str, NULL, fmt, ap)) < 0)
			goto out;
	} else
		arg_str = NULL;

	if (notification & SID_SRV_LNK_NOTIF_UNSET)
		unset = 1;

	if (notification & SID_SRV_LNK_NOTIF_STATUS) {
		if ((arg_value = _get_arg_value(arg_str, SID_SRV_LNK_KEY_STATUS EQ, &size))) {
			if ((r = sid_buf_add_fmt(buf, NULL, NULL, SID_SRV_LNK_KEY_STATUS EQ "%.*s\n", size, arg_value)) < 0)
				goto out;

			if ((r = sid_buf_rewind(buf, 1, SID_BUF_POS_REL)) < 0)
				goto out;
		}
	}

	if (notification & SID_SRV_LNK_NOTIF_ERRNO) {
		if ((arg_value = _get_arg_value(arg_str, SID_SRV_LNK_KEY_ERRNO EQ, &size))) {
			if ((r = sid_buf_add_fmt(buf, NULL, NULL, SID_SRV_LNK_KEY_ERRNO EQ "%.*s\n", size, arg_value)) < 0)
				goto out;

			if ((r = sid_buf_rewind(buf, 1, SID_BUF_POS_REL)) < 0)
				goto out;
		}
	}

	if (notification & SID_SRV_LNK_NOTIF_READY)
		if ((r = sid_buf_add(buf, (void *) SERVICE_READY_LINE, sizeof(SERVICE_READY_LINE) - 1, NULL, NULL)) < 0)
			goto out;

	if (notification & SID_SRV_LNK_NOTIF_RELOADING)
		if ((r = sid_buf_add(buf, (void *) SERVICE_RELOADING_LINE, sizeof(SERVICE_RELOADING_LINE) - 1, NULL, NULL)) < 0)
			goto out;

	if (notification & SID_SRV_LNK_NOTIF_STOPPING)
		if ((r = sid_buf_add(buf, (void *) SERVICE_STOPPING_LINE, sizeof(SERVICE_STOPPING_LINE) - 1, NULL, NULL)) < 0)
			goto out;

	if (notification & SID_SRV_LNK_NOTIF_WATCHDOG_REFRESH)
		if ((r = sid_buf_add(buf,
		                     (void *) SERVICE_WATCHDOG_REFRESH_LINE,
		                     sizeof(SERVICE_WATCHDOG_REFRESH_LINE) - 1,
		                     NULL,
		                     NULL)) < 0)
			goto out;

	if (notification & SID_SRV_LNK_NOTIF_WATCHDOG_TRIGGER)
		if ((r = sid_buf_add(buf,
		                     (void *) SERVICE_WATCHDOG_TRIGGER_LINE,
		                     sizeof(SERVICE_WATCHDOG_TRIGGER_LINE) - 1,
		                     NULL,
		                     NULL)) < 0)
			goto out;

	/* NULL termintate string, or create empty string */
	if ((r = sid_buf_add(buf, (void *) "", 1, NULL, NULL)) < 0)
		goto out;

	sid_buf_get_data(buf, (const void **) &arg_str, &size);

	r = sd_notify(unset, arg_str);
out:
	if (fmt_buf)
		sid_buf_destroy(fmt_buf);
	if (buf)
		sid_buf_destroy(buf);

	return r;
}

static int _notify_logger(struct sid_srv_lnk *sl,
                          sid_srv_lnk_notif_t notification,
                          sid_log_req_t      *log_req,
                          const char         *fmt,
                          va_list             ap)
{
	if (notification & SID_SRV_LNK_NOTIF_MESSAGE)
		sid_log_voutput((sid_log_t *) sl->data, log_req, fmt, ap);

	if (notification & SID_SRV_LNK_NOTIF_STATUS)
		sid_log_voutput((sid_log_t *) sl->data, log_req, fmt, ap);

	// TODO: if (notification & SID_SRV_LNK_NOTIF_ERRNO)

	if (notification & SID_SRV_LNK_NOTIF_READY)
		sid_log_output((sid_log_t *) sl->data, log_req, "| READY |");

	if (notification & SID_SRV_LNK_NOTIF_RELOADING)
		sid_log_output((sid_log_t *) sl->data, log_req, "| RELOADING |");

	if (notification & SID_SRV_LNK_NOTIF_STOPPING)
		sid_log_output((sid_log_t *) sl->data, log_req, "| STOPPING |");

	if (notification & SID_SRV_LNK_NOTIF_WATCHDOG_REFRESH)
		sid_log_output((sid_log_t *) sl->data, log_req, "| WATCHDOG_REFRESH |");

	if (notification & SID_SRV_LNK_NOTIF_WATCHDOG_TRIGGER)
		sid_log_output((sid_log_t *) sl->data, log_req, "| WATCHDOG_TRIGGER |");

	return 0;
}

static int _do_service_link_notify(struct sid_srv_lnk     *sl,
                                   struct sid_srv_lnk_grp *slg,
                                   sid_srv_lnk_notif_t     notification,
                                   sid_log_req_t          *log_req,
                                   const char             *fmt,
                                   va_list                 ap)
{
	int iter_r = 0, r = 0;

	if (sl) {
		if (sl->notification & notification) {
			switch (sl->type) {
				case SID_SRV_LNK_TYPE_SYSTEMD:
					r = _notify_systemd(sl, notification, log_req, fmt, ap);
					break;
				case SID_SRV_LNK_TYPE_LOGGER:
					r = _notify_logger(sl, notification, log_req, fmt, ap);
					break;
				case SID_SRV_LNK_TYPE_NONE:
					break;
			}
		}
	} else if (slg) {
		list_iterate_items (sl, &slg->members) {
			if (!(sl->notification & notification))
				continue;

			switch (sl->type) {
				case SID_SRV_LNK_TYPE_SYSTEMD:
					iter_r = _notify_systemd(sl, notification, log_req, fmt, ap);
					break;
				case SID_SRV_LNK_TYPE_LOGGER:
					iter_r = _notify_logger(sl, notification, log_req, fmt, ap);
					break;
				case SID_SRV_LNK_TYPE_NONE:
					break;
			}

			if (iter_r < 0)
				r = iter_r;
		}
	}

	return r;
}

int sid_srv_lnk_vnotify(struct sid_srv_lnk *sl,
                        sid_srv_lnk_notif_t notification,
                        sid_log_req_t      *log_req,
                        const char         *fmt,
                        va_list             ap)
{
	return _do_service_link_notify(sl, NULL, notification, log_req, fmt, ap);
}

int sid_srv_lnk_notify(struct sid_srv_lnk *sl, sid_srv_lnk_notif_t notification, sid_log_req_t *log_req, const char *fmt, ...)
{
	va_list ap;
	int     r;

	va_start(ap, fmt);
	r = _do_service_link_notify(sl, NULL, notification, log_req, fmt, ap);
	va_end(ap);

	return r;
}

int sid_srv_lnk_grp_vnotify(struct sid_srv_lnk_grp *slg,
                            sid_srv_lnk_notif_t     notification,
                            sid_log_req_t          *log_req,
                            const char             *fmt,
                            va_list                 ap)
{
	return _do_service_link_notify(NULL, slg, notification, log_req, fmt, ap);
}

int sid_srv_lnk_grp_notify(struct sid_srv_lnk_grp *slg,
                           sid_srv_lnk_notif_t     notification,
                           sid_log_req_t          *log_req,
                           const char             *fmt,
                           ...)
{
	va_list ap;
	int     r;

	va_start(ap, fmt);
	r = _do_service_link_notify(NULL, slg, notification, log_req, fmt, ap);
	va_end(ap);

	return r;
}
