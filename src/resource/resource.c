/*
 * This file is part of SID.
 *
 * Copyright (C) 2017-2020 Red Hat, Inc. All rights reserved.
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

#include "resource/resource.h"

#include "base/buffer.h"
#include "internal/formatter.h"
#include "internal/list.h"
#include "internal/mem.h"
#include "log/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-event.h>
#include <unistd.h>

static void _resource_log_output(sid_resource_t *res, log_ctx_t *ctx, const char *fmt, ...);

#define LOG_LINE_INTERNAL(res, l, e, ...)                                                                                          \
	_resource_log_output(                                                                                                      \
		res,                                                                                                               \
		&((log_ctx_t) {.level_id = l, .errno_id = e, .src_file = __FILE__, .src_line = __LINE__, .src_func = __func__}),   \
		__VA_ARGS__)

#define resource_log_debug(res, ...)           LOG_LINE_INTERNAL(res, LOG_DEBUG, 0, __VA_ARGS__)
#define resource_log_info(res, ...)            LOG_LINE_INTERNAL(res, LOG_INFO, 0, __VA_ARGS__)
#define resource_log_notice(res, ...)          LOG_LINE_INTERNAL(res, LOG_NOTICE, 0, __VA_ARGS__)
#define resource_log_warning(res, ...)         LOG_LINE_INTERNAL(res, LOG_WARNING, 0, __VA_ARGS__)
#define resource_log_error(res, ...)           LOG_LINE_INTERNAL(res, LOG_ERR, 0, __VA_ARGS__)
#define resource_log_print(res, ...)           LOG_LINE_INTERNAL(res, LOG_PRINT, 0, __VA_ARGS__)
#define resource_log_error_errno(res, e, ...)  LOG_LINE_INTERNAL(res, LOG_DEBUG, e, __VA_ARGS__)
#define resource_log_sys_error(res, x, y, ...) resource_log_error_errno(res, errno, "%s%s%s failed", y, *y ? ": " : "", x)

typedef struct sid_resource {
	/* structuring */
	struct list     list;
	sid_resource_t *parent;
	struct list     children;

	/* identification */
	const sid_resource_type_t *type;
	char                      *id;

	/* properties */
	pid_t                pid_created;
	sid_resource_flags_t flags;
	int64_t              prio;
	unsigned             ref_count;
	bool                 initialized:1;

	/* event handling */
	struct {
		sd_event *sd_event_loop;
		int       signalfd;
	} event_loop;
	struct list event_sources;

	/* notification handling */
	struct service_link_group *slg;

	/* custom data */
	void *data;
} sid_resource_t;

typedef struct sid_resource_iter {
	sid_resource_t *res;
	struct list    *prev; /* for safety */
	struct list    *current;
	struct list    *next; /* for safety */
	bool            res_refd:1;
} sid_resource_iter_t;

typedef enum {
	EVENT_SOURCE_GENERIC,
	EVENT_SOURCE_IO,
	EVENT_SOURCE_SIGNAL,
	EVENT_SOURCE_CHILD,
	EVENT_SOURCE_TIME,
	EVENT_SOURCE_DEFERRED,
	EVENT_SOURCE_POST,
	EVENT_SOURCE_EXIT,
} event_source_type_t;

static const char * const _event_source_type_names[] = {
	[EVENT_SOURCE_GENERIC]  = "Generic",
	[EVENT_SOURCE_IO]       = "IO",
	[EVENT_SOURCE_SIGNAL]   = "Signal",
	[EVENT_SOURCE_TIME]     = "Time",
	[EVENT_SOURCE_CHILD]    = "Child",
	[EVENT_SOURCE_DEFERRED] = "Deferred",
	[EVENT_SOURCE_POST]     = "Post",
	[EVENT_SOURCE_EXIT]     = "Exit",
};

typedef struct sid_resource_event_source {
	struct list         list;
	sid_resource_t     *res;
	event_source_type_t type;
	sd_event_source    *sd_es;
	const char         *name;
	uint64_t            events_fired;
	uint64_t            events_max;
	void               *handler;
	void               *data;
} sid_resource_event_source_t;

static int _create_event_source(sid_resource_t               *res,
                                event_source_type_t           type,
                                const char                   *name,
                                sd_event_source              *sd_es,
                                void                         *handler,
                                void                         *data,
                                uint64_t                      events_max,
                                sid_resource_event_source_t **es)
{
	static const char            unnamed[] = "unnamed";
	sid_resource_event_source_t *new_es;
	int                          r = 0;

	if (!(new_es = malloc(sizeof(*new_es)))) {
		r = -ENOMEM;
		goto out;
	}

	new_es->res          = res;
	new_es->type         = type;
	new_es->sd_es        = sd_es;
	new_es->events_fired = 0;
	new_es->events_max   = events_max;
	new_es->handler      = handler;
	new_es->data         = data;

	sd_event_source_set_userdata(sd_es, new_es);
	if (name) {
		/*
		 * A little workaround here...
		 *
		 * Set the name in sd-event, then get the name as stored there and
		 * reference it in new_es->name. This way, we can still put the name
		 * in logs even after the PID has changed (after forking) - in this
		 * case the sd-event API functions would exit immediately,
		 * including sd_event_source_get_description we might want to use
		 * in a process with that different PID.
		 */
		if (sd_event_source_set_description(sd_es, name) < 0 || sd_event_source_get_description(sd_es, &new_es->name) < 0)
			name = new_es->name = unnamed;
	} else
		name = unnamed;

	if (events_max == 0)
		sd_event_source_set_enabled(new_es->sd_es, SD_EVENT_OFF);
	else if (events_max == 1)
		sd_event_source_set_enabled(new_es->sd_es, SD_EVENT_ONESHOT);
	else
		sd_event_source_set_enabled(new_es->sd_es, SD_EVENT_ON);

	resource_log_debug(res, "%s event source created: %s.", _event_source_type_names[type], name);

	list_add(&res->event_sources, &new_es->list);
out:
	if (r == 0 && es)
		*es = new_es;

	return r;
}

static void _destroy_event_source(sid_resource_event_source_t *es)
{
	resource_log_debug(es->res, "%s event source removed: %s.", _event_source_type_names[es->type], es->name);

	sd_event_source_disable_unref(es->sd_es);
	list_del(&es->list);
	free(es);
}

static int _create_service_link_group(sid_resource_t                 *parent_res,
                                      sid_resource_t                 *res,
                                      sid_resource_service_link_def_t service_link_defs[])
{
	sid_resource_service_link_def_t *def;
	struct service_link_group       *slg;
	struct service_link             *sl;
	int                              r = 0;

	if (parent_res && parent_res->slg)
		slg = service_link_group_clone(parent_res->slg, res->id);
	else
		slg = NULL;

	if (service_link_defs) {
		if (!slg && !(slg = service_link_group_create(res->id)))
			return -ENOMEM;

		for (def = service_link_defs; def->type != SERVICE_TYPE_NONE; def++) {
			if (!(sl = service_link_create(def->type, def->name))) {
				r = -ENOMEM;
				goto out;
			}

			service_link_set_flags(sl, def->flags);
			service_link_set_data(sl, def->data);
			service_link_add_notification(sl, def->notification);
			service_link_group_add_member(slg, sl);
		}
	}

	res->slg = slg;
out:
	if (r < 0)
		service_link_group_destroy_with_members(slg);

	return r;
}

static void _add_res_to_parent_res(sid_resource_t *res, sid_resource_t *parent_res)
{
	sid_resource_t *child_res;
	struct list    *child_lh;

	if ((res->parent = parent_res)) {
		list_iterate (child_lh, &parent_res->children) {
			child_res = list_item(child_lh, sid_resource_t);
			if (res->prio < child_res->prio)
				break;
		}

		list_add(child_lh, &res->list);
		res->ref_count++;
	}
}

static void _remove_res_from_parent_res(sid_resource_t *res)
{
	if (res->parent) {
		list_del(&res->list);
		res->parent = NULL;
		res->ref_count--;
	}
}

sid_resource_t *sid_resource_create(sid_resource_t                 *parent_res,
                                    const sid_resource_type_t      *type,
                                    sid_resource_flags_t            flags,
                                    const char                     *id_part,
                                    const void                     *kickstart_data,
                                    int64_t                         prio,
                                    sid_resource_service_link_def_t service_link_defs[])
{
	sid_resource_t              *res = NULL;
	size_t                       id_size;
	char                        *id;
	sid_resource_event_source_t *es, *tmp_es;
	sid_resource_t              *child_res, *tmp_child_res;

	/* +1 for '/' if id is defined and +1 for '\0' at the end */
	id_size = (type->short_name ? strlen(type->short_name) : 0) + (id_part ? strlen(id_part) + 1 : 0) + 1;

	if (!(id = malloc(id_size)) ||
	    (snprintf(id, id_size, "%s%s%s", type->short_name ?: "", id_part ? " " : "", id_part ?: "") < 0)) {
		resource_log_error(parent_res, "Failed to construct identifier for a new %s child resource.", type->short_name);
		free(id);
		return NULL;
	}

	if (!(res = mem_zalloc(sizeof(*res)))) {
		resource_log_error(parent_res,
		                   "Failed to allocate structure for a new child resource of type %s.",
		                   type->short_name);
		free(id);
		return NULL;
	}

	res->id = id;

	if (_create_service_link_group(parent_res, res, service_link_defs) < 0) {
		resource_log_error(parent_res, "Failed to attach service links to a new %s child resource.", type->short_name);
		free(id);
		free(res);
		return NULL;
	}

	resource_log_debug(res, "Creating resource.");

	list_init(&res->children);
	list_init(&res->event_sources);

	/*
	 * Take temporary reference!
	 *
	 * This is to avoid automatic resource destruction in case we use ref counts
	 * in the code that follows and at the same time something fails,  mainly in
	 * the type->init initializer. In case of failure, we would drop other references
	 * and the last one would trigger automatic resource destruction. We'd better do
	 * the cleanup here in this function during resource creation stage, not automatically
	 * anywhere else which would be confusing.
	 */
	res->ref_count++;

	res->flags                    = flags;
	res->type                     = type;
	res->prio                     = prio;
	res->event_loop.sd_event_loop = NULL;
	res->event_loop.signalfd      = -1;
	res->pid_created              = getpid(); /* FIXME: Use cached pid instead? Check latency... */

	if (type->with_event_loop && sd_event_new(&res->event_loop.sd_event_loop) < 0)
		goto fail;

	_add_res_to_parent_res(res, parent_res);

	if (type->with_event_loop && type->with_watchdog && sd_event_set_watchdog(res->event_loop.sd_event_loop, 1) < 0)
		goto fail;

	if (type->init && type->init(res, kickstart_data, &res->data) < 0)
		goto fail;

	resource_log_debug(res, "Resource created.");

	/* Drop the temporary reference! */
	res->ref_count--;

	res->initialized = 1;
	return res;
fail:
	list_iterate_items_safe_back (child_res, tmp_child_res, &res->children)
		(void) sid_resource_unref(child_res);

	_remove_res_from_parent_res(res);

	list_iterate_items_safe_back (es, tmp_es, &res->event_sources)
		_destroy_event_source(es);

	if (res->event_loop.sd_event_loop)
		sd_event_unref(res->event_loop.sd_event_loop);

	if (res->slg)
		service_link_group_destroy_with_members(res->slg);

	/* Drop the termporary reference! */
	res->ref_count--;

	if (res->ref_count > 0)
		resource_log_error(res,
		                   INTERNAL_ERROR "%s: Resource has %u references left while destroying it because of a failure.",
		                   __func__,
		                   res->ref_count);

	resource_log_debug(res, "Resource NOT created.");

	free(res);
	free(id);
	return NULL;
}

static int _do_sid_resource_unref(sid_resource_t *res, int nested)
{
	static const char            msg_destroying[]          = "Destroying resource";
	static const char            msg_destroyed[]           = "Resource destroyed";
	static const char            msg_pid_created_current[] = "PID created/current";
	sid_resource_event_source_t *es, *tmp_es;
	sid_resource_t              *child_res, *tmp_child_res;
	pid_t                        pid = getpid();
	int                          do_destroy;

	if (res->parent && res->ref_count == 1) {
		/*
		 * The res has a parent and ref_count == 1, that is, the parent is the only one
		 * that refers to this res. Subsequent call to _remove_res_from_parent_res will
		 * drop the last ref then.
		 */
		do_destroy = 1;
	} else if (!res->parent && res->ref_count == 0) {
		/*
		 * The res does not have a parent and ref_count == 0, that is, nothing refers
		 * to this res - the res is currently 'floating'. This must be the top of the
		 * resource tree that nobody references.
		 */
		do_destroy = 1;
	} else {
		/* Still some other references left. */
		if (nested) {
			/*
			 * If we get here, we are nested inside the resource tree because of
			 * recursive unref traversal. At the same time, we must have
			 * ref_count >= 2, because one is surely coming from the parent-child
			 * relationship and there must be at least one more (...if it wasn't,
			 * then the first condition check 'res->parent && res->ref_count == 1'
			 * would be hit instead of this one).
			 *
			 * So we have to remove res from parent res here - this will also
			 * drop the one ref coming from the parent-child relationship.
			 * Do not destroy yet though.
			 */
			/*
			 * FIXME: also respect SID_RESOURCE_DISALLOW_ISOLATION,
			 *        use sid_resource_isolate_with_children or similar.
			 */
			_remove_res_from_parent_res(res);
			do_destroy = 0;
		} else {
			/*
			 * Otherwise just drop the ref and check if we have
			 * reached ref_count == 0 and destroy if it is.
			 */
			res->ref_count--;
			do_destroy = res->ref_count == 0;
		}
	}

	if (!do_destroy)
		return 0;

	if (pid == res->pid_created)
		resource_log_debug(res, "%s.", msg_destroying);
	else
		resource_log_debug(res, "%s (%s: %d/%d).", msg_destroying, msg_pid_created_current, res->pid_created, pid);

	list_iterate_items_safe_back (child_res, tmp_child_res, &res->children)
		/* nesting... */
		(void) _do_sid_resource_unref(child_res, 1);

	list_iterate_items_safe_back (es, tmp_es, &res->event_sources)
		_destroy_event_source(es);

	if (res->type->destroy)
		(void) res->type->destroy(res);

	if (res->event_loop.sd_event_loop)
		res->event_loop.sd_event_loop = sd_event_unref(res->event_loop.sd_event_loop);

	if (res->event_loop.signalfd != -1) {
		close(res->event_loop.signalfd);
		res->event_loop.signalfd = -1;
	}

	_remove_res_from_parent_res(res);

	if (pid == res->pid_created)
		resource_log_debug(res, "%s.", msg_destroyed);
	else
		resource_log_debug(res, "%s (%s: %d/%d).", msg_destroyed, msg_pid_created_current, res->pid_created, pid);

	if (res->slg)
		service_link_group_destroy_with_members(res->slg);

	free(res->id);
	free(res);

	return 0;
}

int sid_resource_unref(sid_resource_t *res)
{
	return _do_sid_resource_unref(res, 0);
}

/*
 * FIXME: Add sid_resource_ref_from_resource(sid_resource_t *current_res, sid_resource_t *res)
 *        that checks if current_res is not below res in a resource tree. If that happens,
 *        we can get into a problem -  we are moving on to recursive children traversal for
 *        unref only if a resource count drops to 0. So the refence from any resource below
 *        would never get unreffed. The same check also needs to be a part of
 *        sid_resource_add_child  somehow - but for that we'd need to track all the refs that
 *        a resource has made to other resources.
 */
sid_resource_t *sid_resource_ref(sid_resource_t *res)
{
	if (res)
		res->ref_count++;

	return res;
}

const char *sid_resource_get_full_id(sid_resource_t *res)
{
	return res->id;
}

const char *sid_resource_get_id(sid_resource_t *res)
{
	if (!res->type->short_name)
		return res->id;

	return res->id + strlen(res->type->short_name) + 1;
}

void *sid_resource_get_data(sid_resource_t *res)
{
	return res->data;
}

int sid_resource_set_prio(sid_resource_t *res, int64_t prio)
{
	sid_resource_t *parent_res;
	int64_t         orig_prio;

	if (prio == res->prio)
		return 0;

	if ((parent_res = res->parent)) {
		_remove_res_from_parent_res(res);

		orig_prio = res->prio;
		res->prio = prio;

		_add_res_to_parent_res(res, parent_res);

		resource_log_debug(res, "Resource priority changed from %" PRId64 " to %" PRId64 ".", orig_prio, prio);
	}

	return 0;
}

int64_t sid_resource_get_prio(sid_resource_t *res)
{
	return res->prio;
}

static sid_resource_t *_get_resource_with_event_loop(sid_resource_t *res, int error_if_not_found)
{
	sid_resource_t *tmp_res = res;

	do {
		if (tmp_res->event_loop.sd_event_loop)
			return tmp_res;
		tmp_res = tmp_res->parent;
	} while (tmp_res);

	if (error_if_not_found)
		resource_log_error(res, INTERNAL_ERROR "%s: No event loop found.", __func__);

	return NULL;
}

static void _handle_event_counter(sid_resource_event_source_t *es)
{
	es->events_fired++;
	if ((es->events_max != SID_RESOURCE_UNLIMITED_EVENT_COUNT) && (es->events_fired == es->events_max))
		sd_event_source_set_enabled(es->sd_es, SD_EVENT_OFF);
}

static int _sd_io_event_handler(sd_event_source *sd_es, int fd, uint32_t revents, void *data)
{
	sid_resource_event_source_t *es = data;
	int                          r;

	_handle_event_counter(es);
	if (es->handler) {
		if ((r = ((sid_resource_io_event_handler_t) es->handler)(es, fd, revents, es->data)) < 0)
			es->events_max = es->events_fired;
	} else
		r = 0;

	return r;
}

int sid_resource_create_io_event_source(sid_resource_t                 *res,
                                        sid_resource_event_source_t   **es,
                                        int                             fd,
                                        sid_resource_io_event_handler_t handler,
                                        int64_t                         prio,
                                        const char                     *name,
                                        void                           *data)
{
	sid_resource_t  *res_event_loop;
	sd_event_source *sd_es = NULL;
	int              r;

	if (!(res_event_loop = _get_resource_with_event_loop(res, 1))) {
		r = -ENOMEDIUM;
		goto fail;
	}

	if ((r = sd_event_add_io(res_event_loop->event_loop.sd_event_loop, &sd_es, fd, EPOLLIN, _sd_io_event_handler, NULL)) < 0)
		goto fail;

	if (prio && (r = sd_event_source_set_priority(sd_es, prio)) < 0)
		goto fail;

	if ((r = _create_event_source(res, EVENT_SOURCE_IO, name, sd_es, handler, data, SID_RESOURCE_UNLIMITED_EVENT_COUNT, es)) <
	    0)
		goto fail;

	return 0;
fail:
	if (sd_es)
		sd_event_source_unref(sd_es);
	return r;
}

static int _sd_signal_event_handler(sd_event_source *sd_es, int sfd, uint32_t revents, void *data)
{
	sid_resource_event_source_t *es = sd_event_source_get_userdata(sd_es);
	struct signalfd_siginfo      si;
	ssize_t                      res;
	int                          r;

	_handle_event_counter(es);

	res = read(sfd, &si, sizeof(si));

	if (res < 0) {
		resource_log_error(es->res, "failed to read signal");
		return 1;
	}
	if (res != sizeof(si)) {
		resource_log_error(es->res, "failed to read size of return data");
		return 1;
	}

	if (es->handler) {
		if ((r = ((sid_resource_signal_event_handler_t) es->handler)(es, &si, es->data)) < 0)
			es->events_max = es->events_fired;
	} else
		r = 0;

	return r;
}

/* This should not watch the SIGCHLD signal if sd_event_add_child() is also used */
int sid_resource_create_signal_event_source(sid_resource_t                     *res,
                                            sid_resource_event_source_t       **es,
                                            sigset_t                            mask,
                                            sid_resource_signal_event_handler_t handler,
                                            int64_t                             prio,
                                            const char                         *name,
                                            void                               *data)
{
	sid_resource_t  *res_event_loop;
	sd_event_source *sd_es = NULL;
	sigset_t         original_sigmask;
	int              r;

	if (!(res_event_loop = _get_resource_with_event_loop(res, 1)))
		return -ENOMEDIUM;

	if (sigprocmask(SIG_BLOCK, &mask, &original_sigmask) < 0) {
		resource_log_error(res, "Failed to set sigprocmask().");
		return -errno;
	}

	if (res_event_loop->event_loop.signalfd == -1) {
		res_event_loop->event_loop.signalfd = signalfd(-1, &mask, SFD_NONBLOCK);
		if (res_event_loop->event_loop.signalfd < 0) {
			resource_log_error(res, "Failed to create signalfd.");
			r = -errno;
			goto fail;
		}
	} else {
		r = -EADDRINUSE;
		goto fail;
	}

	if ((r = sd_event_add_io(res_event_loop->event_loop.sd_event_loop,
	                         &sd_es,
	                         res_event_loop->event_loop.signalfd,
	                         EPOLLIN,
	                         _sd_signal_event_handler,
	                         NULL)) < 0) {
		resource_log_error(res, "Failed sd_event_add_io().");
		goto fail;
	}

	if (prio && (r = sd_event_source_set_priority(sd_es, prio)) < 0)
		goto fail;

	if ((r = _create_event_source(res,
	                              EVENT_SOURCE_SIGNAL,
	                              name,
	                              sd_es,
	                              handler,
	                              data,
	                              SID_RESOURCE_UNLIMITED_EVENT_COUNT,
	                              es)) < 0)
		goto fail;

	return 0;
fail:
	if (sigprocmask(SIG_SETMASK, &original_sigmask, NULL) < 0)
		resource_log_error(res, "Failed to restore original sigprocmask().");

	if (sd_es)
		sd_event_source_unref(sd_es);
	return r;
}

static int _sd_child_event_handler(sd_event_source *sd_es, const siginfo_t *si, void *data)
{
	sid_resource_event_source_t *es = data;
	int                          r;

	_handle_event_counter(es);
	if (es->handler) {
		if ((r = ((sid_resource_child_event_handler_t) es->handler)(es, si, es->data)) > 0)
			es->events_max = es->events_fired;
	} else
		r = 0;

	return r;
}

int sid_resource_create_child_event_source(sid_resource_t                    *res,
                                           sid_resource_event_source_t      **es,
                                           pid_t                              pid,
                                           int                                options,
                                           sid_resource_child_event_handler_t handler,
                                           int64_t                            prio,
                                           const char                        *name,
                                           void                              *data)
{
	sid_resource_t  *res_event_loop;
	sd_event_source *sd_es = NULL;
	int              r;

	if (!(res_event_loop = _get_resource_with_event_loop(res, 1))) {
		r = -ENOMEDIUM;
		goto fail;
	}

	if ((r = sd_event_add_child(res_event_loop->event_loop.sd_event_loop,
	                            &sd_es,
	                            pid,
	                            options,
	                            _sd_child_event_handler,
	                            NULL)) < 0)
		goto fail;

	if (prio && (r = sd_event_source_set_priority(sd_es, prio)) < 0)
		goto fail;

	if ((r = _create_event_source(res,
	                              EVENT_SOURCE_CHILD,
	                              name,
	                              sd_es,
	                              handler,
	                              data,
	                              SID_RESOURCE_UNLIMITED_EVENT_COUNT,
	                              es)) < 0)
		goto fail;

	return 0;
fail:
	if (sd_es)
		sd_event_source_unref(sd_es);
	return r;
}

static int _sd_time_event_handler(sd_event_source *sd_es, uint64_t usec, void *data)
{
	sid_resource_event_source_t *es = data;
	int                          r;

	_handle_event_counter(es);
	if (es->handler) {
		if ((r = ((sid_resource_time_event_handler_t) es->handler)(es, usec, es->data)) < 0)
			es->events_max = es->events_fired;
	} else
		r = 0;

	return r;
}

int sid_resource_create_time_event_source(sid_resource_t                   *res,
                                          sid_resource_event_source_t     **es,
                                          clockid_t                         clock,
                                          sid_resource_pos_t                disposition,
                                          uint64_t                          usec,
                                          uint64_t                          accuracy,
                                          sid_resource_time_event_handler_t handler,
                                          int64_t                           prio,
                                          const char                       *name,
                                          void                             *data)
{
	sid_resource_t  *res_event_loop;
	sd_event_source *sd_es = NULL;
	uint64_t         usec_now;
	int              r;

	if (!(res_event_loop = _get_resource_with_event_loop(res, 1))) {
		r = -ENOMEDIUM;
		goto fail;
	}

	switch (disposition) {
		case SID_RESOURCE_POS_ABS:
			if ((r = sd_event_add_time(res_event_loop->event_loop.sd_event_loop,
			                           &sd_es,
			                           clock,
			                           usec,
			                           accuracy,
			                           _sd_time_event_handler,
			                           NULL)) < 0)
				goto fail;
			break;

		case SID_RESOURCE_POS_REL:
			if ((r = sd_event_now(res_event_loop->event_loop.sd_event_loop, clock, &usec_now) < 0))
				goto fail;

			if (usec >= UINT64_MAX - usec_now) {
				r = -EOVERFLOW;
				goto fail;
			}

			if ((r = sd_event_add_time(res_event_loop->event_loop.sd_event_loop,
			                           &sd_es,
			                           clock,
			                           usec_now + usec,
			                           accuracy,
			                           _sd_time_event_handler,
			                           NULL)) < 0)
				goto fail;
			break;
	}

	if (prio && (r = sd_event_source_set_priority(sd_es, prio)) < 0)
		goto fail;

	if ((r = _create_event_source(res, EVENT_SOURCE_TIME, name, sd_es, handler, data, 1, es)) < 0)
		goto fail;

	return 0;
fail:
	if (sd_es)
		sd_event_source_unref(sd_es);
	return r;
}

int sid_resource_rearm_time_event_source(sid_resource_event_source_t *es, sid_resource_pos_t disposition, uint64_t usec)
{
	sid_resource_t *res_event_loop;
	clockid_t       clock;
	uint64_t        usec_now;
	int             r;

	switch (disposition) {
		case SID_RESOURCE_POS_ABS:
			if ((r = sd_event_source_set_time(es->sd_es, usec) < 0))
				return r;
			break;

		case SID_RESOURCE_POS_REL:
			if (!(res_event_loop = _get_resource_with_event_loop(es->res, 1)))
				return -ENOMEDIUM;

			if ((r = sd_event_source_get_time_clock(es->sd_es, &clock)) < 0)
				return r;

			if ((r = sd_event_now(res_event_loop->event_loop.sd_event_loop, clock, &usec_now)) < 0)
				return r;

			if (usec >= UINT64_MAX - usec_now)
				return -EOVERFLOW;

			if ((r = sd_event_source_set_time(es->sd_es, usec_now + usec)))
				return r;
			break;
	}

	return sid_resource_set_event_source_counter(es, SID_RESOURCE_POS_REL, 1);
}

static int _sd_generic_event_handler(sd_event_source *sd_es, void *data)
{
	sid_resource_event_source_t *es = data;
	int                          r;

	_handle_event_counter(es);
	if (es->handler) {
		if ((r = ((sid_resource_generic_event_handler_t) es->handler)(es, es->data)) < 0)
			es->events_max = es->events_fired;
	} else
		r = 0;

	return r;
}

int sid_resource_create_deferred_event_source(sid_resource_t                      *res,
                                              sid_resource_event_source_t        **es,
                                              sid_resource_generic_event_handler_t handler,
                                              int64_t                              prio,
                                              const char                          *name,
                                              void                                *data)
{
	sid_resource_t  *res_event_loop;
	sd_event_source *sd_es = NULL;
	int              r;

	if (!(res_event_loop = _get_resource_with_event_loop(res, 1))) {
		r = -ENOMEDIUM;
		goto fail;
	}

	if ((r = sd_event_add_defer(res_event_loop->event_loop.sd_event_loop, &sd_es, _sd_generic_event_handler, NULL)) < 0)
		goto fail;

	if (prio && (r = sd_event_source_set_priority(sd_es, prio)) < 0)
		goto fail;

	if ((r = _create_event_source(res, EVENT_SOURCE_DEFERRED, name, sd_es, handler, data, 1, es)) < 0)
		goto fail;

	return 0;
fail:
	if (sd_es)
		sd_event_source_unref(sd_es);
	return r;
}

int sid_resource_create_post_event_source(sid_resource_t                      *res,
                                          sid_resource_event_source_t        **es,
                                          sid_resource_generic_event_handler_t handler,
                                          int64_t                              prio,
                                          const char                          *name,
                                          void                                *data)
{
	sid_resource_t  *res_event_loop;
	sd_event_source *sd_es = NULL;
	int              r;

	if (!(res_event_loop = _get_resource_with_event_loop(res, 1))) {
		r = -ENOMEDIUM;
		goto fail;
	}

	if ((r = sd_event_add_post(res_event_loop->event_loop.sd_event_loop, &sd_es, _sd_generic_event_handler, NULL)) < 0)
		goto fail;

	if (prio && (r = sd_event_source_set_priority(sd_es, prio)) < 0)
		goto fail;

	if ((r = _create_event_source(res, EVENT_SOURCE_POST, name, sd_es, handler, data, SID_RESOURCE_UNLIMITED_EVENT_COUNT, es)) <
	    0)
		goto fail;

	return 0;
fail:
	if (sd_es)
		sd_event_source_unref(sd_es);
	return r;
}

int sid_resource_create_exit_event_source(sid_resource_t                      *res,
                                          sid_resource_event_source_t        **es,
                                          sid_resource_generic_event_handler_t handler,
                                          int64_t                              prio,
                                          const char                          *name,
                                          void                                *data)
{
	sid_resource_t  *res_event_loop;
	sd_event_source *sd_es = NULL;
	int              r;

	if (!(res_event_loop = _get_resource_with_event_loop(res, 1))) {
		r = -ENOMEDIUM;
		goto fail;
	}

	if ((r = sd_event_add_exit(res_event_loop->event_loop.sd_event_loop, &sd_es, _sd_generic_event_handler, NULL)) < 0)
		goto fail;

	if (prio && (r = sd_event_source_set_priority(sd_es, prio)) < 0)
		goto fail;

	if ((r = _create_event_source(res, EVENT_SOURCE_EXIT, name, sd_es, handler, data, 1, es)) < 0)
		goto fail;

	return 0;
fail:
	if (sd_es)
		sd_event_source_unref(sd_es);
	return r;
}

int sid_resource_set_event_source_counter(sid_resource_event_source_t *es, sid_resource_pos_t disposition, uint64_t events_max)
{
	if (events_max == SID_RESOURCE_UNLIMITED_EVENT_COUNT) {
		es->events_max = events_max;
		sd_event_source_set_enabled(es->sd_es, SD_EVENT_ON);
		return 0;
	}

	switch (disposition) {
		case SID_RESOURCE_POS_ABS:
			if (events_max < es->events_fired)
				events_max = es->events_fired;
			break;
		case SID_RESOURCE_POS_REL:
			events_max = es->events_fired + events_max;
			if ((events_max == SID_RESOURCE_UNLIMITED_EVENT_COUNT) || (events_max < es->events_fired))
				events_max = SID_RESOURCE_UNLIMITED_EVENT_COUNT - 1;
			break;
	}

	if (es->events_fired == events_max)
		sd_event_source_set_enabled(es->sd_es, SD_EVENT_OFF);
	else if (es->events_fired + 1 == events_max)
		sd_event_source_set_enabled(es->sd_es, SD_EVENT_ONESHOT);
	else
		sd_event_source_set_enabled(es->sd_es, SD_EVENT_ON);

	es->events_max = events_max;
	return 0;
}

int sid_resource_get_event_source_counter(sid_resource_event_source_t *es, uint64_t *events_fired, uint64_t *events_max)
{
	if (events_fired)
		*events_fired = es->events_fired;

	if (events_max)
		*events_max = es->events_max;

	return 0;
}

int sid_resource_destroy_event_source(sid_resource_event_source_t **es)
{
	_destroy_event_source(*es);
	*es = NULL;
	return 0;
}

bool sid_resource_match(sid_resource_t *res, const sid_resource_type_t *type, const char *id)
{
	return res && (type ? res->type == type : true) && (id ? !strcmp(sid_resource_get_id(res), id) : true);
}

static bool _can_walk_down(sid_resource_t *res, sid_resource_t *ign_res)
{
	return (res != ign_res) && !(res->flags & SID_RESOURCE_RESTRICT_WALK_DOWN);
}

static bool _can_walk_up(sid_resource_t *res, sid_resource_t *ign_res)
{
	return (res->parent && res->parent != ign_res) && !(res->flags & SID_RESOURCE_RESTRICT_WALK_UP);
}

static sid_resource_t *_search_down(sid_resource_t              *res,
                                    sid_resource_search_method_t method,
                                    const sid_resource_type_t   *type,
                                    const char                  *id,
                                    sid_resource_t              *ign_res)
{
	sid_resource_t *child_res, *found;

	list_iterate_items (child_res, &res->children) {
		if (!_can_walk_down(child_res, ign_res))
			continue;

		if (sid_resource_match(child_res, type, id))
			return child_res;

		if (method == SID_RESOURCE_SEARCH_DFS) {
			if ((found = _search_down(child_res, method, type, id, NULL)))
				return found;
		}
	}

	if (method == SID_RESOURCE_SEARCH_WIDE_DFS) {
		list_iterate_items (child_res, &res->children) {
			if ((found = _search_down(child_res, method, type, id, NULL)))
				return found;
		}
	}

	return NULL;
}

static sid_resource_t *_search_up(sid_resource_t              *res,
                                  sid_resource_search_method_t method,
                                  const sid_resource_type_t   *type,
                                  const char                  *id,
                                  sid_resource_t              *ign_res)
{
	if (method == SID_RESOURCE_SEARCH_IMM_ANC) {
		if (_can_walk_up(res, ign_res) && sid_resource_match(res->parent, type, id))
			return res->parent;
	} else if (method == SID_RESOURCE_SEARCH_ANC) {
		do {
			if (!_can_walk_up(res, ign_res))
				break;

			if (sid_resource_match(res->parent, type, id))
				return res->parent;
		} while ((res = res->parent));
	} else if (method == SID_RESOURCE_SEARCH_TOP) {
		do {
			if (!res->parent && sid_resource_match(res, type, id))
				return res;

			if (!_can_walk_up(res, ign_res))
				break;
		} while ((res = res->parent));
	}

	return NULL;
}

static sid_resource_t *
	_search(sid_resource_t *res, sid_resource_search_method_t method, const sid_resource_type_t *type, const char *id)
{
	sid_resource_t *tmp_res;

	if (method == SID_RESOURCE_SEARCH_GENUS) {
		if (!(tmp_res = _search_up(res, SID_RESOURCE_SEARCH_TOP, NULL, NULL, NULL)))
			return NULL;

		return _search_down(tmp_res, SID_RESOURCE_SEARCH_WIDE_DFS, type, id, NULL);
	}

	if (method == SID_RESOURCE_SEARCH_SIB) {
		if (!(tmp_res = _search_up(res, SID_RESOURCE_SEARCH_IMM_ANC, NULL, NULL, NULL)))
			return NULL;

		return _search_down(tmp_res, SID_RESOURCE_SEARCH_IMM_DESC, type, id, res);
	}

	return NULL;
}

sid_resource_t *sid_resource_search(sid_resource_t              *start_res,
                                    sid_resource_search_method_t method,
                                    const sid_resource_type_t   *type,
                                    const char                  *id)
{
	if (method > _SID_RESOURCE_SEARCH_DESC_START && method < _SID_RESOURCE_SEARCH_DESC_END)
		return _search_down(start_res, method, type, id, NULL);

	if (method > _SID_RESOURCE_SEARCH_ANC_START && method < _SID_RESOURCE_SEARCH_ANC_END)
		return _search_up(start_res, method, type, id, NULL);

	if (method > _SID_RESOURCE_SEARCH_COMP_START && method < _SID_RESOURCE_SEARCH_COMP_END)
		return _search(start_res, method, type, id);

	return NULL;
}

bool sid_resource_has_parent(sid_resource_t *res)
{
	return res->parent != NULL;
}

int sid_resource_add_child(sid_resource_t *res, sid_resource_t *child, sid_resource_flags_t flags)
{
	if (child->parent)
		return -EBUSY;

	child->flags = flags;
	_add_res_to_parent_res(child, res);

	resource_log_debug(res, "Child %s added.", child->id);
	return 0;
}

int sid_resource_isolate(sid_resource_t *res)
{
	sid_resource_t *tmp_child_res, *child_res;

	/* Only allow to isolate resource with parent and without event loop! */
	if (res->event_loop.sd_event_loop || !res->parent || (res->flags & SID_RESOURCE_DISALLOW_ISOLATION))
		return -EPERM;

	/* Reparent and isolate. */
	list_iterate_items_safe (child_res, tmp_child_res, &res->children) {
		_remove_res_from_parent_res(child_res);
		_add_res_to_parent_res(child_res, res->parent);
	}

	_remove_res_from_parent_res(res);
	return 0;
}

int sid_resource_isolate_with_children(sid_resource_t *res)
{
	if (res->event_loop.sd_event_loop || !res->parent || (res->flags & SID_RESOURCE_DISALLOW_ISOLATION))
		return -EPERM;

	_remove_res_from_parent_res(res);
	return 0;
}

sid_resource_iter_t *sid_resource_iter_create(sid_resource_t *res)
{
	sid_resource_iter_t *iter;

	if (!(iter = malloc(sizeof(*iter))))
		return NULL;

	if ((iter->res_refd = res->initialized))
		iter->res = sid_resource_ref(res);
	else
		iter->res = res;

	iter->current = &res->children;
	iter->prev    = iter->current->p;
	iter->next    = iter->current->n;

	return iter;
}

sid_resource_t *sid_resource_iter_current(sid_resource_iter_t *iter)
{
	if (iter->current == &iter->res->children)
		return NULL;

	return list_struct_base(iter->current, sid_resource_t, list);
}

sid_resource_t *sid_resource_iter_next(sid_resource_iter_t *iter)
{
	sid_resource_t *res;

	if (iter->next == &iter->res->children)
		return NULL;

	iter->current = iter->next;
	iter->next    = iter->current->n;

	if ((res = list_struct_base(iter->current, sid_resource_t, list)) && res->flags & SID_RESOURCE_RESTRICT_WALK_DOWN)
		return sid_resource_iter_next(iter);

	return res;
}

sid_resource_t *sid_resource_iter_previous(sid_resource_iter_t *iter)
{
	sid_resource_t *res;

	if (iter->prev == &iter->res->children)
		return NULL;

	iter->current = iter->prev;
	iter->prev    = iter->current->p;

	if ((res = list_struct_base(iter->current, sid_resource_t, list)) && res->flags & SID_RESOURCE_RESTRICT_WALK_DOWN)
		return sid_resource_iter_previous(iter);

	return res;
}

void sid_resource_iter_reset(sid_resource_iter_t *iter)
{
	iter->current = &iter->res->children;
	iter->prev    = iter->current->p;
	iter->next    = iter->current->n;
}

void sid_resource_iter_destroy(sid_resource_iter_t *iter)
{
	if (iter->res_refd)
		(void) sid_resource_unref(iter->res);
	free(iter);
}

int sid_resource_run_event_loop(sid_resource_t *res)
{
	log_req_t log_req;
	int       r;

	if (!res->event_loop.sd_event_loop)
		return -ENOMEDIUM;

	sid_resource_ref(res);
	resource_log_debug(res, "Entering event loop.");

	log_req.pfx = &((log_pfx_t) {.s = res->id, .n = NULL});
	log_req.ctx = &SERVICE_LINK_DEFAULT_LOG_CTX;
	(void) service_link_group_notify(res->slg, SERVICE_NOTIFICATION_READY, &log_req, NULL);

	if ((r = sd_event_loop(res->event_loop.sd_event_loop)) < 0) {
		if (r == -ECHILD)
			resource_log_debug(res, "Exiting event loop in child");
		else
			resource_log_error_errno(res, r, "Event loop failed");
		goto out;
	}

	resource_log_debug(res, "Exiting event loop.");
out:
	sid_resource_unref(res);
	return r;
}

int sid_resource_exit_event_loop(sid_resource_t *res)
{
	if (!res->event_loop.sd_event_loop) {
		resource_log_debug(res, "sid_resource_exit_event_loop call with NULL event loop.");
		return -ENOMEDIUM;
	}

	return sd_event_exit(res->event_loop.sd_event_loop, 0);
}

static void _resource_log_output(sid_resource_t *res, log_ctx_t *ctx, const char *fmt, ...)
{
	log_req_t req;
	va_list   ap;

	if (!res)
		return;

	req = (log_req_t) {.pfx = &((log_pfx_t) {.s = "res-int", .n = &((log_pfx_t) {.s = res->id, .n = NULL})}), .ctx = ctx};

	va_start(ap, fmt);
	service_link_group_vnotify(res->slg, SERVICE_NOTIFICATION_MESSAGE, &req, fmt, ap);
	va_end(ap);
}

void sid_resource_log_output(sid_resource_t *res, const log_req_t *log_req, const char *fmt, ...)
{
	log_req_t req;
	va_list   ap;
	log_pfx_t pfx1, pfx2, pfx_last;

	if (!res)
		return;

	pfx_last.s = res->id;
	pfx_last.n = log_req->pfx;

	pfx1.s     = "res-imp";

	if (res->type->log_prefix) {
		pfx2.s = res->type->log_prefix;
		pfx2.n = &pfx_last;
		pfx1.n = &pfx2;
	} else
		pfx1.n = &pfx_last;

	req.pfx = &pfx1;
	req.ctx = log_req->ctx;

	va_start(ap, fmt);
	service_link_group_vnotify(res->slg, SERVICE_NOTIFICATION_MESSAGE, &req, fmt, ap);
	va_end(ap);
}

static void _write_event_source_elem_fields(sid_resource_event_source_t *es,
                                            output_format_t              format,
                                            struct sid_buffer           *outbuf,
                                            int                          level)
{
	print_str_field(format, outbuf, level, "name", (char *) es->name, false);
	print_uint64_field(format, outbuf, level, "events_max", es->events_max, true);
	print_uint64_field(format, outbuf, level, "events_fired", es->events_fired, true);
}

static void _write_resource_elem_fields(sid_resource_t *res, output_format_t format, struct sid_buffer *outbuf, int level)
{
	sid_resource_event_source_t *es, *tmp_es;
	int                          es_count, item = 0;

	print_str_field(format, outbuf, level, "ID", res->id, false);
	if (res->type != NULL && res->type->name != NULL)
		print_str_field(format, outbuf, level, "type", (char *) res->type->name, true);
	es_count = list_size(&res->event_sources);
	if (es_count != 0) {
		print_start_array(format, outbuf, level, "event-sources", true);
		list_iterate_items_safe_back (es, tmp_es, &res->event_sources) {
			item++;
			print_start_elem(format, outbuf, level + 1, item > 1);
			_write_event_source_elem_fields(es, format, outbuf, level + 2);
			print_end_elem(format, outbuf, level + 1);
		}
		print_end_array(format, outbuf, level);
	}
	print_uint_field(format, outbuf, level, "pid-created", res->pid_created, true);
	print_uint_field(format, outbuf, level, "flags", res->flags, true);
	print_int64_field(format, outbuf, level, "prio", res->prio, true);
	print_uint_field(format, outbuf, level, "ref-count", res->ref_count, true);
}

int sid_resource_write_tree_recursively(sid_resource_t    *res,
                                        output_format_t    format,
                                        struct sid_buffer *outbuf,
                                        int                level,
                                        bool               with_comma)
{
	sid_resource_t *child_res;
	int             count, item = 0;

	count = list_size(&res->children);

	print_start_elem(format, outbuf, level, with_comma);
	_write_resource_elem_fields(res, format, outbuf, level + 1);
	if (count > 0) {
		print_start_array(format, outbuf, level + 1, "children", true);
		list_iterate_items (child_res, &res->children) {
			sid_resource_write_tree_recursively(child_res, format, outbuf, level + 2, item > 0);
			item++;
		}
		print_end_array(format, outbuf, level + 1);
	}
	print_end_elem(format, outbuf, level);

	return 0;
}

/*
void _dump_children_recursively_in_dot(sid_resource_t *res)
{
        static const char ID[] = "DOT";
        sid_resource_t *  child_res;
        const char *      dir;

        list_iterate_items (child_res, &res->children) {
                log_print(ID, "\"%s\";", child_res->id);

                switch (child_res->flags & SID_RESOURCE_RESTRICT_MASK) {
                        case SID_RESOURCE_RESTRICT_WALK_UP | SID_RESOURCE_RESTRICT_WALK_DOWN:
                                dir = " [dir=none]";
                                break;
                        case SID_RESOURCE_RESTRICT_WALK_UP:
                                dir = " [dir=forward]";
                                break;
                        case SID_RESOURCE_RESTRICT_WALK_DOWN:
                                dir = " [dir=back]";
                                break;
                        default:
                                dir = "[dir=both]";
                                break;
                }

                log_print(ID,
                          "\"%s\" -> \"%s\" %s%s;",
                          res->id,
                          child_res->id,
                          dir,
                          child_res->flags & SID_RESOURCE_DISALLOW_ISOLATION ? " [color=red]" : "");
                _dump_children_recursively_in_dot(child_res);
        }
}

void sid_resource_dump_all_in_dot(sid_resource_t *res)
{
        static const char ID[] = "DOT";

        log_print(ID, "digraph resources {");
        log_print(ID, "\"%s\";", res->id);
        _dump_children_recursively_in_dot(res);
        log_print(ID, "}");
}
*/
