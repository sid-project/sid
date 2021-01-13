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

#include "base/list.h"
#include "base/mem.h"
#include "log/log.h"
#include "resource/resource.h"

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-event.h>
#include <unistd.h>

typedef struct sid_resource {
	struct list list;
	const sid_resource_type_t *type;
	char *id;
	unsigned ref_count;
	sid_resource_t *parent;
	struct list children;
	sid_resource_flags_t flags;
	int64_t prio;
	sd_event *sd_event_loop;
	struct list event_sources;
	struct service_link_group *slg;
	pid_t pid_created;
	void *data;
} sid_resource_t;

typedef struct sid_resource_iter {
	sid_resource_t *res;
	struct list *prev; /* for safety */
	struct list *current;
	struct list *next; /* for safety */
} sid_resource_iter_t;

typedef struct sid_resource_event_source {
	struct list list;
	sid_resource_t *res;
	sd_event_source *sd_es;
	void *handler;
	void *data;
} sid_resource_event_source_t;

static int _create_event_source(sid_resource_t *res, const char *name, sd_event_source *sd_es,
                                void *handler, void *data, sid_resource_event_source_t **es)
{
	sid_resource_event_source_t *new_es;
	int r = 0;

	if (!(new_es = malloc(sizeof(*new_es)))) {
		r = -ENOMEM;
		goto out;
	}

	new_es->res = res;
	new_es->sd_es = sd_es;
	new_es->handler = handler;
	new_es->data = data;

	sd_event_source_set_userdata(sd_es, new_es);
	if (name)
		(void) sd_event_source_set_description(sd_es, name);
	else
		name = "unnamed";

	log_debug(res->id, "Event source created: %s.", name);

	list_add(&res->event_sources, &new_es->list);
out:
	if (r < 0)
		sd_event_source_unref(sd_es);
	else if (es)
		*es = new_es;

	return r;
}

static void _destroy_event_source(sid_resource_event_source_t *es)
{
	const char *name;

	/* FIXME: When destroying event source in a different process than the one
	 *        where it was created, systemd return with -ECHLD failure here because
	 *        it doesn't allow access to event sources if PIDs of creation and use
	 *        differ. However, systemd allows unref for the event source at least.
	 *        Maybe just save the event name in our sid_resource_event_source_t
	 *        structure and don't bother with systemd here...
	 */
	if (sd_event_source_get_description(es->sd_es, &name) < 0)
		name = "unknown";

	log_debug(es->res->id, "Event source removed: %s.", name);

	sd_event_source_unref(es->sd_es);
	list_del(&es->list);
	free(es);
}

static int _create_service_link_group(sid_resource_t *res, sid_resource_service_link_def_t service_link_defs[])
{
	sid_resource_service_link_def_t *def;
	struct service_link_group *slg;
	struct service_link *sl;
	int r = 0;

	if (!service_link_defs)
		return 0;

	if (!(slg = service_link_group_create(res->id)))
		return -ENOMEM;

	for (def = service_link_defs; def->type != SERVICE_TYPE_NONE; def++) {
		if (!(sl = service_link_create(def->type, def->name))) {
			r = -ENOMEM;
			goto out;
		}

		if ((r = service_link_add_notification(sl, def->notification)) < 0)
			goto out;

		if ((r = service_link_group_add_member(slg, sl)) < 0)
			goto out;
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
	struct list *child_lh;

	if ((res->parent = parent_res)) {
		list_iterate(child_lh, &parent_res->children) {
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

sid_resource_t *sid_resource_create(sid_resource_t *parent_res, const sid_resource_type_t *type,
                                    sid_resource_flags_t flags, const char *id_part, const void *kickstart_data,
                                    int64_t prio, sid_resource_service_link_def_t service_link_defs[])
{
	sid_resource_t *res = NULL;
	size_t id_size;
	char *id;
	sid_resource_event_source_t *es, *tmp_es;
	sid_resource_t *child_res, *tmp_child_res;

	/* +1 for '/' if id is defined and +1 for '\0' at the end */
	id_size = (type->name ? strlen(type->name) : 0) + (id_part ? strlen(id_part) + 1 : 0) + 1;

	if (!(id = malloc(id_size)))
		goto fail;

	if (snprintf(id, id_size, "%s%s%s", type->name ? : "", id_part ? "/" : "", id_part ? : "") < 0)
		goto fail;

	log_debug(id, "Creating resource.");

	if (!(res = mem_zalloc(sizeof(*res))))
		goto fail;

	res->id = id;

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

	if (_create_service_link_group(res, service_link_defs) < 0)
		goto fail;

	res->flags = flags;
	list_init(&res->children);
	res->type = type;
	res->prio = prio;
	res->sd_event_loop = NULL;
	res->pid_created = getpid(); /* FIXME: Use cached pid instead? Check latency... */

	if (type->with_event_loop && sd_event_new(&res->sd_event_loop) < 0)
		goto fail;

	list_init(&res->event_sources);

	_add_res_to_parent_res(res, parent_res);

	if (type->with_event_loop && type->with_watchdog &&
	    sd_event_set_watchdog(res->sd_event_loop, 1) < 0)
		goto fail;

	if (type->init && type->init(res, kickstart_data, &res->data) < 0)
		goto fail;

	log_debug(res->id, "Resource created.");

	/* Drop the temporary reference! */
	res->ref_count--;
	return res;
fail:
	if (res) {
		list_iterate_items_safe_back(child_res, tmp_child_res, &res->children)
		(void) sid_resource_destroy(child_res);

		_remove_res_from_parent_res(res);

		/* FIXME: Normally, we'd use list_iterate_items_safe_back here but
		 *        it causes problems. One known problem is that when signal
		 *        event sources are destroyed, signal handling is then messed up
		 *        for some reason.
		 */
		list_iterate_items_safe(es, tmp_es, &res->event_sources)
		_destroy_event_source(es);

		if (res->sd_event_loop)
			sd_event_unref(res->sd_event_loop);

		if (res->slg)
			service_link_group_destroy_with_members(res->slg);

		/* Drop the termporary reference! */
		res->ref_count--;

		if (res->ref_count > 0)
			log_error(res->id, INTERNAL_ERROR "%s: Resource has %u references left while destroying it because of a failure.", __func__, res->ref_count);

		free(res);
	}

	log_debug(id, "Resource NOT created.");
	free(id);
	return NULL;
}

int sid_resource_destroy(sid_resource_t *res)
{
	static const char msg_destroying[] = "Destroying resource";
	static const char msg_destroyed[] = "Resource destroyed";
	static const char msg_pid_created_current[] = "PID created/current";
	sid_resource_event_source_t *es, *tmp_es;
	sid_resource_t *child_res, *tmp_child_res;
	pid_t pid = getpid();

	if (pid == res->pid_created)
		log_debug(res->id, "%s.", msg_destroying);
	else
		log_debug(res->id, "%s (%s: %d/%d).", msg_destroying,
		          msg_pid_created_current, res->pid_created, pid);

	list_iterate_items_safe_back(child_res, tmp_child_res, &res->children)
	(void) sid_resource_destroy(child_res);

	/* FIXME: Normally, we'd use list_iterate_items_safe_back here but
	 *        it causes problems. One known problem is that when signal
	 *        event sources are destroyed, signal handling is then messed up
	 *        for some reason.
	 */
	list_iterate_items_safe(es, tmp_es, &res->event_sources)
	_destroy_event_source(es);

	if (res->type->destroy)
		(void) res->type->destroy(res);

	if (res->sd_event_loop)
		res->sd_event_loop = sd_event_unref(res->sd_event_loop);

	_remove_res_from_parent_res(res);

	if (res->ref_count > 0)
		log_error(res->id, INTERNAL_ERROR "%s: Resource has %u references left while destroying it.", __func__, res->ref_count);

	if (res->slg)
		service_link_group_destroy_with_members(res->slg);

	if (pid == res->pid_created)
		log_debug(res->id, "%s.", msg_destroyed);
	else
		log_debug(res->id, "%s (%s: %d/%d).", msg_destroyed,
		          msg_pid_created_current, res->pid_created, pid);

	free(res->id);
	free(res);

	return 0;
}

sid_resource_t *sid_resource_ref(sid_resource_t *res)
{
	if (res)
		res->ref_count++;

	return res;
}

int sid_resource_unref(sid_resource_t *res)
{
	if (res->ref_count == 0) {
		log_error(res->id, INTERNAL_ERROR "%s: Resource has no references.", __func__);
		return -EINVAL;
	}

	res->ref_count--;

	if (res->ref_count == 0)
		return sid_resource_destroy(res);

	return 0;
}

const char *sid_resource_get_full_id(sid_resource_t *res)
{
	return res->id;
}


const char *sid_resource_get_id(sid_resource_t *res)
{
	if (!res->type->name)
		return res->id;

	return res->id + strlen(res->type->name) + 1;
}

void *sid_resource_get_data(sid_resource_t *res)
{
	return res->data;
}

int sid_resource_set_prio(sid_resource_t *res, int64_t prio)
{
	sid_resource_t *parent_res;
	int64_t orig_prio;

	if (prio == res->prio)
		return 0;

	if ((parent_res = res->parent)) {
		_remove_res_from_parent_res(res);

		orig_prio = res->prio;
		res->prio = prio;

		_add_res_to_parent_res(res, parent_res);

		log_debug(res->id, "Resource priority changed from %" PRId64 " to %" PRId64 ".", orig_prio, prio);
	}

	return 0;
}

int64_t sid_resource_get_prio(sid_resource_t *res)
{
	return res->prio;
}

sid_resource_t *_get_resource_with_event_loop(sid_resource_t *res, int error_if_not_found)
{
	sid_resource_t *tmp_res = res;

	do {
		if (tmp_res->sd_event_loop)
			return tmp_res;
		tmp_res = tmp_res->parent;
	} while (tmp_res);

	if (error_if_not_found)
		log_error(res->id, INTERNAL_ERROR "%s: No event loop found.", __func__);

	return NULL;
}

static int _sd_io_event_handler(sd_event_source *sd_es, int fd, uint32_t revents, void *data)
{
	sid_resource_event_source_t *es = data;
	return ((sid_resource_io_event_handler_t) es->handler)(es, fd, revents, es->data);
}

int sid_resource_create_io_event_source(sid_resource_t *res, sid_resource_event_source_t **es, int fd,
                                        sid_resource_io_event_handler_t handler, int64_t prio,
                                        const char *name, void *data)
{
	sid_resource_t *res_event_loop;
	sd_event_source *sd_es = NULL;
	int r;

	if (!(res_event_loop = _get_resource_with_event_loop(res, 1))) {
		r = -ENOMEDIUM;
		goto fail;
	}

	if ((r = sd_event_add_io(res_event_loop->sd_event_loop, &sd_es, fd, EPOLLIN, _sd_io_event_handler, NULL)) < 0)
		goto fail;

	if (prio && (r = sd_event_source_set_priority(sd_es, prio)) < 0)
		goto fail;

	if ((r = _create_event_source(res, name, sd_es, handler, data, es)) < 0)
		goto fail;

	return 0;
fail:
	if (sd_es)
		sd_event_source_unref(sd_es);
	return r;
}

static int _sd_signal_event_handler(sd_event_source *sd_es, const struct signalfd_siginfo *si, void *data)
{
	sid_resource_event_source_t *es = data;
	return ((sid_resource_signal_event_handler_t) es->handler)(es, si, es->data);
}

int sid_resource_create_signal_event_source(sid_resource_t *res, sid_resource_event_source_t **es, int signal,
                                            sid_resource_signal_event_handler_t handler, int64_t prio,
                                            const char *name, void *data)
{
	sid_resource_t *res_event_loop;
	sd_event_source *sd_es = NULL;
	int r;

	if (!(res_event_loop = _get_resource_with_event_loop(res, 1))) {
		r = -ENOMEDIUM;
		goto fail;
	}

	if ((r = sd_event_add_signal(res_event_loop->sd_event_loop, &sd_es, signal, handler ? _sd_signal_event_handler : NULL, NULL)) < 0)
		goto fail;

	if (prio && (r = sd_event_source_set_priority(sd_es, prio)) < 0)
		goto fail;

	if ((r = _create_event_source(res, name, sd_es, handler, data, es)) < 0)
		goto fail;

	return 0;
fail:
	if (sd_es)
		sd_event_source_unref(sd_es);
	return r;
}

static int _sd_child_event_handler(sd_event_source *sd_es, const siginfo_t *si, void *data)
{
	sid_resource_event_source_t *es = data;
	return ((sid_resource_child_event_handler_t) es->handler)(es, si, es->data);
}

int sid_resource_create_child_event_source(sid_resource_t *res, sid_resource_event_source_t **es, pid_t pid, int options,
                                           sid_resource_child_event_handler_t handler, int64_t prio,
                                           const char *name, void *data)
{
	sid_resource_t *res_event_loop;
	sd_event_source *sd_es = NULL;
	int r;

	if (!(res_event_loop = _get_resource_with_event_loop(res, 1))) {
		r = -ENOMEDIUM;
		goto fail;
	}

	if ((r = sd_event_add_child(res_event_loop->sd_event_loop, &sd_es, pid, options, handler ? _sd_child_event_handler : NULL, NULL)) < 0)
		goto fail;

	if (prio && (r = sd_event_source_set_priority(sd_es, prio)) < 0)
		goto fail;

	if ((r = _create_event_source(res, name, sd_es, handler, data, es)) < 0)
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
	return ((sid_resource_time_event_handler_t) es->handler)(es, usec, es->data);
}

int sid_resource_create_time_event_source(sid_resource_t *res, sid_resource_event_source_t **es, clockid_t clock,
                                          uint64_t usec, uint64_t accuracy,
                                          sid_resource_time_event_handler_t handler, int64_t prio,
                                          const char *name, void *data)
{
	sid_resource_t *res_event_loop;
	sd_event_source *sd_es = NULL;
	int r;

	if (!(res_event_loop = _get_resource_with_event_loop(res, 1))) {
		r = -ENOMEDIUM;
		goto fail;
	}

	if ((r = sd_event_add_time(res_event_loop->sd_event_loop, &sd_es, clock, usec, accuracy, handler ? _sd_time_event_handler : NULL, NULL)) < 0)
		goto fail;

	if (prio && (r = sd_event_source_set_priority(sd_es, prio)) < 0)
		goto fail;

	if ((r = _create_event_source(res, name, sd_es, handler, data, es)) < 0)
		goto fail;

	return 0;
fail:
	if (sd_es)
		sd_event_source_unref(sd_es);
	return r;
}

static int _sd_generic_event_handler(sd_event_source *sd_es, void *data)
{
	sid_resource_event_source_t *es = data;
	return ((sid_resource_generic_event_handler_t) es->handler)(es, es->data);

}

int sid_resource_create_deferred_event_source(sid_resource_t *res, sid_resource_event_source_t **es,
                                              sid_resource_generic_event_handler_t handler, int64_t prio,
                                              const char *name, void *data)
{
	sid_resource_t *res_event_loop;
	sd_event_source *sd_es = NULL;
	int r;

	if (!(res_event_loop = _get_resource_with_event_loop(res, 1))) {
		r = -ENOMEDIUM;
		goto fail;
	}

	if ((r = sd_event_add_defer(res_event_loop->sd_event_loop, &sd_es, handler ? _sd_generic_event_handler : NULL, NULL)) < 0)
		goto fail;

	if (prio && (r = sd_event_source_set_priority(sd_es, prio)) < 0)
		goto fail;

	if ((r = _create_event_source(res, name, sd_es, handler, data, es)) < 0)
		goto fail;

	return 0;
fail:
	if (sd_es)
		sd_event_source_unref(sd_es);
	return r;
}

int sid_resource_create_post_event_source(sid_resource_t *res, sid_resource_event_source_t **es,
                                          sid_resource_generic_event_handler_t handler, int64_t prio,
                                          const char *name, void *data)
{
	sid_resource_t *res_event_loop;
	sd_event_source *sd_es = NULL;
	int r;

	if (!(res_event_loop = _get_resource_with_event_loop(res, 1))) {
		r = -ENOMEDIUM;
		goto fail;
	}

	if ((r = sd_event_add_post(res_event_loop->sd_event_loop, &sd_es, handler ? _sd_generic_event_handler : NULL, NULL)) < 0)
		goto fail;

	if (prio && (r = sd_event_source_set_priority(sd_es, prio)) < 0)
		goto fail;

	if ((r = _create_event_source(res, name, sd_es, handler, data, es)) < 0)
		goto fail;

	return 0;
fail:
	if (sd_es)
		sd_event_source_unref(sd_es);
	return r;
}

int sid_resource_create_exit_event_source(sid_resource_t *res, sid_resource_event_source_t **es,
                                          sid_resource_generic_event_handler_t handler, int64_t prio,
                                          const char *name, void *data)
{
	sid_resource_t *res_event_loop;
	sd_event_source *sd_es = NULL;
	int r;

	if (!(res_event_loop = _get_resource_with_event_loop(res, 1))) {
		r = -ENOMEDIUM;
		goto fail;
	}

	if ((r = sd_event_add_exit(res_event_loop->sd_event_loop, &sd_es, handler ? _sd_generic_event_handler : NULL, NULL)) < 0)
		goto fail;

	if (prio && (r = sd_event_source_set_priority(sd_es, prio)) < 0)
		goto fail;

	if ((r = _create_event_source(res, name, sd_es, handler, data, es)) < 0)
		goto fail;

	return 0;
fail:
	if (sd_es)
		sd_event_source_unref(sd_es);
	return r;
}

int sid_resource_destroy_event_source(sid_resource_event_source_t **es)
{
	_destroy_event_source(*es);
	*es = NULL;
	return 0;
}

bool sid_resource_match(sid_resource_t *res, const sid_resource_type_t *type, const char *id)
{
	return (type ? res->type == type : true) && (id ? !strcmp(sid_resource_get_id(res), id) : true);
}

sid_resource_t *_search_down(sid_resource_t *res, sid_resource_search_method_t method,
                             const sid_resource_type_t *type, const char *id,
                             sid_resource_t *ign_res)
{
	sid_resource_t *child_res, *found;

	list_iterate_items(child_res, &res->children) {
		if (child_res->flags & SID_RESOURCE_RESTRICT_WALK_DOWN)
			continue;

		if (child_res != ign_res && sid_resource_match(child_res, type, id))
			return child_res;

		if (method == SID_RESOURCE_SEARCH_DFS) {
			if ((found = sid_resource_search(child_res, method, type, id)))
				return found;
		}
	}

	if (method == SID_RESOURCE_SEARCH_WIDE_DFS) {
		list_iterate_items(child_res, &res->children) {
			if ((found = _search_down(child_res, method, type, id, NULL)))
				return found;
		}
	}

	return NULL;
}

sid_resource_t *_search_up(sid_resource_t *res, sid_resource_search_method_t method,
                           const sid_resource_type_t *type, const char *id,
                           sid_resource_t *ign_res)
{
	if (method == SID_RESOURCE_SEARCH_IMM_ANC) {
		if (res->parent && !(res->flags & SID_RESOURCE_RESTRICT_WALK_UP) &&
		    res->parent != ign_res && sid_resource_match(res->parent, type, id))
			return res->parent;
	} else if (method == SID_RESOURCE_SEARCH_ANC) {
		while (res->parent && !(res->flags & SID_RESOURCE_RESTRICT_WALK_UP)) {
			if (res->parent != ign_res && sid_resource_match(res->parent, type, id))
				return res->parent;

			res = res->parent;
		}
	} else if (method == SID_RESOURCE_SEARCH_TOP) {
		while (res->parent && !(res->flags & SID_RESOURCE_RESTRICT_WALK_UP))
			res = res->parent;

		if (res != ign_res && sid_resource_match(res, type, id))
			return res;
	}

	return NULL;
}

sid_resource_t *_search(sid_resource_t *res, sid_resource_search_method_t method,
                        const sid_resource_type_t *type, const char *id)
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

sid_resource_t *sid_resource_search(sid_resource_t *res, sid_resource_search_method_t method,
                                    const sid_resource_type_t *type, const char *id)
{
	if (method > _SID_RESOURCE_SEARCH_DESC_START && method < _SID_RESOURCE_SEARCH_DESC_END)
		return _search_down(res, method, type, id, NULL);

	if (method > _SID_RESOURCE_SEARCH_ANC_START && method < _SID_RESOURCE_SEARCH_ANC_END)
		return _search_up(res, method, type, id, NULL);

	if (method > _SID_RESOURCE_SEARCH_COMP_START && method < _SID_RESOURCE_SEARCH_COMP_END)
		return _search(res, method, type, id);

	return NULL;
}

int sid_resource_add_child(sid_resource_t *res, sid_resource_t *child, sid_resource_flags_t flags)
{
	if (child->parent)
		return -EBUSY;

	child->flags = flags;
	_add_res_to_parent_res(child, res);

	log_debug(res->id, "Child %s added.", child->id);
	return 0;
}

int sid_resource_isolate(sid_resource_t *res)
{
	sid_resource_t *tmp_child_res, *child_res;

	/* Only allow to isolate resource with parent and without event loop! */
	if (res->sd_event_loop || !res->parent || (res->flags & SID_RESOURCE_DISALLOW_ISOLATION))
		return -EPERM;

	/* Reparent and isolate. */
	list_iterate_items_safe(child_res, tmp_child_res, &res->children) {
		_remove_res_from_parent_res(child_res);
		_add_res_to_parent_res(child_res, res->parent);
	}

	_remove_res_from_parent_res(res);
	return 0;
}

int sid_resource_isolate_with_children(sid_resource_t *res)
{

	if (res->sd_event_loop || !res->parent || (res->flags & SID_RESOURCE_DISALLOW_ISOLATION))
		return -EPERM;

	_remove_res_from_parent_res(res);
	return 0;
}

sid_resource_iter_t *sid_resource_iter_create(sid_resource_t *res)
{
	sid_resource_iter_t *iter;

	if (!(iter = malloc(sizeof(*iter))))
		return NULL;

	iter->res = sid_resource_ref(res);

	iter->current = &res->children;
	iter->prev = iter->current->p;
	iter->next = iter->current->n;

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
	iter->next = iter->current->n;

	if ((res = list_struct_base(iter->current, sid_resource_t, list)) &&
	    res->flags & SID_RESOURCE_RESTRICT_WALK_DOWN)
		return sid_resource_iter_next(iter);

	return res;
}

sid_resource_t *sid_resource_iter_previous(sid_resource_iter_t *iter)
{
	sid_resource_t *res;

	if (iter->prev == &iter->res->children)
		return NULL;

	iter->current = iter->prev;
	iter->prev = iter->current->p;

	if ((res = list_struct_base(iter->current, sid_resource_t, list)) &&
	    res->flags & SID_RESOURCE_RESTRICT_WALK_DOWN)
		return sid_resource_iter_previous(iter);

	return res;
}

void sid_resource_iter_reset(sid_resource_iter_t *iter)
{
	iter->current = &iter->res->children;
	iter->prev = iter->current->p;
	iter->next = iter->current->n;
}

void sid_resource_iter_destroy(sid_resource_iter_t *iter)
{
	(void) sid_resource_unref(iter->res);
	free(iter);
}

int sid_resource_run_event_loop(sid_resource_t *res)
{
	int r;

	if (!res->sd_event_loop)
		return -ENOMEDIUM;

	log_debug(res->id, "Entering event loop.");

	(void) service_link_group_notify(res->slg, SERVICE_NOTIFICATION_READY, NULL);

	if ((r = sd_event_loop(res->sd_event_loop)) < 0) {
		log_error_errno(res->id, r, "Event loop failed");
		return r;
	}

	log_debug(res->id, "Exiting event loop.");
	return 0;
}

int sid_resource_exit_event_loop(sid_resource_t *res)
{
	if (!res->sd_event_loop) {
		log_debug(res->id, "sid_resource_exit_event_loop call with NULL event loop.");
		return -ENOMEDIUM;
	}

	return sd_event_exit(res->sd_event_loop, 0);
}

void _dump_children_recursively_in_dot(sid_resource_t *res)
{
	static const char ID[] = "DOT";
	sid_resource_t *child_res;
	const char *dir;

	list_iterate_items(child_res, &res->children) {
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

		log_print(ID, "\"%s\" -> \"%s\" %s%s;",
		          res->id, child_res->id, dir,
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
