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

#include "list.h"
#include "log.h"
#include "mem.h"
#include "resource.h"

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <systemd/sd-daemon.h>
#include <unistd.h>

typedef struct sid_resource {
	struct list list;
	const sid_resource_type_t *type;
	char *id;
	sid_resource_t *parent;
	struct list children;
	sid_resource_flags_t flags;
	sd_event *event_loop;
	pid_t pid_created;
	void *data;
} sid_resource_t;

typedef struct sid_resource_iter {
	sid_resource_t *res;
	struct list *prev; /* for safety */
	struct list *current;
	struct list *next; /* for safety */
} sid_resource_iter_t;

sid_resource_t *sid_resource_create(sid_resource_t *parent_res, const sid_resource_type_t *type,
				    sid_resource_flags_t flags, const char *id_part, const void *kickstart_data)
{
	sid_resource_t *res;
	size_t id_size;
	char *id;
	sid_resource_t *child_res, *tmp_child_res;

	/* +1 for '/' if id is defined and +1 for '\0' at the end */
	id_size = (type->name ? strlen(type->name) : 0) + (id_part ? strlen(id_part) + 1 : 0) + 1;

	if (!(id = malloc(id_size)))
		goto fail;

	if (snprintf(id, id_size, "%s%s%s", type->name ? : "", id_part ? "/" : "", id_part ? : "") < 0)
		goto fail;

	log_debug(id, "Creating resource.");

	if (!(res = zalloc(sizeof(*res))))
		goto fail;

	res->id = id;
	res->flags = flags;
	list_init(&res->children);
	res->type = type;
	res->event_loop = NULL;
	res->pid_created = getpid(); /* FIXME: Use cached pid instead? Check latency... */

	if (type->with_event_loop && sd_event_new(&res->event_loop) < 0)
		goto fail;

	if ((res->parent = parent_res))
		list_add(&parent_res->children, &res->list);

	if (type->with_event_loop && type->with_watchdog &&
	    sd_event_set_watchdog(res->event_loop, 1) < 0)
		goto fail;

	if (type->init && type->init(res, kickstart_data, &res->data) < 0)
		goto fail;

	log_debug(res->id, "Resource created.");
	return res;
fail:
	if (res) {
		list_iterate_items_safe_back(child_res, tmp_child_res, &res->children)
			(void) sid_resource_destroy(child_res);
		if (res->parent)
			list_del(&res->list);
		if (res->event_loop)
			sd_event_unref(res->event_loop);
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
	sid_resource_t *child_res, *tmp_child_res;
	pid_t pid = getpid();

	if (pid == res->pid_created)
		log_debug(res->id, "%s.", msg_destroying);
	else
		log_debug(res->id, "%s (%s: %d/%d).", msg_destroying,
			  msg_pid_created_current, res->pid_created, pid);

	list_iterate_items_safe_back(child_res, tmp_child_res, &res->children)
		(void) sid_resource_destroy(child_res);

	if (res->type->destroy)
		(void) res->type->destroy(res);

	if (res->event_loop)
		res->event_loop = sd_event_unref(res->event_loop);

	if (res->parent)
		list_del(&res->list);

	if (pid == res->pid_created)
		log_debug(res->id, "%s.", msg_destroyed);
	else
		log_debug(res->id, "%s (%s: %d/%d).", msg_destroyed,
			  msg_pid_created_current, res->pid_created, pid);

	free(res->id);
	free(res);

	return 0;
}

bool sid_resource_is_type_of(sid_resource_t *res, const sid_resource_type_t *type)
{
	return res->type == type;
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

sid_resource_t *_get_resource_with_event_loop(sid_resource_t *res, int error_if_not_found)
{
	sid_resource_t *tmp_res = res;

	do {
		if (tmp_res->event_loop)
			return tmp_res;
		tmp_res = tmp_res->parent;
	} while (tmp_res);

	if (error_if_not_found)
		log_error(res->id, INTERNAL_ERROR "%s: No event loop found.", __func__);

	return NULL;
}

int sid_resource_create_io_event_source(sid_resource_t *res, sid_event_source **es, int fd,
				        sid_io_handler handler, const char *name, void *data)
{
	sid_resource_t *res_event_loop = _get_resource_with_event_loop(res, 1);
	int r;

	if (!res_event_loop)
		return -ENOMEDIUM;

	r = sd_event_add_io(res_event_loop->event_loop, es, fd, EPOLLIN, handler, data);
	if (r < 0)
		return r;

	if (name)
		(void) sd_event_source_set_description(*es, name);

	return 0;
}

int sid_resource_create_signal_event_source(sid_resource_t *res, sid_event_source **es, int signal,
					    sid_signal_handler handler, const char *name, void *data)
{
	sid_resource_t *res_event_loop = _get_resource_with_event_loop(res, 1);
	int r;

	if (!res_event_loop)
		return -ENOMEDIUM;

	r =sd_event_add_signal(res_event_loop->event_loop, es, signal, handler, data);
	if (r < 0)
		return r;

	if (name)
		(void) sd_event_source_set_description(*es, name);

	return 0;
}

int sid_resource_create_child_event_source(sid_resource_t *res, sid_event_source **es, pid_t pid,
					   int options, sid_child_handler handler, const char *name, void *data)
{
	sid_resource_t *res_event_loop = _get_resource_with_event_loop(res, 1);
	int r;

	if (!res_event_loop)
		return -ENOMEDIUM;

	r = sd_event_add_child(res_event_loop->event_loop, es, pid, options, handler, data);
	if (r < 0)
		return r;

	if (name)
		(void) sd_event_source_set_description(*es, name);

	return 0;
}

int sid_resource_create_time_event_source(sid_resource_t *res, sid_event_source **es, clockid_t clock,
					  uint64_t usec, uint64_t accuracy, sid_time_handler handler,
					  const char *name, void *data)
{
	sid_resource_t *res_event_loop = _get_resource_with_event_loop(res, 1);
	int r;

	if (!res_event_loop)
		return -ENOMEDIUM;

	r = sd_event_add_time(res_event_loop->event_loop, es, clock, usec, accuracy, handler, data);
	if (r < 0)
		return r;

	if (name)
		(void) sd_event_source_set_description(*es, name);

	return 0;
}

int sid_resource_create_deferred_event_source(sid_resource_t *res, sid_event_source **es, sid_generic_handler handler, void *data)
{
	sid_resource_t *res_event_loop = _get_resource_with_event_loop(res, 1);

	if (!res_event_loop)
		return -ENOMEDIUM;

	return sd_event_add_defer(res_event_loop->event_loop, es, handler, data);
}

int sid_resource_create_post_event_source(sid_resource_t *res, sid_event_source **es, sid_generic_handler handler, void *data)
{
	sid_resource_t *res_event_loop = _get_resource_with_event_loop(res, 1);

	if (!res_event_loop)
		return -ENOMEDIUM;

	return sd_event_add_post(res_event_loop->event_loop, es, handler, data);
}

int sid_resource_create_exit_event_source(sid_resource_t *res, sid_event_source **es, sid_generic_handler handler, void *data)
{
	sid_resource_t *res_event_loop = _get_resource_with_event_loop(res, 1);

	if (!res_event_loop)
		return -ENOMEDIUM;

	return sd_event_add_exit(res_event_loop->event_loop, es, handler, data);
}

int sid_resource_destroy_event_source(sid_resource_t *res __attribute__((unused)),
				      sid_event_source **es)
{
	*es = sd_event_source_unref(*es);
	return 0;
}

sid_resource_t *sid_resource_get_parent(sid_resource_t *res)
{
	if (!res->parent || res->parent->flags & SID_RESOURCE_RESTRICT_WALK_UP)
		return NULL;

	return res->parent;
}

sid_resource_t *sid_resource_get_top_level(sid_resource_t *res)
{
	while (res->parent)
		res = res->parent;

	return res;
}

sid_resource_t *sid_resource_get_child(sid_resource_t *res, const sid_resource_type_t *type, const char *id)
{
	sid_resource_t *child_res;

	list_iterate_items(child_res, &res->children) {
		if (child_res->flags & SID_RESOURCE_RESTRICT_WALK_DOWN)
			continue;
		if (child_res->type == type && !strcmp(sid_resource_get_id(child_res), id))
			return child_res;
	}

	return NULL;
}

unsigned int sid_resource_get_children_count(sid_resource_t *res)
{
	return list_size(&(res->children));
}

int sid_resource_add_child(sid_resource_t *res, sid_resource_t *child)
{
	if (!res || child->parent)
		return -EINVAL;

	child->parent = res;
	list_add(&res->children, &child->list);

	log_debug(res->id, "Child %s added.", child->id);
	return 0;
}

int sid_resource_isolate(sid_resource_t *res)
{
	sid_resource_t *tmp_child_res, *child_res;

	/* Only allow to isolate resource with parent and without event loop! */
	if (res->event_loop || !res->parent || (res->flags & SID_RESOURCE_DISALLOW_ISOLATION))
		return -EPERM;

	/* Reparent and isolate. */
	list_iterate_items_safe(child_res, tmp_child_res, &res->children) {
		list_del(&child_res->list);
		list_add(&res->parent->children, &child_res->list);
	}
	list_del(&res->list);
	res->parent = NULL;

	return 0;
}

int sid_resource_isolate_with_children(sid_resource_t *res)
{

	if (res->event_loop || !res->parent || (res->flags & SID_RESOURCE_DISALLOW_ISOLATION))
		return -EPERM;

	list_del(&res->list);
	res->parent = NULL;

	return 0;
}

sid_resource_iter_t *sid_resource_iter_create(sid_resource_t *res)
{
	sid_resource_iter_t *iter;

	if (!(iter = malloc(sizeof(*iter))))
		return NULL;

	iter->res = res;

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
	free(iter);
}

int sid_resource_run_event_loop(sid_resource_t *res)
{
	int r;

	if (!res->event_loop)
		return -ENOMEDIUM;

	log_debug(res->id, "Entering event loop.");

	(void) sd_notify(0, "READY=1\n"
			    "STATUS=SID started processing requests.");

	r = sd_event_loop(res->event_loop);
	if (r < 0) {
		log_error_errno(res->id, -r, "Event loop failed.");
		return r;
	}

	log_debug(res->id, "Exiting event loop.");
	return 0;
}

int sid_resource_exit_event_loop(sid_resource_t *res)
{
	if (!res->event_loop)
		return -ENOMEDIUM;

	return sd_event_exit(res->event_loop, 0);
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
