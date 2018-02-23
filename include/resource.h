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

#ifndef _SID_CONTEXT_H
#define _SID_CONTEXT_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/timerfd.h>
#include "resource-regs.h"
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* opaque handler */
struct sid_resource;

/* resource registration structure */
struct sid_resource_reg {
	const char *name;
	int (*init) (struct sid_resource *res, const void *kickstart_data, void **data);
	int (*destroy) (struct sid_resource *res);
	unsigned int with_event_loop : 1;
	unsigned int with_watchdog   : 1;
};

/* 
 * create/destroy functions
 */
struct sid_resource *sid_resource_create(struct sid_resource *parent_res, const struct sid_resource_reg *reg,
					 uint64_t flags, const char *id, const void *kickstart_data);
int sid_resource_destroy(struct sid_resource *res);

/*
 * basic property retrieval functions
 */
bool sid_resource_is_registered_by(struct sid_resource *res, const struct sid_resource_reg *reg);
void *sid_resource_get_data(struct sid_resource *res);
const char *sid_resource_get_id(struct sid_resource *res);

#define ID(res) sid_resource_get_id(res)

/*
 * event source handling functions
 */
int sid_resource_create_io_event_source(struct sid_resource *res, sid_event_source **es, int fd,
					sid_io_handler handler, const char *name, void *data);
int sid_resource_create_signal_event_source(struct sid_resource *res, sid_event_source **es, int signal,
					    sid_signal_handler handler, const char *name, void *data);
int sid_resource_create_child_event_source(struct sid_resource *res, sid_event_source **es, pid_t pid,
					   int options, sid_child_handler handler, const char *name, void *data);
int sid_resource_create_time_event_source(struct sid_resource *res, sid_event_source **es, clockid_t clock,
					  uint64_t usec, uint64_t accuracy, sid_time_handler handler,
					  const char *name, void *data);
int sid_resource_create_deferred_event_source(struct sid_resource *res, sid_event_source **es,
					      sid_generic_handler handler, void *data);
int sid_resource_destroy_event_source(struct sid_resource *res __attribute__((unused)), sid_event_source **es);

/* 
 * structure/tree iterator and 'get' functions
 */
struct sid_resource_iter;

struct sid_resource_iter *sid_resource_iter_create(struct sid_resource *res);
struct sid_resource *sid_resource_iter_current(struct sid_resource_iter *iter);
struct sid_resource *sid_resource_iter_next(struct sid_resource_iter *iter);
struct sid_resource *sid_resource_iter_previous(struct sid_resource_iter *iter);
void sid_resource_iter_reset(struct sid_resource_iter *iter);
void sid_resource_iter_destroy(struct sid_resource_iter *iter);

struct sid_resource *sid_resource_get_parent(struct sid_resource *res);
struct sid_resource *sid_resource_get_top_level(struct sid_resource *res);
struct sid_resource *sid_resource_get_child(struct sid_resource *res, const struct sid_resource_reg *reg, const char *id);

/*
 * structure/tree modification functions
 */
int sid_resource_add_child(struct sid_resource *res, struct sid_resource *child);
int sid_resource_isolate(struct sid_resource *res);
int sid_resource_isolate_with_children(struct sid_resource *res);

/* event loop functions */
int sid_resource_run_event_loop(struct sid_resource *res);
int sid_resource_exit_event_loop(struct sid_resource *res);

#ifdef __cplusplus
}
#endif

#endif
