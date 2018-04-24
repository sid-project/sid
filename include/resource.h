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
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* opaque resource handler */
typedef struct sid_resource sid_resource_t;

/* resource registration structure */
typedef struct sid_resource_reg {
	const char *name;
	int (*init) (sid_resource_t *res, const void *kickstart_data, void **data);
	int (*destroy) (sid_resource_t *res);
	unsigned int with_event_loop : 1;
	unsigned int with_watchdog   : 1;
} sid_resource_reg_t;

/* opaque resource's child iteration handler */
typedef struct sid_resource_iter sid_resource_iter_t;

#include "resource-regs.h"

#define SID_RESOURCE_INTERNAL 0x0000000000000001

/* 
 * create/destroy functions
 */
sid_resource_t *sid_resource_create(sid_resource_t *parent_res, const sid_resource_reg_t *reg,
				    uint64_t flags, const char *id, const void *kickstart_data);
int sid_resource_destroy(sid_resource_t *res);

/*
 * basic property retrieval functions
 */
bool sid_resource_is_registered_by(sid_resource_t *res, const sid_resource_reg_t *reg);
void *sid_resource_get_data(sid_resource_t *res);
const char *sid_resource_get_id(sid_resource_t *res);

#define ID(res) sid_resource_get_id(res)

/*
 * event source handling functions
 */
int sid_resource_create_io_event_source(sid_resource_t *res, sid_event_source **es, int fd,
					sid_io_handler handler, const char *name, void *data);
int sid_resource_create_signal_event_source(sid_resource_t *res, sid_event_source **es, int signal,
					    sid_signal_handler handler, const char *name, void *data);
int sid_resource_create_child_event_source(sid_resource_t *res, sid_event_source **es, pid_t pid,
					   int options, sid_child_handler handler, const char *name, void *data);
int sid_resource_create_time_event_source(sid_resource_t *res, sid_event_source **es, clockid_t clock,
					  uint64_t usec, uint64_t accuracy, sid_time_handler handler,
					  const char *name, void *data);
int sid_resource_create_deferred_event_source(sid_resource_t *res, sid_event_source **es,
					      sid_generic_handler handler, void *data);
int sid_resource_destroy_event_source(sid_resource_t *res __attribute__((unused)), sid_event_source **es);

/* 
 * structure/tree iterator and 'get' functions
 */
sid_resource_iter_t *sid_resource_iter_create(sid_resource_t *res);
sid_resource_t *sid_resource_iter_current(sid_resource_iter_t *iter);
sid_resource_t *sid_resource_iter_next(sid_resource_iter_t *iter);
sid_resource_t *sid_resource_iter_previous(sid_resource_iter_t *iter);
void sid_resource_iter_reset(sid_resource_iter_t *iter);
void sid_resource_iter_destroy(sid_resource_iter_t *iter);

sid_resource_t *sid_resource_get_parent(sid_resource_t *res);
sid_resource_t *sid_resource_get_top_level(sid_resource_t *res);
sid_resource_t *sid_resource_get_child(sid_resource_t *res, const sid_resource_reg_t *reg, const char *id);

/*
 * structure/tree modification functions
 */
int sid_resource_add_child(sid_resource_t *res, sid_resource_t *child);
int sid_resource_isolate(sid_resource_t *res);
int sid_resource_isolate_with_children(sid_resource_t *res);

/* event loop functions */
int sid_resource_run_event_loop(sid_resource_t *res);
int sid_resource_exit_event_loop(sid_resource_t *res);

#ifdef __cplusplus
}
#endif

#endif
