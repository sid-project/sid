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

#ifndef _SID_WORKER_CONTROL_H
#define _SID_WORKER_CONTROL_H

#include "resource.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	WORKER_NEW,       /* worker is newly created and it's not initialized yet */
	WORKER_IDLE,      /* worker is already initialized and it's idle at the moment */
	WORKER_ASSIGNED,  /* first message sent to worker to execute some processing */
	WORKER_EXITING,   /* exit request sent to worker */
	WORKER_EXITED,    /* worker has exited */
} worker_state_t;

typedef int worker_control_worker_init_cb_fn_t(sid_resource_t *res, void *arg);
typedef int worker_control_recv_cb_fn_t(sid_resource_t *res, void *data, size_t data_size, int fd, void *arg);

sid_resource_t *worker_control_get_new_worker(sid_resource_t *worker_control_res, const char *id, worker_control_worker_init_cb_fn_t *init_fn, void *init_fn_arg);
sid_resource_t *worker_control_get_idle_worker(sid_resource_t *worker_control_res);
sid_resource_t *worker_control_find_worker(sid_resource_t *worker_control_res, const char *id);

bool worker_control_is_worker(sid_resource_t *res);

const char *worker_control_get_worker_id(sid_resource_t *res);

/* Set callback called on data and/or fd reception. */
int worker_control_set_recv_callback(sid_resource_t *res, worker_control_recv_cb_fn_t *recv_fn, void *recv_fn_arg);

/* Send data and/or fd from worker to worker proxy or vice versa. */
int worker_control_send(sid_resource_t *res, void *data, size_t data_size, int fd);

/* Yield current worker and make it available for others to use. */
int worker_control_worker_yield(sid_resource_t *worker_res);

#ifdef __cplusplus
}
#endif

#endif
