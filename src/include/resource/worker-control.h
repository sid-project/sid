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

#ifndef _SID_WORKER_CONTROL_H
#define _SID_WORKER_CONTROL_H

#include "resource/resource.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Basic worker properties */
typedef enum {
	WORKER_TYPE_INTERNAL, /* fork only to execute internal code */
	WORKER_TYPE_EXTERNAL, /* fork + exec to execute external code */
} worker_type_t;

typedef enum {
	WORKER_STATE_NEW,      /* worker is newly created and it's not initialized yet */
	WORKER_STATE_IDLE,     /* worker is already initialized and it's idle at the moment */
	WORKER_STATE_ASSIGNED, /* first message sent to worker for it to start execution  */
	WORKER_STATE_EXITING,  /* exit request sent to worker, waiting for worker to exit */
	WORKER_STATE_EXITED,   /* worker has exited */
} worker_state_t;

/* Worker initialization specification */
typedef int worker_init_cb_fn_t(sid_resource_t *res, void *arg);

struct worker_init_cb_spec {
	worker_init_cb_fn_t *cb;
	void                *arg;
};

#define NULL_WORKER_INIT_CB_SPEC ((struct worker_init_cb_spec) {.cb = NULL, .arg = NULL})

/* Wire specification */
typedef enum {
	WORKER_WIRE_NONE,
	WORKER_WIRE_PIPE_TO_WORKER, /* pipe wire   "proxy   -->  worker" */
	WORKER_WIRE_PIPE_TO_PROXY,  /* pipe wire   "proxy  <--  worker" */
	WORKER_WIRE_SOCKET,         /* socket wire "proxy  <--> worker" */
} worker_wire_type_t;

struct worker_wire_spec {
	worker_wire_type_t type;

	struct {
		bool used;

		union {
			struct {
				int fd_redir; /* FD to redirect into/from a pipe (depending on pipe direction) on worker side */
			} pipe;

			struct {
				int fd_redir; /* FD to redirect into a socket on worker side */
			} socket;
		};
	} ext;
};

/* Transmit/receive data specification */
struct worker_data_spec {
	void  *data;
	size_t data_size;

	struct {
		bool used;

		union {
			struct {
				int fd_pass; /* FD to pass through a socket wire */
			} socket;
		};
	} ext;
};

/* Channel specification */
struct worker_channel;

typedef int
	worker_channel_cb_fn_t(sid_resource_t *res, struct worker_channel *channel, struct worker_data_spec *data_spec, void *arg);

struct worker_channel_cb_spec {
	worker_channel_cb_fn_t *cb;
	void                   *arg;
};

#define NULL_WORKER_CHANNEL_CB_SPEC ((const struct worker_channel_cb_spec) {NULL})

struct worker_channel_spec {
	const char                   *id;           /* channel id */
	struct worker_wire_spec       wire;         /* channel wire specification */
	struct worker_channel_cb_spec worker_tx_cb; /* transmit callback specification on worker side */
	struct worker_channel_cb_spec worker_rx_cb; /* receive callback specification on worker side */
	struct worker_channel_cb_spec proxy_tx_cb;  /* transmit callback specification on proxy side */
	struct worker_channel_cb_spec proxy_rx_cb;  /* receive callback specification on proxy side */
};

#define NULL_WORKER_CHANNEL_SPEC ((const struct worker_channel_spec) {NULL})

/* Worker-control resource parameters */
struct worker_control_resource_params {
	worker_type_t                     worker_type;   /* type of workers this controller creates */
	struct worker_init_cb_spec        init_cb_spec;  /* worker initialization callback specification */
	const struct worker_channel_spec *channel_specs; /* NULL-terminated list of proxy <-> worker channel specs */
};

int worker_control_channel_send(sid_resource_t *res, const char *channel_id, struct worker_data_spec *data_spec);

/* Worker creation/lookup. */
struct worker_params {
	const char *id;

	union {
		struct {
			const char *exec_file;
			const char *args;
			const char *env;
		} external;
	};
};

int worker_control_get_new_worker(sid_resource_t *worker_control_res, struct worker_params *params, sid_resource_t **res_p);
int worker_control_run_new_worker(sid_resource_t *worker_control_res, struct worker_params *params);
int worker_control_run_worker(sid_resource_t *worker_control_res);
sid_resource_t *worker_control_get_idle_worker(sid_resource_t *worker_control_res);
sid_resource_t *worker_control_find_worker(sid_resource_t *worker_control_res, const char *id);

/* Worker utility functions. */
bool        worker_control_is_worker(sid_resource_t *res);
const char *worker_control_get_worker_id(sid_resource_t *res);

/* Yield current worker and make it available for others to use. */
int worker_control_worker_yield(sid_resource_t *res);

#ifdef __cplusplus
}
#endif

#endif
