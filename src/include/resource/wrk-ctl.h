/*
 * SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _SID_WRK_CTL_H
#define _SID_WRK_CTL_H

#include "base/buf-common.h"
#include "resource/res.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Basic worker properties */
typedef enum {
	SID_WRK_TYPE_INTERNAL, /* fork only to execute internal code */
	SID_WRK_TYPE_EXTERNAL, /* fork + exec to execute external code */
} sid_wrk_type_t;

typedef enum {
	SID_WRK_STATE_UNKNOWN,   /* worker state is not known/not applicable */
	SID_WRK_STATE_NEW,       /* worker is newly created and it's not initialized yet */
	SID_WRK_STATE_IDLE,      /* worker is already initialized and it's idle at the moment */
	SID_WRK_STATE_ASSIGNED,  /* first message sent to worker for it to start execution  */
	SID_WRK_STATE_EXITING,   /* worker yielded itself, exit signal sent back to worker, waiting for worker to exit */
	SID_WRK_STATE_TIMED_OUT, /* worker has timed out, exit signal sent back to worker, waiting for worker to exit */
	SID_WRK_STATE_EXITED,    /* worker has exited */
} sid_wrk_state_t;

/* Worker initialization specification */
typedef int sid_wrk_init_cb_fn_t(sid_res_t *res, void *arg);

struct sid_wrk_init_cb_spec {
	sid_wrk_init_cb_fn_t *fn;
	void                 *arg;
};

#define SID_WRK_NULL_INIT_CB_SPEC ((struct sid_wrk_init_cb_spec) {.fn = NULL, .arg = NULL})

/* Wire specification */
typedef enum {
	SID_WRK_WIRE_NONE,
	SID_WRK_WIRE_PIPE_TO_WRK, /* pipe wire   "proxy   -->  worker" */
	SID_WRK_WIRE_PIPE_TO_PRX, /* pipe wire   "proxy  <--  worker" */
	SID_WRK_WIRE_SOCKET,      /* socket wire "proxy  <--> worker" */
} sid_wrk_wire_type_t;

struct sid_wrk_wire_spec {
	sid_wrk_wire_type_t type;

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
struct sid_wrk_data_spec {
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
struct sid_wrk_chan;

typedef int sid_wrk_lane_cb_fn_t(sid_res_t *res, struct sid_wrk_chan *channel, struct sid_wrk_data_spec *data_spec, void *arg);

struct sid_wrk_lane_cb_spec {
	sid_wrk_lane_cb_fn_t *fn;
	void                 *arg;
};

struct sid_wrk_lane_spec {
	struct sid_wrk_lane_cb_spec cb;       /* callback called on lane activity */
	struct sid_buf_init         buf_init; /* lane buffer initialization parameters */
	struct iovec                data_suffix;
};

struct sid_wrk_chan_spec {
	const char              *id;
	struct sid_wrk_wire_spec wire;
	struct sid_wrk_lane_spec worker_tx;
	struct sid_wrk_lane_spec worker_rx;
	struct sid_wrk_lane_spec proxy_tx;
	struct sid_wrk_lane_spec proxy_rx;
};

#define SID_WRK_NULL_LANE_CB_SPEC ((const struct sid_wrk_lane_cb_spec) {NULL})
#define SID_WRK_NULL_LANE_SPEC    ((const struct sid_wrk_lane_spec) {NULL})
#define SID_WRK_NULL_CHAN_SPEC    ((const struct sid_wrk_chan_spec) {NULL})

/* Timeout specification */
struct sid_wrk_timeout_spec {
	uint64_t usec;
	int      signum;
};

/* Worker-control resource parameters */
struct sid_wrk_ctl_res_params {
	sid_wrk_type_t                    worker_type;   /* type of workers this controller creates */
	struct sid_wrk_init_cb_spec       init_cb_spec;  /* worker initialization callback specification */
	const struct sid_wrk_chan_spec   *channel_specs; /* NULL-terminated list of proxy <-> worker channel specs */
	const struct sid_wrk_timeout_spec timeout_spec;  /* timeout specification */
};

int sid_wrk_ctl_chan_send(sid_res_t *res, const char *channel_id, struct sid_wrk_data_spec *data_spec);
int sid_wrk_ctl_chan_close(sid_res_t *res, const char *channel_id);

/* Worker creation/lookup. */
struct sid_wrk_params {
	const char *id;

	union {
		struct {
			const char *exec_file;
			const char *args;
			const char *env;
		} external;
	};

	void *worker_arg;
	void *worker_proxy_arg;

	struct sid_wrk_timeout_spec timeout_spec;
};

int        sid_wrk_ctl_get_new_worker(sid_res_t *worker_control_res, struct sid_wrk_params *params, sid_res_t **res_p);
int        sid_wrk_ctl_run_new_worker(sid_res_t             *worker_control_res,
                                      struct sid_wrk_params *params,
                                      sid_res_srv_lnk_def_t  service_link_defs[]);
int        sid_wrk_ctl_run_worker(sid_res_t *worker_control_res, sid_res_srv_lnk_def_t service_link_defs[]);
sid_res_t *sid_wrk_ctl_get_idle_worker(sid_res_t *worker_control_res);
sid_res_t *sid_wrk_ctl_find_worker(sid_res_t *worker_control_res, const char *id);

/* Worker utility functions. */
bool            sid_wrk_ctl_detect_worker(sid_res_t *res);
sid_wrk_state_t sid_wrk_ctl_get_worker_state(sid_res_t *res);
const char     *sid_wrk_ctl_get_worker_id(sid_res_t *res);
void           *sid_wrk_ctl_get_worker_arg(sid_res_t *res);

/* Yield current worker and make it available for others to use. */
int sid_wrk_ctl_yield_worker(sid_res_t *res);

#ifdef __cplusplus
}
#endif

#endif
