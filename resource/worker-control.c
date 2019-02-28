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

#include "comms.h"
#include "configure.h"
#include "log.h"
#include "mem.h"
#include "resource.h"
#include "util.h"
#include "worker-control.h"

#include <unistd.h>

#define WORKER_CONTROL_NAME              "worker-control"
#define WORKER_PROXY_NAME                "worker-proxy"
#define WORKER_NAME                      "worker"
#define WORKER_PROXIES_AGGREGATE_ID      "worker-proxies"

#define DEFAULT_WORKER_IDLE_TIMEOUT_USEC 5000000

typedef enum {
	COMMS_CMD_NOOP   = 0,
	COMMS_CMD_YIELD  = 1,
	COMMS_CMD_CUSTOM = 2,
	_COMMS_CMD_COUNT,
} comms_cmd_t;

#define COMMS_BUFFER_LEN sizeof(comms_cmd_t)

static const char *comms_cmd_str[] = {[COMMS_CMD_NOOP]   = "NOOP",
				      [COMMS_CMD_YIELD]  = "YIELD",
				      [COMMS_CMD_CUSTOM] = "CUSTOM"};

static const char *worker_state_str[] = {[WORKER_NEW]      = "WORKER_NEW",
					 [WORKER_IDLE]     = "WORKER_IDLE",
					 [WORKER_ASSIGNED] = "WORKER_ASSIGNED",
					 [WORKER_EXITING]  = "WORKER_EXITING",
					 [WORKER_EXITED]   = "WORKER_EXITED"};

const sid_resource_reg_t sid_resource_reg_worker_proxy;
const sid_resource_reg_t sid_resource_reg_worker;

struct worker_control {
	sid_resource_t *worker_proxies_res;  /* aggregate resource to collect all worker proxies */
};

struct worker_kickstart {
	pid_t pid;
	int comms_fd;
};

struct worker_proxy {
	pid_t pid;                            /* worker PID */
	int comms_fd;			      /* communication channel between worker proxy and worker */
	sid_event_source *comms_es;           /* event source for comms_fd */
	sid_event_source *child_es;           /* event source to catch SIGCHLD from worker */
	sid_event_source *idle_timeout_es;    /* event source to catch idle timeout for worker */
	worker_state_t state;                 /* current worker state */
	worker_control_recv_cb_fn_t *recv_fn; /* callback function called on CMD_CUSTOM comms command reception */
	void *recv_fn_arg;                    /* argument passed to callback function called on CMD_CUSTOM comms command reception */
};

struct worker {
	int comms_fd;                         /* communication channel between worker proxy and worker */
	sid_event_source *comms_es;           /* event source for commds_fd */
	sid_event_source *sigint_es;          /* event source to catch SIGINT */
	sid_event_source *sigterm_es;         /* event source to catch SIGTERM */
	worker_control_recv_cb_fn_t *recv_fn; /* callback function called on CMD_CUSTOM comms command reception */
	void *recv_fn_arg;                    /* argument passed to callback function called on CMD_CUSTOM comms command reception */
};

static void _change_worker_proxy_state(sid_resource_t *worker_proxy_res, worker_state_t state)
{
	struct worker_proxy *worker_proxy = sid_resource_get_data(worker_proxy_res);

	worker_proxy->state = state;
	log_debug(ID(worker_proxy_res), "Worker state changed to %s.", worker_state_str[state]);
}

sid_resource_t *worker_control_get_new_worker(sid_resource_t *worker_control_res, const char *id, worker_control_worker_init_cb_fn_t *init_fn, void *init_fn_arg)
{
	struct worker_control *worker_control = sid_resource_get_data(worker_control_res);
	struct worker_kickstart kickstart = {0};
	sigset_t original_sigmask, new_sigmask;
	sid_resource_t *res = NULL;
	int signals_blocked = 0;
	int comms_fd[2];
	pid_t pid = -1;
	char gen_id[16];
	int r;

	if (socketpair(AF_LOCAL, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, comms_fd) < 0) {
		log_sys_error(ID(worker_control_res), "socketpair", "");
		goto out;
	}

	if (sigfillset(&new_sigmask) < 0) {
		log_sys_error(ID(worker_control_res), "sigfillset", "");
		goto out;
	}

	if (sigprocmask(SIG_SETMASK, &new_sigmask, &original_sigmask) < 0) {
		log_sys_error(ID(worker_control_res), "sigprocmask", "blocking signals before fork");
		goto out;
	}
	signals_blocked = 1;

	if ((pid = fork()) < 0) {
		log_sys_error(ID(worker_control_res), "fork", "");
		goto out;
	}

	if (pid == 0) {
		(void) close(comms_fd[0]);

		kickstart.pid = getpid();
		kickstart.comms_fd = comms_fd[1];

		if (!id) {
			(void) util_pid_to_str(kickstart.pid, gen_id, sizeof(gen_id));
			id = gen_id;
		}

		res = sid_resource_create(NULL, &sid_resource_reg_worker, 0, id, &kickstart);

		if (init_fn)
			(void) init_fn(res, init_fn_arg);

		(void) sid_resource_destroy(sid_resource_get_top_level(worker_control_res));
	} else {
		(void) close(comms_fd[1]);

		log_debug(ID(worker_control_res), "Created new worker process with PID %d.", pid);

		kickstart.pid = pid;
		kickstart.comms_fd = comms_fd[0];

		if (!id) {
			(void) util_pid_to_str(kickstart.pid, gen_id, sizeof(gen_id));
			id = gen_id;
		}

		res = sid_resource_create(worker_control->worker_proxies_res, &sid_resource_reg_worker_proxy, 0, id, &kickstart);
	}
out:
	if (signals_blocked && pid) {
		if (sigprocmask(SIG_SETMASK, &original_sigmask, NULL) < 0)
			log_sys_error(ID(res), "sigprocmask", "after forking process");
	}

	if (pid)
		/* return worker proxy resource */
		return res;

	/* run event loop in worker's top-level resource */
	r = sid_resource_run_event_loop(res);

	(void) sid_resource_destroy(res);
	exit(-r);
}

sid_resource_t *worker_control_get_idle_worker(sid_resource_t *worker_control_res)
{
	struct worker_control *worker_control = sid_resource_get_data(worker_control_res);
	sid_resource_iter_t *iter;
	sid_resource_t *res;

	if (!(iter = sid_resource_iter_create(worker_control->worker_proxies_res)))
		return NULL;

	while ((res = sid_resource_iter_next(iter))) {
		if (((struct worker_proxy *) sid_resource_get_data(res))->state == WORKER_IDLE)
			break;
	}

	sid_resource_iter_destroy(iter);
	return res;
}

bool worker_control_is_worker(sid_resource_t *res)
{
	return sid_resource_is_registered_by(sid_resource_get_top_level(res), &sid_resource_reg_worker);
}

static int _comms_send(int comms_fd, comms_cmd_t cmd, void *data, size_t data_size, int fd)
{
	struct iovec iov[3];

	iov[0].iov_base = &cmd;
	iov[0].iov_len = sizeof(cmd);
	iov[1].iov_base = &data_size;
	iov[1].iov_len = sizeof(data_size);
	iov[2].iov_base = data;
	iov[2].iov_len = data_size;

	return comms_unix_send_iovec(comms_fd, iov, data && data_size ? 3 : 2, fd);
}

static int _comms_recv(int comms_fd, comms_cmd_t *cmd, void **data, size_t *data_size, int *fd)
{
	struct iovec iov[2];
	size_t buf_size;
	void *buf = NULL;
	int r;

	iov[0].iov_base = cmd;
	iov[0].iov_len = sizeof(*cmd);
	iov[1].iov_base = data_size;
	iov[1].iov_len = sizeof(*data_size);

	if ((r = comms_unix_recv_iovec(comms_fd, iov, 2, fd)) < 0)
		return -1;

	if ((buf_size = *data_size) > 0) {
		if (!(buf = malloc(buf_size))) {
			errno = ENOMEM;
			return -1;
		}

		if (comms_unix_recv(comms_fd, buf, buf_size, NULL) < 0) {
			free(buf);
			return -1;
		}
	}

	*data = buf;
	return r + buf_size;
}

int worker_control_set_recv_callback(sid_resource_t *res, worker_control_recv_cb_fn_t *recv_fn, void *recv_fn_arg)
{
	struct worker_proxy *worker_proxy;
	struct worker *worker;

	if (sid_resource_is_registered_by(res, &sid_resource_reg_worker_proxy)) {
		worker_proxy = sid_resource_get_data(res);
		worker_proxy->recv_fn = recv_fn;
		worker_proxy->recv_fn_arg = recv_fn_arg;
	} else if (sid_resource_is_registered_by(res, &sid_resource_reg_worker)) {
		worker = sid_resource_get_data(res);
		worker->recv_fn = recv_fn;
		worker->recv_fn_arg = recv_fn_arg;
	} else {
		errno = ENOMEDIUM;
		return -1;
	}

	return 0;
}

int worker_control_send(sid_resource_t *res, void *data, size_t data_size, int fd)
{
	struct worker_proxy *worker_proxy;
	int comms_fd;

	if (sid_resource_is_registered_by(res, &sid_resource_reg_worker_proxy)) {
		/* sending from worker proxy to worker */
		worker_proxy = sid_resource_get_data(res);
		comms_fd = worker_proxy->comms_fd;
		sid_resource_destroy_event_source(res, &worker_proxy->idle_timeout_es);
		if (worker_proxy->state != WORKER_ASSIGNED)
			_change_worker_proxy_state(res, WORKER_ASSIGNED);
	} else {
		res = sid_resource_get_top_level(res);

		if (sid_resource_is_registered_by(res, &sid_resource_reg_worker)) {
			/* sending from worker to worker proxy */
			comms_fd = ((struct worker *) sid_resource_get_data(res))->comms_fd;
		} else {
			errno = ENOMEDIUM;
			return -1;
		}
	}

	return _comms_send(comms_fd, COMMS_CMD_CUSTOM, data, data_size, fd);
}

int worker_control_worker_yield(sid_resource_t *worker_res)
{
	struct worker *worker = sid_resource_get_data(worker_res);

	if (_comms_send(worker->comms_fd, COMMS_CMD_YIELD, NULL, 0, -1) < 0)
		return -1;

	return 0;
}

static int _on_worker_proxy_child_event(sid_event_source *es, const siginfo_t *si, void *data)
{
	sid_resource_t *worker_proxy_res = data;

	switch (si->si_code) {
		case CLD_EXITED:
			log_debug(ID(worker_proxy_res), "Worker exited with exit code %d.", si->si_status);
			break;
		case CLD_KILLED:
		case CLD_DUMPED:
			log_debug(ID(worker_proxy_res), "Worker terminated by signal %d.", si->si_status);
			break;
		default:
			log_debug(ID(worker_proxy_res), "Worker failed unexpectedly.");
	}

	_change_worker_proxy_state(worker_proxy_res, WORKER_EXITED);

	/*
	 * FIXME: Add config to keep worker_proxy_res with struct worker_proxy for a while to be able to catch possible status.
	 *        At the moment, we don't need this ability, but WORKER_EXITED state is prepared here for this purpose.
	 *        Then, that would be this assignemt here at this place:
	 *            worker_proxy->state = WORKER_EXITED;
	 *        And call sid_resource_destroy(worker_proxy_res) on some timeout or garbace collecting, not here.
	 */

	(void) sid_resource_destroy(worker_proxy_res);
	return 0;
}

static int _make_worker_exit(sid_resource_t *worker_proxy_res)
{
	struct worker_proxy *worker_proxy = sid_resource_get_data(worker_proxy_res);
	int r;

	if (!(r = kill(worker_proxy->pid, SIGTERM)))
		_change_worker_proxy_state(worker_proxy_res, WORKER_EXITING);

	return r;
}

/*
static int _on_worker_proxy_idle_timeout_event(sid_event_source *es, uint64_t usec, void *data)
{
	sid_resource_t *worker_proxy_res = data;

	log_debug(ID(worker_proxy_res), "Idle timeout expired.");
	return _make_worker_exit(worker_proxy_res);
}
*/

static const char _unexpected_internal_command_msg[] = "unexpected internal command received.";
static const char _no_custom_receive_function_msg[] = "Custom message received but not receive function defined.";
static const char _custom_message_handling_failed_msg[] = "Custom message handling failed.";

static int _on_worker_proxy_comms_event(sid_event_source *es, int fd, uint32_t revents, void *data)
{
	sid_resource_t *worker_proxy_res = data;
	struct worker_proxy *worker_proxy = sid_resource_get_data(worker_proxy_res);
	comms_cmd_t recv_cmd;
	void *recv_data;
	size_t recv_data_size;
	int recv_fd;
	/*uint64_t timeout_usec;*/

	if (_comms_recv(worker_proxy->comms_fd, &recv_cmd, &recv_data, &recv_data_size, &recv_fd) < 0)
		return -1;

	switch (recv_cmd) {
		case COMMS_CMD_YIELD:
			/* FIXME: Make timeout configurable. If timeout is set to zero, exit worker right away - call _make_worker_exit.
			 *
			timeout_usec = util_get_now_usec(CLOCK_MONOTONIC) + DEFAULT_WORKER_IDLE_TIMEOUT_USEC;
			sid_resource_create_time_event_source(worker_proxy_res, &worker_proxy->idle_timeout_es, CLOCK_MONOTONIC,
							      timeout_usec, 0, _on_worker_proxy_idle_timeout_event, NULL, worker_proxy_res);
			_change_worker_proxy_state(worker_proxy_res, WORKER_IDLE);
			*/
			_make_worker_exit(worker_proxy_res);
			break;
		case COMMS_CMD_CUSTOM:
			if (worker_proxy->recv_fn) {
				if (worker_proxy->recv_fn(worker_proxy_res, recv_data, recv_data_size, recv_fd, worker_proxy->recv_fn_arg) < 0)
					log_warning(ID(worker_proxy_res), "%s", _custom_message_handling_failed_msg);
			} else {
				log_warning(ID(worker_proxy_res), "%s", _no_custom_receive_function_msg);
				if (recv_data)
					free(recv_data);
			}
			break;
		default:
			log_error(ID(worker_proxy_res), INTERNAL_ERROR "%s%s", comms_cmd_str[recv_cmd], _unexpected_internal_command_msg);
			return -1;
	}

	return 0;
}

static int _on_worker_comms_event(sid_event_source *es, int fd, uint32_t revents, void *data)
{
	sid_resource_t *worker_res = data;
	struct worker *worker = sid_resource_get_data(worker_res);
	comms_cmd_t recv_cmd;
	void *recv_data;
	size_t recv_data_size;
	int recv_fd;

	if (_comms_recv(worker->comms_fd, &recv_cmd, &recv_data, &recv_data_size, &recv_fd) < 0)
		return -1;

	switch (recv_cmd) {
		case COMMS_CMD_CUSTOM:
			if (worker->recv_fn) {
				if (worker->recv_fn(worker_res, recv_data, recv_data_size, recv_fd, worker->recv_fn_arg) < 0)
					log_warning(ID(worker_res), "%s", _custom_message_handling_failed_msg);
			} else {
				log_warning(ID(worker_res), "%s", _no_custom_receive_function_msg);
				if (recv_data)
					free(recv_data);
			}
			break;
		default:
			log_error(ID(worker_res), INTERNAL_ERROR "%s%s", comms_cmd_str[recv_cmd], _unexpected_internal_command_msg);
			return -1;
	}

	return 0;
}

static int _on_worker_signal_event(sid_event_source *es, const struct signalfd_siginfo *si, void *userdata)
{
	sid_resource_t *res = userdata;

	log_print(ID(res), "Received signal %d from %d.", si->ssi_signo, si->ssi_pid);
	sid_resource_exit_event_loop(res);

	return 0;
}

static int _init_worker_proxy(sid_resource_t *worker_proxy_res, const void *kickstart_data, void **data)
{
	const struct worker_kickstart *kickstart = kickstart_data;
	struct worker_proxy *worker_proxy = NULL;

	if (!(worker_proxy = zalloc(sizeof(*worker_proxy)))) {
		log_error(ID(worker_proxy_res), "Failed to allocate worker_proxy structure.");
		goto fail;
	}

	worker_proxy->pid = kickstart->pid;
	worker_proxy->comms_fd = kickstart->comms_fd;
	worker_proxy->state = WORKER_NEW;

	if (sid_resource_create_child_event_source(worker_proxy_res, &worker_proxy->child_es, worker_proxy->pid, WEXITED,
						   _on_worker_proxy_child_event, NULL, worker_proxy_res) < 0) {
		log_error(ID(worker_proxy_res), "Failed to register worker process monitoring in worker proxy.");
		goto fail;
	}

	if (sid_resource_create_io_event_source(worker_proxy_res, &worker_proxy->comms_es, worker_proxy->comms_fd,
						_on_worker_proxy_comms_event, NULL, worker_proxy_res) < 0) {
		log_error(ID(worker_proxy_res), "Failed to register communication channel between worker and its proxy.");
		goto fail;
	}

	*data = worker_proxy;
	return 0;
fail:
	if (worker_proxy) {
		if (worker_proxy->child_es)
			(void) sid_resource_destroy_event_source(worker_proxy_res, &worker_proxy->child_es);
		if (worker_proxy->comms_es)
			(void) sid_resource_destroy_event_source(worker_proxy_res, &worker_proxy->comms_es);
		free(worker_proxy);
	}
	return -1;
}

static int _destroy_worker_proxy(sid_resource_t *worker_proxy_res)
{
	struct worker_proxy *worker_proxy = sid_resource_get_data(worker_proxy_res);

	if (worker_proxy->idle_timeout_es)
		(void) sid_resource_destroy_event_source(worker_proxy_res, &worker_proxy->idle_timeout_es);
	(void) sid_resource_destroy_event_source(worker_proxy_res, &worker_proxy->child_es);
	(void) sid_resource_destroy_event_source(worker_proxy_res, &worker_proxy->comms_es);
	(void) close(worker_proxy->comms_fd);

	free(worker_proxy);
	return 0;
}

static int _init_worker(sid_resource_t *worker_res, const void *kickstart_data, void **data)
{
	const struct worker_kickstart *kickstart = kickstart_data;
	struct worker *worker = NULL;

	if (!(worker = zalloc(sizeof(*worker)))) {
		log_error(ID(worker_res), "Failed to allocate new worker structure.");
		goto fail;
	}

	worker->comms_fd = kickstart->comms_fd;

	if (sid_resource_create_signal_event_source(worker_res, &worker->sigterm_es, SIGTERM, _on_worker_signal_event, NULL, worker_res) < 0 ||
	    sid_resource_create_signal_event_source(worker_res, &worker->sigint_es, SIGINT, _on_worker_signal_event, NULL, worker_res) < 0) {
		log_error(ID(worker_res), "Failed to create signal handlers.");
		goto fail;
	}

	if (sid_resource_create_io_event_source(worker_res, &worker->comms_es, worker->comms_fd, _on_worker_comms_event, NULL, worker_res) < 0) {
		log_error(ID(worker_res), "Failed to register worker <-> proxy channel.");
		goto fail;
	}

	*data = worker;
	return 0;
fail:
	if (worker) {
		if (worker->sigterm_es)
			(void) sid_resource_destroy_event_source(worker_res, &worker->sigterm_es);
		if (worker->sigint_es)
			(void) sid_resource_destroy_event_source(worker_res, &worker->sigint_es);
		if (worker->comms_es)
			(void) sid_resource_destroy_event_source(worker_res, &worker->comms_es);
		free(worker);
	}
	return -1;
}

static int _destroy_worker(sid_resource_t *worker_res)
{
	struct worker *worker = sid_resource_get_data(worker_res);

	(void) sid_resource_destroy_event_source(worker_res, &worker->comms_es);
	(void) sid_resource_destroy_event_source(worker_res, &worker->sigterm_es);
	(void) sid_resource_destroy_event_source(worker_res, &worker->sigint_es);

	(void) close(worker->comms_fd);

	free(worker);
	return 0;
}

static int _init_worker_control(sid_resource_t *worker_control_res, const void *kickstart_data, void **data)
{
	struct worker_control *worker_control;

	if (!(worker_control = zalloc(sizeof(*worker_control)))) {
		log_error(ID(worker_control_res), "Failed to allocate memory for worker control structure.");
		goto fail;
	}

	if (!(worker_control->worker_proxies_res = sid_resource_create(worker_control_res, &sid_resource_reg_aggregate,
								       SID_RESOURCE_RESTRICT_WALK_UP |
								       SID_RESOURCE_RESTRICT_WALK_DOWN |
								       SID_RESOURCE_DISALLOW_ISOLATION,
								       WORKER_PROXIES_AGGREGATE_ID, worker_control))) {
		log_error(ID(worker_control_res), "Failed to create aggregate resource for worker proxies.");
		goto fail;
	}

	*data = worker_control;
	return 0;
fail:
	if (worker_control) {
		free(worker_control);
	}
	return -1;
}

static int _destroy_worker_control(sid_resource_t *worker_control_res)
{
	struct worker_control *worker_control = sid_resource_get_data(worker_control_res);

	free(worker_control);
	return 0;
}

const sid_resource_reg_t sid_resource_reg_worker_proxy = {
	.name = WORKER_PROXY_NAME,
	.init = _init_worker_proxy,
	.destroy = _destroy_worker_proxy,
};

const sid_resource_reg_t sid_resource_reg_worker = {
	.name = WORKER_NAME,
	.init = _init_worker,
	.destroy = _destroy_worker,
	.with_event_loop = 1,
};

const sid_resource_reg_t sid_resource_reg_worker_control = {
	.name = WORKER_CONTROL_NAME,
	.init = _init_worker_control,
	.destroy = _destroy_worker_control,
};
