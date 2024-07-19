/*
 * This file is part of SID.
 *
 * Copyright (C) 2023 Red Hat, Inc. All rights reserved.
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

#include "../dm.h"
#include "internal/util.h"
#include "resource/ucmd-module.h"
#include "resource/worker-control.h"

#include <limits.h>
#include <stdlib.h>

#define LVM_DM_UUID_PREFIX "LVM-"

SID_UCMD_MOD_PRIO(0)

#define LVM_EXEC_BIN_PATH    SBINDIR "/lvm"
#define LVM_VG_NAME_COMPLETE "LVM_VG_NAME_COMPLETE"

/* _unquote from lvm2 source code: libdm/libdm-string */
static char *_unquote(char *component)
{
	char *c = component;
	char *o = c;
	char *r;

	while (*c) {
		if (*(c + 1)) {
			if (*c == '-') {
				if (*(c + 1) == '-')
					c++;
				else
					break;
			}
		}
		*o = *c;
		o++;
		c++;
	}

	r  = (*c) ? c + 1 : c;
	*o = '\0';

	return r;
}

static int _store_component_names(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	const char *dm_name;
	char       *vg_name = NULL, *lv_name, *lv_layer;
	int         r       = -1;

	if (!(dm_name = sid_ucmd_kv_get_foreign_mod(mod_res, ucmd_ctx, "/type/dm", SID_KV_NS_DEVMOD, DM_X_NAME, NULL, NULL, 0)))
		goto out;

	if (!(vg_name = strdup(dm_name)))
		goto out;

	_unquote(lv_layer = _unquote(lv_name = _unquote(vg_name)));

	if (!*vg_name || !*lv_name)
		goto out;

	if (!sid_ucmd_kv_set(mod_res,
	                     ucmd_ctx,
	                     SID_KV_NS_UDEV,
	                     "DM_VG_NAME",
	                     vg_name,
	                     strlen(vg_name) + 1,
	                     SID_KV_FL_SYNC | SID_KV_FL_RD) ||
	    !sid_ucmd_kv_set(mod_res,
	                     ucmd_ctx,
	                     SID_KV_NS_DEVMOD,
	                     "vg_name",
	                     vg_name,
	                     strlen(vg_name) + 1,
	                     SID_KV_FL_SYNC | SID_KV_FL_RD) ||
	    !sid_ucmd_kv_set(mod_res,
	                     ucmd_ctx,
	                     SID_KV_NS_UDEV,
	                     "DM_LV_NAME",
	                     lv_name,
	                     strlen(lv_name) + 1,
	                     SID_KV_FL_SYNC | SID_KV_FL_RD) ||
	    !sid_ucmd_kv_set(mod_res,
	                     ucmd_ctx,
	                     SID_KV_NS_DEVMOD,
	                     "lv_name",
	                     lv_name,
	                     strlen(lv_name) + 1,
	                     SID_KV_FL_SYNC | SID_KV_FL_RD))
		goto out;

	if (*lv_layer) {
		if (!sid_ucmd_kv_set(mod_res,
		                     ucmd_ctx,
		                     SID_KV_NS_UDEV,
		                     "DM_LV_LAYER",
		                     lv_layer,
		                     strlen(lv_layer) + 1,
		                     SID_KV_FL_SYNC | SID_KV_FL_RD) ||
		    !sid_ucmd_kv_set(mod_res,
		                     ucmd_ctx,
		                     SID_KV_NS_DEVMOD,
		                     "lv_layer",
		                     lv_layer,
		                     strlen(lv_layer) + 1,
		                     SID_KV_FL_SYNC | SID_KV_FL_RD))
			goto out;
	}

	r = 1;
out:
	free(vg_name);
	return r;
}

struct out_ctx {
	sid_res_t           *mod_res;
	struct sid_ucmd_ctx *ucmd_ctx;
	bool                 store_kv;
};

static int _process_out_line(const char *line, size_t len, bool merge_back, void *data)
{
	sid_res_t      *proxy_res = data;
	struct out_ctx *ctx       = sid_wrk_ctl_get_worker_arg(proxy_res);
	char            line_buf[LINE_MAX];
	char           *key, *val;
	int             r;

	sid_res_log_debug(proxy_res, "OUT: %s", line);

	if (!ctx->store_kv)
		return 0;

	if (len > LINE_MAX - 1)
		return -ENOBUFS;

	memcpy(line_buf, line, len);
	line_buf[len] = '\0';

	if ((r = util_str_get_kv(line_buf, &key, &val) < 0))
		return r;

	if (!(sid_ucmd_kv_set(ctx->mod_res, ctx->ucmd_ctx, SID_KV_NS_DEVMOD, key, val, strlen(val) + 1, SID_KV_FL_NONE)))
		return -EREMOTEIO;

	return 0;
}

static int _process_err_line(const char *line, size_t len, bool merge_back, void *data)
{
	struct out_ctx *ctx = sid_wrk_ctl_get_worker_arg(data);
	sid_res_log_debug(ctx->mod_res, "ERR: %s", line);

	return 0;
}

static int _runner_stdout_recv_fn(sid_res_t *proxy_res, struct sid_wrk_chan *chan, struct sid_wrk_data_spec *data_spec, void *arg)
{
	return util_str_iterate_tokens(data_spec->data, "\n", NULL, _process_out_line, proxy_res);
}

static int _runner_stderr_recv_fn(sid_res_t *proxy_res, struct sid_wrk_chan *chan, struct sid_wrk_data_spec *data_spec, void *arg)
{
	return util_str_iterate_tokens(data_spec->data, "\n", NULL, _process_err_line, proxy_res);
}

static int _lvm_init(sid_res_t *mod_res, struct sid_ucmd_common_ctx *ucmd_common_ctx)
{
	sid_res_t *runner_res;

	sid_res_log_debug(mod_res, "init");

	struct sid_wrk_ctl_res_params runner_params = {
		.worker_type = SID_WRK_TYPE_EXTERNAL,
		.channel_specs =
			(struct sid_wrk_chan_spec[]) {
				{
					.id = "stdout",
					.wire =
						(struct sid_wrk_wire_spec) {
							.type              = SID_WRK_WIRE_PIPE_TO_PRX,
							.ext.used          = true,
							.ext.pipe.fd_redir = STDOUT_FILENO,
						},
					.proxy_rx =
						(struct sid_wrk_lane_spec) {
							.cb =
								(struct sid_wrk_lane_cb_spec) {
									.fn = _runner_stdout_recv_fn,
								},
							.data_suffix = (struct iovec) {.iov_base = "", .iov_len = 1},
						},
				},
				{
					.id = "stderr",
					.wire =
						(struct sid_wrk_wire_spec) {
							.type              = SID_WRK_WIRE_PIPE_TO_PRX,
							.ext.used          = true,
							.ext.pipe.fd_redir = STDERR_FILENO,
						},
					.proxy_rx =
						(struct sid_wrk_lane_spec) {
							.cb =
								(struct sid_wrk_lane_cb_spec) {
									.fn = _runner_stderr_recv_fn,
								},
							.data_suffix = (struct iovec) {.iov_base = "", .iov_len = 1},
						},
				},
				SID_WRK_NULL_CHAN_SPEC,
			},
		.timeout_spec =
			(struct sid_wrk_timeout_spec) {
				.usec   = 5000000,
				.signum = SIGKILL,
			},
	};

	if (!(runner_res = sid_res_create(mod_res,
	                                  &sid_res_type_wrk_ctl,
	                                  SID_RES_FL_NONE,
	                                  "lvm runner",
	                                  &runner_params,
	                                  SID_RES_PRIO_NORMAL,
	                                  SID_RES_NO_SERVICE_LINKS))) {
		sid_res_log_error(mod_res, "Failed to create command runner.");
		return -1;
	}

	sid_mod_set_data(mod_res, runner_res);
	return 0;
}
SID_UCMD_MOD_INIT(_lvm_init)

static int _lvm_exit(sid_res_t *mod_res, struct sid_ucmd_common_ctx *ucmd_common_ctx)
{
	sid_res_log_debug(mod_res, "exit");
	return 0;
}
SID_UCMD_MOD_EXIT(_lvm_exit)

static int _lvm_reset(sid_res_t *mod_res, struct sid_ucmd_common_ctx *ucmd_common_ctx)
{
	sid_res_log_debug(mod_res, "reset");
	return 0;
}
SID_UCMD_MOD_RESET(_lvm_reset)

static int _lvm_subsys_match_current(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	const char *uuid;

	sid_res_log_debug(mod_res, "scan-dm-subsys-match");

	if (!(uuid = sid_ucmd_kv_get_foreign_mod(mod_res, ucmd_ctx, "/type/dm", SID_KV_NS_DEVMOD, "uuid", NULL, NULL, 0)))
		return 0;

	return !strncmp(uuid, LVM_DM_UUID_PREFIX, sizeof(LVM_DM_UUID_PREFIX) - 1);
}
SID_UCMD_MOD_DM_SCAN_SUBSYS_MATCH_CURRENT(_lvm_subsys_match_current)

static int _lvm_subsys_match_next(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	const char *type;

	sid_res_log_debug(mod_res, "scan-dm-subsys-match-next");

	if (!(type = sid_ucmd_kv_get(mod_res, ucmd_ctx, SID_KV_NS_UDEV, "ID_FS_TYPE", NULL, NULL, 0)))
		return 0;

	return !strcmp(type, "LVM2_member");
}
SID_UCMD_MOD_DM_SCAN_SUBSYS_MATCH_NEXT(_lvm_subsys_match_next)

static int _lvm_scan_a_init(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-a-init");

	if (_store_component_names(mod_res, ucmd_ctx) < 0)
		return -1;

	return 0;
}
SID_UCMD_SCAN_A_INIT(_lvm_scan_a_init)

static int _lvm_scan_pre(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	static const char        failed_to_change_dev_rdy_msg[] = "Failed to change LVM device ready state";
	const dm_cookie_flags_t *flags;
	sid_ucmd_dev_ready_t     ready;
	int                      r = 0;

	sid_res_log_debug(mod_res, "scan-pre");

	ready = sid_ucmd_dev_get_ready(mod_res, ucmd_ctx, 0);

	if (ready < _SID_DEV_RDY)
		return 0;

	flags = sid_ucmd_kv_get_foreign_mod(mod_res, ucmd_ctx, "/type/dm", SID_KV_NS_DEVMOD, DM_X_COOKIE_FLAGS, NULL, NULL, 0);

	switch (ready) {
		case SID_DEV_RDY_PUBLIC:
		case SID_DEV_RDY_PRIVATE:
			if (flags && *flags & DM_SUBSYSTEM_UDEV_FLAG0) {
				if ((r = sid_ucmd_dev_set_ready(mod_res, ucmd_ctx, SID_DEV_RDY_UNINITIALIZED)) < 0)
					sid_res_log_error_errno(mod_res, r, failed_to_change_dev_rdy_msg);
			}
			break;

		case SID_DEV_RDY_UNINITIALIZED:
			if (!flags || !(*flags & DM_SUBSYSTEM_UDEV_FLAG0)) {
				if ((r = sid_ucmd_dev_set_ready(mod_res, ucmd_ctx, SID_DEV_RDY_PUBLIC)) < 0)
					sid_res_log_error_errno(mod_res, r, failed_to_change_dev_rdy_msg);
			}
			break;

		default:
			break;
	}

	return r;
}
SID_UCMD_SCAN_PRE(_lvm_scan_pre)

static int _lvm_scan_next(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_t            *runner_res = sid_mod_get_data(mod_res);
	char                 *cmd_line;
	int                   r;
	struct sid_wrk_params wrk_pvscan;

	sid_res_log_debug(mod_res, "scan-next");

	if (!(cmd_line = util_str_comb_to_str(NULL,
	                                      NULL,
	                                      "pvscan --cache --listvg --checkcomplete --vgonline --autoactivation event "
	                                      "--udevoutput --journal=output /dev/",
	                                      sid_ucmd_ev_get_dev_name(ucmd_ctx))))
		return -1;

	wrk_pvscan = (struct sid_wrk_params) {
		.id                 = "pvscan",
		.external.exec_file = LVM_EXEC_BIN_PATH,
		.external.args      = cmd_line,
		.worker_proxy_arg   = &((struct out_ctx) {.mod_res = mod_res, .ucmd_ctx = ucmd_ctx, .store_kv = true}),
		.timeout_spec       = (struct sid_wrk_timeout_spec) {
			      .usec   = 20000000,
			      .signum = SIGKILL,
                }};

	if ((r = sid_wrk_ctl_run_new_worker(runner_res, &wrk_pvscan, SID_RES_NO_SERVICE_LINKS)) < 0) {
		sid_res_log_error_errno(mod_res, r, "Failed to run %s", wrk_pvscan.id);
		free(cmd_line);
		return -1;
	}

	free(cmd_line);
	return 0;
}
SID_UCMD_SCAN_NEXT(_lvm_scan_next)

static int _lvm_scan_action_next(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	const char           *val;
	sid_res_t            *runner_res;
	char                 *cmd_line = NULL;
	struct sid_wrk_params wrk_vgchange;
	int                   r = -1;

	sid_res_log_debug(mod_res, "scan-action-next");

	if ((val = sid_ucmd_kv_get(mod_res, ucmd_ctx, SID_KV_NS_DEVMOD, LVM_VG_NAME_COMPLETE, NULL, NULL, 0))) {
		runner_res = sid_mod_get_data(mod_res);

		if (!(cmd_line = util_str_comb_to_str(NULL, NULL, "vgchange -aay --autoactivation event ", val)))
			goto out;

		wrk_vgchange = (struct sid_wrk_params) {
			.id                 = "vgchange",
			.external.exec_file = LVM_EXEC_BIN_PATH,
			.external.args      = cmd_line,
			.worker_proxy_arg   = &((struct out_ctx) {.mod_res = mod_res, .ucmd_ctx = ucmd_ctx, .store_kv = false}),
			.timeout_spec       = (struct sid_wrk_timeout_spec) {
				      .usec   = 20000000,
				      .signum = SIGKILL,
                        }};

		if ((r = sid_wrk_ctl_run_new_worker(runner_res, &wrk_vgchange, SID_RES_NO_SERVICE_LINKS)) < 0) {
			sid_res_log_error_errno(mod_res, r, "Failed to run %s", wrk_vgchange.id);
			goto out;
		}

		if (!(sid_ucmd_kv_set(mod_res, ucmd_ctx, SID_KV_NS_DEVMOD, LVM_VG_NAME_COMPLETE, NULL, 0, SID_KV_FL_NONE))) {
			sid_res_log_error(mod_res, "Failed to store value for key \"%s\"", LVM_VG_NAME_COMPLETE);
			goto out;
		}
	}

	r = 0;
out:
	free(cmd_line);
	return r;
}
SID_UCMD_SCAN_ACTION_NEXT(_lvm_scan_action_next)

static int _lvm_scan_error(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-error");
	return 0;
}
SID_UCMD_SCAN_ERROR(_lvm_scan_error)
