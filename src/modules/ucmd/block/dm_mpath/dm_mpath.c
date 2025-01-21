/*
 * SPDX-FileCopyrightText: (C) 2017-2025 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "base/util.h"
#include "resource/ucmd-mod.h"

#include <libudev.h>
#include <mpath_valid.h>
#include <stdio.h>
#include <stdlib.h>

SID_UCMD_MOD_PRIO(-1)

#define U_DEV_PATH "DM_MULTIPATH_DEVICE_PATH"
#define X_VALID    "VALID"
#define X_WWID     "WWID"

static int _dm_mpath_init(sid_res_t *mod_res, struct sid_ucmd_common_ctx *ucmd_common_ctx)
{
	sid_res_log_debug(mod_res, "init");

	/* TODO - set up dm/udev logging */
	if (mpathvalid_init(MPATH_LOG_PRIO_NOLOG, MPATH_LOG_STDERR)) {
		sid_res_log_error(mod_res, "failed to initialize mpathvalid");
		return -1;
	}

	if (sid_ucmd_kv_reserve(mod_res, ucmd_common_ctx, SID_KV_NS_UDEV, U_DEV_PATH, SID_KV_FL_FRG_RD) < 0) {
		sid_res_log_error(mod_res, "Failed to reserve multipath udev key %s.", U_DEV_PATH);
		goto fail;
	}

	return 0;
fail:
	mpathvalid_exit();
	return -1;
}
SID_UCMD_MOD_INIT(_dm_mpath_init)

static int _dm_mpath_exit(sid_res_t *mod_res, struct sid_ucmd_common_ctx *ucmd_common_ctx)
{
	sid_res_log_debug(mod_res, "exit");

	if (sid_ucmd_kv_unreserve(mod_res, ucmd_common_ctx, SID_KV_NS_UDEV, U_DEV_PATH) < 0)
		sid_res_log_error(mod_res, "Failed to unreserve multipath udev key %s.", U_DEV_PATH);

	mpathvalid_exit();
	return 0;
}
SID_UCMD_MOD_EXIT(_dm_mpath_exit)

static int _kernel_cmdline_allow(void)
{
	char *value = NULL;

	if (!sid_util_kernel_get_arg("nompath", NULL, NULL) && !sid_util_kernel_get_arg("nompath", &value, NULL))
		return 1;
	if (value && strcmp(value, "off") != 0)
		return 1;
	return 0;
}

static int _dm_mpath_reset(sid_res_t *mod_res, struct sid_ucmd_common_ctx *ucmd_common_ctx)
{
	sid_res_log_debug(mod_res, "reset");
	return 0;
}
SID_UCMD_MOD_RESET(_dm_mpath_reset)

static int _is_parent_multipathed(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	const char **parent;
	const char  *valid_str;
	int          mpath_valid = MPATH_IS_ERROR;
	char        *p;
	int          r;

	parent = sid_ucmd_dev_stack_va_get(mod_res, ucmd_ctx, .method = SID_DEV_SEARCH_IMM_ANC, .ret_code = &r);
	if (r < 0 || !parent)
		return 0;

	valid_str = sid_ucmd_kv_va_get(mod_res, ucmd_ctx, .ns = SID_KV_NS_DEV, .frg_dev_id = parent[0], .key = X_VALID);
	free(parent);

	if (!valid_str || !valid_str[0])
		return 0;

	errno       = 0;
	mpath_valid = strtol(valid_str, &p, 10);
	if (errno || !p || *p)
		return 0;

	if (mpath_valid == MPATH_IS_VALID) {
		sid_res_log_debug(mod_res, "%s whole disk is a multipath path", sid_ucmd_ev_get_dev_name(ucmd_ctx));
		sid_ucmd_kv_va_set(mod_res, ucmd_ctx, .ns = SID_KV_NS_UDEV, .key = U_DEV_PATH, .val = "1", .fl = SID_KV_FL_RD);
		return 1;
	}

	sid_res_log_debug(mod_res, "%s whole disk is not a multipath path", sid_ucmd_ev_get_dev_name(ucmd_ctx));
	return 0;
}

static int _dm_mpath_scan_next(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	int   r;
	char *wwid;
	char  valid_str[2];

	sid_res_log_debug(mod_res, "scan-next");

	if (!_kernel_cmdline_allow()) // treat failure as allowed
		return 0;

	switch (sid_ucmd_ev_get_dev_type(ucmd_ctx)) {
		case UDEV_DEVTYPE_DISK:
			break;
		case UDEV_DEVTYPE_PARTITION:
			return _is_parent_multipathed(mod_res, ucmd_ctx);
		case UDEV_DEVTYPE_UNKNOWN:
			return 0;
	}

	if (mpathvalid_reload_config() < 0) {
		sid_res_log_error(mod_res, "failed to reinitialize mpathvalid");
		return -1;
	}
	// currently treats MPATH_SMART like MPATH_STRICT
	r = mpathvalid_is_path(sid_ucmd_ev_get_dev_name(ucmd_ctx), MPATH_DEFAULT, &wwid, NULL, 0);
	sid_res_log_debug(mod_res, "%s mpathvalid_is_path returned %d", sid_ucmd_ev_get_dev_name(ucmd_ctx), r);

	if (r == MPATH_IS_VALID) {
		const char *old_valid_str;
		char       *p;
		int         old_valid;

		old_valid_str = sid_ucmd_kv_va_get(mod_res, ucmd_ctx, .ns = SID_KV_NS_DEVMOD, .key = X_VALID);
		if (old_valid_str && old_valid_str[0]) {
			errno     = 0;
			old_valid = strtol(old_valid_str, &p, 10);
			// If old_valid is garbage assume the device
			// wasn't claimed before
			if (errno || !p || *p || old_valid != MPATH_IS_VALID) {
				sid_res_log_debug(mod_res,
				                  "previously released %s. not claiming",
				                  sid_ucmd_ev_get_dev_name(ucmd_ctx));
				r = MPATH_IS_NOT_VALID;
			}
		}
	} else if (r == MPATH_IS_VALID_NO_CHECK)
		r = MPATH_IS_VALID;

	if (r == MPATH_IS_VALID)
		sid_ucmd_kv_va_set(mod_res, ucmd_ctx, .ns = SID_KV_NS_UDEV, .key = U_DEV_PATH, .val = "1", .fl = SID_KV_FL_RD);
	else if (r != MPATH_IS_ERROR)
		sid_ucmd_kv_va_set(mod_res, ucmd_ctx, .ns = SID_KV_NS_UDEV, .key = U_DEV_PATH, .val = "0", .fl = SID_KV_FL_RD);

	if (r != MPATH_IS_ERROR && snprintf(valid_str, sizeof(valid_str), "%d", r) < sizeof(valid_str) && valid_str[0])
		sid_ucmd_kv_va_set(mod_res,
		                   ucmd_ctx,
		                   .ns  = SID_KV_NS_DEVMOD,
		                   .key = X_VALID,
		                   .val = valid_str,
		                   .fl  = SID_KV_FL_RD | SID_KV_FL_SCPS);
	if (wwid) {
		sid_ucmd_kv_va_set(mod_res,
		                   ucmd_ctx,
		                   .ns  = SID_KV_NS_DEVMOD,
		                   .key = X_WWID,
		                   .val = wwid,
		                   .fl  = SID_KV_FL_RD | SID_KV_FL_SCPS);
		free(wwid);
	}
	return (r != MPATH_IS_ERROR) ? 0 : -1;
}
SID_UCMD_SCAN_NEXT(_dm_mpath_scan_next)

static int _dm_mpath_scan_error(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-error");
	return 0;
}
SID_UCMD_SCAN_ERROR(_dm_mpath_scan_error)
