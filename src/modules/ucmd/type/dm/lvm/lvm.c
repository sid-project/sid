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
#include "resource/ucmd-module.h"

#include <stdlib.h>

#define LVM_DM_UUID_PREFIX "LVM-"

SID_UCMD_MOD_PRIO(0)

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

	if (!(dm_name = sid_ucmd_kv_foreign_mod_get(mod_res, ucmd_ctx, "/type/dm", SID_KV_NS_DEVMOD, DM_X_NAME, NULL, NULL, 0)))
		goto out;

	if (!(vg_name = strdup(dm_name)))
		goto out;

	_unquote(lv_layer = _unquote(lv_name = _unquote(vg_name)));

	if (!*vg_name || !*lv_name)
		goto out;

	if (!sid_ucmd_kv_set(mod_res, ucmd_ctx, SID_KV_NS_UDEV, "DM_VG_NAME", vg_name, strlen(vg_name) + 1, SID_KV_FL_RD) ||
	    !sid_ucmd_kv_set(mod_res,
	                     ucmd_ctx,
	                     SID_KV_NS_DEVMOD,
	                     "vg_name",
	                     vg_name,
	                     strlen(vg_name) + 1,
	                     SID_KV_FL_SYNC | SID_KV_FL_RD) ||
	    !sid_ucmd_kv_set(mod_res, ucmd_ctx, SID_KV_NS_UDEV, "DM_LV_NAME", lv_name, strlen(lv_name) + 1, SID_KV_FL_RD) ||
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
		                     SID_KV_FL_RD) ||
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

static int _lvm_init(sid_res_t *mod_res, struct sid_ucmd_common_ctx *ucmd_common_ctx)
{
	sid_res_log_debug(mod_res, "init");
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

	if (!(uuid = sid_ucmd_kv_foreign_mod_get(mod_res, ucmd_ctx, "/type/dm", SID_KV_NS_DEVMOD, "uuid", NULL, NULL, 0)))
		return 0;

	return !strncmp(uuid, LVM_DM_UUID_PREFIX, sizeof(LVM_DM_UUID_PREFIX) - 1);
}
SID_UCMD_MOD_DM_SUBSYS_MATCH_CURRENT(_lvm_subsys_match_current)

static int _lvm_subsys_match_next(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	const char *type;

	if (!(type = sid_ucmd_kv_get(mod_res, ucmd_ctx, SID_KV_NS_UDEV, "ID_FS_TYPE", NULL, NULL, 0)))
		return 0;

	return !strcmp(type, "LVM2_member");
}
SID_UCMD_MOD_DM_SUBSYS_MATCH_NEXT(_lvm_subsys_match_next)

static int _lvm_scan_ident(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "ident");

	if (_store_component_names(mod_res, ucmd_ctx) < 0)
		return -1;

	return 0;
}
SID_UCMD_SCAN_IDENT(_lvm_scan_ident)

static int _lvm_scan_pre(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	static const char        failed_to_change_dev_rdy_msg[] = "Failed to change LVM device ready state";
	const dm_cookie_flags_t *flags;
	sid_ucmd_dev_ready_t     ready;
	int                      r = 0;

	sid_res_log_debug(mod_res, "scan-pre");

	ready = sid_ucmd_dev_ready_get(mod_res, ucmd_ctx, 0);

	if (ready < _SID_DEV_RDY)
		return 0;

	flags = sid_ucmd_kv_foreign_mod_get(mod_res, ucmd_ctx, "/type/dm", SID_KV_NS_DEVMOD, DM_X_COOKIE_FLAGS, NULL, NULL, 0);

	switch (ready) {
		case SID_DEV_RDY_PUBLIC:
		case SID_DEV_RDY_PRIVATE:
			if (flags && *flags & DM_SUBSYSTEM_UDEV_FLAG0) {
				if ((r = sid_ucmd_dev_ready_set(mod_res, ucmd_ctx, SID_DEV_RDY_UNINITIALIZED)) < 0)
					sid_res_log_error_errno(mod_res, r, failed_to_change_dev_rdy_msg);
			}
			break;

		case SID_DEV_RDY_UNINITIALIZED:
			if (!flags || !(*flags & DM_SUBSYSTEM_UDEV_FLAG0)) {
				if ((r = sid_ucmd_dev_ready_set(mod_res, ucmd_ctx, SID_DEV_RDY_PUBLIC)) < 0)
					sid_res_log_error_errno(mod_res, r, failed_to_change_dev_rdy_msg);
			}
			break;

		default:
			break;
	}

	return r;
}
SID_UCMD_SCAN_PRE(_lvm_scan_pre)

static int _lvm_scan_current(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-current");
	return 0;
}
SID_UCMD_SCAN_CURRENT(_lvm_scan_current)

static int _lvm_scan_next(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-next");
	return 0;
}
SID_UCMD_SCAN_NEXT(_lvm_scan_next)

static int _lvm_scan_post_current(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-post-current");
	return 0;
}
SID_UCMD_SCAN_POST_CURRENT(_lvm_scan_post_current)

static int _lvm_scan_post_next(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-post-next");
	return 0;
}
SID_UCMD_SCAN_POST_NEXT(_lvm_scan_post_next)

static int _lvm_scan_remove(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-remove");
	return 0;
}
SID_UCMD_SCAN_REMOVE(_lvm_scan_remove)
