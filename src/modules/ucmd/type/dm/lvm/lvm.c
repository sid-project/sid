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
#include "internal/mem.h"
#include "log/log.h"
#include "resource/module-registry.h"
#include "resource/ucmd-module.h"

#include <stdlib.h>

#define LVM_DM_UUID_PREFIX "LVM-"

SID_UCMD_MOD_PRIO(0)

static int _lvm_init(sid_resource_t *mod_res, struct sid_ucmd_common_ctx *ucmd_common_ctx)
{
	sid_resource_log_debug(mod_res, "init");
	return 0;
}
SID_UCMD_MOD_INIT(_lvm_init)

static int _lvm_exit(sid_resource_t *mod_res, struct sid_ucmd_common_ctx *ucmd_common_ctx)
{
	sid_resource_log_debug(mod_res, "exit");
	return 0;
}
SID_UCMD_MOD_EXIT(_lvm_exit)

static int _lvm_reset(sid_resource_t *mod_res, struct sid_ucmd_common_ctx *ucmd_common_ctx)
{
	sid_resource_log_debug(mod_res, "reset");
	return 0;
}
SID_UCMD_MOD_RESET(_lvm_reset)

static int _lvm_subsys_match(sid_resource_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	const char *uuid;

	if (!(uuid = sid_ucmd_get_foreign_mod_kv(mod_res, ucmd_ctx, "/type/dm", KV_NS_DEVMOD, "uuid", NULL, NULL, 0)))
		return 0;

	return !strncmp(uuid, LVM_DM_UUID_PREFIX, sizeof(LVM_DM_UUID_PREFIX) - 1);
}
SID_UCMD_MOD_DM_SUBSYS_MATCH(_lvm_subsys_match)

static int _lvm_ident(sid_resource_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_resource_log_debug(mod_res, "ident");
	return 0;
}
SID_UCMD_IDENT(_lvm_ident)

static int _lvm_scan_pre(sid_resource_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_resource_log_debug(mod_res, "scan-pre");
	return 0;
}
SID_UCMD_SCAN_PRE(_lvm_scan_pre)

static int _lvm_scan_current(sid_resource_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_resource_log_debug(mod_res, "scan-current");
	return 0;
}
SID_UCMD_SCAN_CURRENT(_lvm_scan_current)

static int _lvm_scan_next(sid_resource_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_resource_log_debug(mod_res, "scan-next");
	return 0;
}
SID_UCMD_SCAN_NEXT(_lvm_scan_next)

static int _lvm_scan_post_current(sid_resource_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_resource_log_debug(mod_res, "scan-post-current");
	return 0;
}
SID_UCMD_SCAN_POST_CURRENT(_lvm_scan_post_current)

static int _lvm_scan_post_next(sid_resource_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_resource_log_debug(mod_res, "scan-post-next");
	return 0;
}
SID_UCMD_SCAN_POST_NEXT(_lvm_scan_post_next)

static int _lvm_scan_remove(sid_resource_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_resource_log_debug(mod_res, "scan-remove");
	return 0;
}
SID_UCMD_SCAN_REMOVE(_lvm_scan_remove)
