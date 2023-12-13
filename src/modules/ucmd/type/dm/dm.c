/*
 * This file is part of SID.
 *
 * Copyright (C) 2020 Red Hat, Inc. All rights reserved.
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

#include "internal/comp-attrs.h"

#include "dm.h"

#include "base/util.h"
#include "internal/mem.h"
#include "log/log.h"
#include "resource/module-registry.h"
#include "resource/ucmd-module.h"

#include <limits.h>
#include <linux/dm-ioctl.h>
#include <stdio.h>
#include <stdlib.h>

#define DM_ID                "dm"
#define DM_SUBMODULES_ID     DM_ID "_sub"
#define DM_SUBMODULE_ID_NONE "none"

SID_UCMD_MOD_PRIO(0)
SID_UCMD_MOD_ALIASES("device_mapper")

static struct module_symbol_params dm_submod_symbol_params[] = {
	{
		SID_UCMD_MOD_DM_FN_NAME_SUBSYS_MATCH,
		MODULE_SYMBOL_FAIL_ON_MISSING | MODULE_SYMBOL_INDIRECT,
	},
	{
		SID_UCMD_MOD_FN_NAME_IDENT,
		MODULE_SYMBOL_FAIL_ON_MISSING | MODULE_SYMBOL_INDIRECT,
	},
	{
		SID_UCMD_MOD_FN_NAME_SCAN_PRE,
		MODULE_SYMBOL_INDIRECT,
	},
	{
		SID_UCMD_MOD_FN_NAME_SCAN_CURRENT,
		MODULE_SYMBOL_INDIRECT,
	},
	{
		SID_UCMD_MOD_FN_NAME_SCAN_NEXT,
		MODULE_SYMBOL_INDIRECT,
	},
	{
		SID_UCMD_MOD_FN_NAME_SCAN_POST_CURRENT,
		MODULE_SYMBOL_INDIRECT,
	},
	{
		SID_UCMD_MOD_FN_NAME_SCAN_POST_NEXT,
		MODULE_SYMBOL_INDIRECT,
	},
	{
		SID_UCMD_MOD_FN_NAME_SCAN_REMOVE,
		MODULE_SYMBOL_INDIRECT,
	},
	NULL_MODULE_SYMBOL_PARAMS,
};

struct dm_submod_fns {
	sid_ucmd_fn_t *subsys_match;
	sid_ucmd_fn_t *ident;
	sid_ucmd_fn_t *scan_pre;
	sid_ucmd_fn_t *scan_current;
	sid_ucmd_fn_t *scan_next;
	sid_ucmd_fn_t *scan_post_current;
	sid_ucmd_fn_t *scan_post_next;
	sid_ucmd_fn_t *scan_remove;
} __packed;

struct dm_mod_ctx {
	sid_resource_t *submod_registry;
	sid_resource_t *submod_res_current;
	sid_resource_t *submod_res_next;
};

static int _dm_init(sid_resource_t *mod_res, struct sid_ucmd_common_ctx *ucmd_common_ctx)
{
	struct dm_mod_ctx *dm_mod = NULL;

	sid_resource_log_debug(mod_res, "init");

	if (!(dm_mod = mem_zalloc(sizeof(*dm_mod)))) {
		sid_resource_log_error(mod_res, "Failed to allocate memory module context structure.");
		return -1;
	}

	struct module_registry_resource_params dm_submod_registry_res_mod_params = {
		.directory     = SID_UCMD_TYPE_MOD_DIR "/" DM_ID,
		.module_prefix = NULL,
		.module_suffix = ".so",
		.flags         = 0,
		.symbol_params = dm_submod_symbol_params,
		.cb_arg        = ucmd_common_ctx,
	};

	if (!(dm_mod->submod_registry = sid_resource_create(SID_RESOURCE_NO_PARENT,
	                                                    &sid_resource_type_module_registry,
	                                                    SID_RESOURCE_NO_FLAGS,
	                                                    DM_SUBMODULES_ID,
	                                                    &dm_submod_registry_res_mod_params,
	                                                    SID_RESOURCE_PRIO_NORMAL,
	                                                    SID_RESOURCE_NO_SERVICE_LINKS))) {
		sid_resource_log_error(mod_res, "Failed to create submodule registry.");
		goto fail;
	}

	if (module_registry_add_module_subregistry(mod_res, dm_mod->submod_registry) < 0) {
		sid_resource_log_error(mod_res, "Failed to attach submodule registry.");
		goto fail;
	}

	if (module_registry_load_modules(dm_mod->submod_registry) < 0) {
		sid_resource_log_error(mod_res, "Failed to load submodules.");
		goto fail;
	}

	module_set_data(mod_res, dm_mod);
	return 0;
fail:
	if (dm_mod->submod_registry)
		sid_resource_unref(dm_mod->submod_registry);
	free(dm_mod);
	return -1;
}
SID_UCMD_MOD_INIT(_dm_init)

static int _dm_exit(sid_resource_t *mod_res, struct sid_ucmd_common_ctx *ucmd_common_ctx)
{
	struct dm_mod_ctx *dm_mod;

	sid_resource_log_debug(mod_res, "exit");

	dm_mod = module_get_data(mod_res);
	free(dm_mod);

	return 0;
}
SID_UCMD_MOD_EXIT(_dm_exit)

static int _dm_reset(sid_resource_t *mod_res, struct sid_ucmd_common_ctx *ucmd_common_ctx)
{
	sid_resource_log_debug(mod_res, "reset");
	return 0;
}
SID_UCMD_MOD_RESET(_dm_reset)

static int _dm_ident(sid_resource_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	char                  path[PATH_MAX];
	char                  name[DM_NAME_LEN];
	char                  uuid[DM_UUID_LEN];
	struct dm_mod_ctx    *dm_mod;
	sid_resource_iter_t  *iter;
	sid_resource_t       *submod_res;
	const char           *submod_name = NULL;
	struct dm_submod_fns *submod_fns;

	sid_resource_log_debug(mod_res, "ident");

	snprintf(path, sizeof(path), "%s%s/dm/uuid", SYSTEM_SYSFS_PATH, sid_ucmd_event_get_dev_path(ucmd_ctx));
	if (sid_util_sysfs_get_value(path, uuid, sizeof(uuid)) < 0) {
		sid_resource_log_error(mod_res, "Failed to get DM uuid.");
		return -1;
	}
	sid_ucmd_dev_add_alias(mod_res, ucmd_ctx, "uuid", uuid);
	sid_ucmd_set_kv(mod_res, ucmd_ctx, KV_NS_DEVMOD, "uuid", uuid, strlen(uuid) + 1, KV_SYNC | KV_SUB_RD);

	snprintf(path, sizeof(path), "%s%s/dm/name", SYSTEM_SYSFS_PATH, sid_ucmd_event_get_dev_path(ucmd_ctx));
	if (sid_util_sysfs_get_value(path, name, sizeof(name)) < 0) {
		sid_resource_log_error(mod_res, "Failed to get DM name.");
		return -1;
	}
	sid_ucmd_dev_add_alias(mod_res, ucmd_ctx, "name", name);
	sid_ucmd_set_kv(mod_res, ucmd_ctx, KV_NS_DEVMOD, "name", name, strlen(name) + 1, KV_SYNC | KV_SUB_RD);

	dm_mod      = module_get_data(mod_res);
	submod_name = sid_ucmd_get_kv(mod_res, ucmd_ctx, KV_NS_DEVICE, DM_SUBMODULES_ID, NULL, NULL, 0);

	if (submod_name) {
		if (strcmp(submod_name, DM_SUBMODULE_ID_NONE) != 0) {
			if (!(dm_mod->submod_res_current = module_registry_get_module(dm_mod->submod_registry, submod_name))) {
				sid_resource_log_debug(mod_res, "Module %s not loaded.", submod_name);
				return 0;
			}
		}
	} else {
		if (!(iter = sid_resource_iter_create(dm_mod->submod_registry))) {
			sid_resource_log_error(mod_res, "Failed to create submodule iterator.");
			return -1;
		}

		while ((submod_res = sid_resource_iter_next(iter))) {
			if (module_registry_get_module_symbols(submod_res, (const void ***) &submod_fns) < 0) {
				sid_resource_log_error(mod_res,
				                       "Failed to retrieve submodule symbols from submodule %s.",
				                       ID(submod_res));
				continue;
			}

			if (submod_fns->subsys_match) {
				if (submod_fns->subsys_match(submod_res, ucmd_ctx)) {
					dm_mod->submod_res_current = submod_res;
					submod_name                = sid_resource_get_id(submod_res);
					sid_resource_log_debug(mod_res, "%s submodule claimed this DM device.", submod_name);
					break;
				}
			}
		}

		sid_resource_iter_destroy(iter);

		if (!submod_name)
			submod_name = DM_SUBMODULE_ID_NONE;

		sid_ucmd_set_kv(mod_res, ucmd_ctx, KV_NS_DEVICE, DM_SUBMODULES_ID, submod_name, strlen(submod_name) + 1, KV_FRG_RD);
	}

	if (!dm_mod->submod_res_current)
		return 0;

	module_registry_get_module_symbols(dm_mod->submod_res_current, (const void ***) &submod_fns);
	if (submod_fns && submod_fns->ident)
		(void) submod_fns->ident(dm_mod->submod_res_current, ucmd_ctx);

	return 0;
}
SID_UCMD_IDENT(_dm_ident)

static int _dm_scan_pre(sid_resource_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	struct dm_mod_ctx    *dm_mod;
	struct dm_submod_fns *submod_fns;

	sid_resource_log_debug(mod_res, "scan-pre");

	dm_mod = module_get_data(mod_res);

	if (!dm_mod->submod_res_current)
		return 0;

	module_registry_get_module_symbols(dm_mod->submod_res_current, (const void ***) &submod_fns);
	if (submod_fns && submod_fns->scan_pre)
		(void) submod_fns->scan_pre(dm_mod->submod_res_current, ucmd_ctx);

	return 0;
}
SID_UCMD_SCAN_PRE(_dm_scan_pre)

static int _dm_scan_current(sid_resource_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	struct dm_mod_ctx    *dm_mod;
	struct dm_submod_fns *submod_fns;

	sid_resource_log_debug(mod_res, "scan-current");

	dm_mod = module_get_data(mod_res);

	if (!dm_mod->submod_res_current)
		return 0;

	module_registry_get_module_symbols(dm_mod->submod_res_current, (const void ***) &submod_fns);
	if (submod_fns && submod_fns->scan_current)
		(void) submod_fns->scan_current(dm_mod->submod_res_current, ucmd_ctx);

	return 0;
}
SID_UCMD_SCAN_CURRENT(_dm_scan_current)

static int _dm_scan_next(sid_resource_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	struct dm_mod_ctx    *dm_mod;
	const char           *val;
	const char           *submod_name = NULL;
	struct dm_submod_fns *submod_fns;

	sid_resource_log_debug(mod_res, "scan-next");

	if ((val = sid_ucmd_get_kv(mod_res, ucmd_ctx, KV_NS_UDEV, "ID_FS_TYPE", NULL, NULL, 0))) {
		if (!strcmp(val, "LVM2_member") || !strcmp(val, "LVM1_member"))
			submod_name = "lvm";
		else if (!strcmp(val, "DM_snapshot_cow"))
			submod_name = "snap";
		else if (!strcmp(val, "DM_verity_hash") || !strcmp(val, "DM_integrity"))
			submod_name = "verity";
		else if (!strcmp(val, "crypto_LUKS"))
			submod_name = "luks";
	}

	if (!submod_name)
		return 0;

	dm_mod = module_get_data(mod_res);

	if (!(dm_mod->submod_res_next = module_registry_get_module(dm_mod->submod_registry, submod_name))) {
		sid_resource_log_debug(mod_res, "Module %s not loaded.", submod_name);
		return 0;
	}

	module_registry_get_module_symbols(dm_mod->submod_res_next, (const void ***) &submod_fns);
	if (submod_fns && submod_fns->scan_next)
		(void) submod_fns->scan_next(dm_mod->submod_res_next, ucmd_ctx);

	return 0;
}
SID_UCMD_SCAN_NEXT(_dm_scan_next)

static int _dm_scan_post_current(sid_resource_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	struct dm_mod_ctx    *dm_mod;
	struct dm_submod_fns *submod_fns;

	sid_resource_log_debug(mod_res, "scan-post-current");

	dm_mod = module_get_data(mod_res);

	if (!dm_mod->submod_res_current)
		return 0;

	module_registry_get_module_symbols(dm_mod->submod_res_current, (const void ***) &submod_fns);
	if (submod_fns && submod_fns->scan_post_current)
		(void) submod_fns->scan_post_current(dm_mod->submod_res_current, ucmd_ctx);

	return 0;
}
SID_UCMD_SCAN_POST_CURRENT(_dm_scan_post_current)

static int _dm_scan_post_next(sid_resource_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	struct dm_mod_ctx    *dm_mod;
	struct dm_submod_fns *submod_fns;

	sid_resource_log_debug(mod_res, "scan-post-next");

	dm_mod = module_get_data(mod_res);

	if (!(dm_mod->submod_res_next))
		return 0;

	module_registry_get_module_symbols(dm_mod->submod_res_next, (const void ***) &submod_fns);
	if (submod_fns && submod_fns->scan_post_next)
		(void) submod_fns->scan_post_next(dm_mod->submod_res_next, ucmd_ctx);

	return 0;
}
SID_UCMD_SCAN_POST_NEXT(_dm_scan_post_next)

static int _dm_scan_remove(sid_resource_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	struct dm_mod_ctx    *dm_mod;
	struct dm_submod_fns *submod_fns;

	sid_resource_log_debug(mod_res, "scan-remove");

	dm_mod = module_get_data(mod_res);

	if (!dm_mod->submod_res_current)
		return 0;

	module_registry_get_module_symbols(dm_mod->submod_res_current, (const void ***) &submod_fns);
	if (submod_fns && submod_fns->scan_remove)
		(void) submod_fns->scan_remove(dm_mod->submod_res_current, ucmd_ctx);

	return 0;
}
SID_UCMD_SCAN_REMOVE(_dm_scan_remove)

static int _dm_error(sid_resource_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_resource_log_debug(mod_res, "error");
	return 0;
}
SID_UCMD_ERROR(_dm_error)
