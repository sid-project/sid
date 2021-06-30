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

#include "internal/mem.h"
#include "log/log.h"
#include "resource/module-registry.h"
#include "resource/ucmd-module.h"

#include <stdlib.h>

#define DM_ID            "dm"
#define DM_SUBMODULES_ID DM_ID "_sub"

SID_UCMD_MOD_PRIO(0)

static struct module_symbol_params dm_submod_symbol_params[] = {
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
};

struct dm_submod_fns {
	sid_ucmd_fn_t *ident;
	sid_ucmd_fn_t *scan_pre;
	sid_ucmd_fn_t *scan_current;
	sid_ucmd_fn_t *scan_next;
	sid_ucmd_fn_t *scan_post_current;
	sid_ucmd_fn_t *scan_post_next;
} __attribute__((packed));

struct dm_mod_ctx {
	sid_resource_t *submod_registry;
	sid_resource_t *submod_res_current;
	sid_resource_t *submod_res_next;
};

static int _dm_init(struct module *module, struct sid_ucmd_mod_ctx *ucmd_mod_ctx)
{
	struct dm_mod_ctx *dm_mod = NULL;
	int                r;

	log_debug(DM_ID, "init");

	if (!(dm_mod = mem_zalloc(sizeof(*dm_mod)))) {
		log_error(DM_ID, "Failed to allocate memory module context structure.");
		r = -ENOMEM;
	}

	struct module_registry_resource_params dm_submod_registry_res_mod_params = {
		.directory     = SID_UCMD_TYPE_MOD_DIR "/" DM_ID,
		.module_prefix = NULL,
		.module_suffix = ".so",
		.flags         = MODULE_REGISTRY_PRELOAD,
		.symbol_params = dm_submod_symbol_params,
		.cb_arg        = NULL,
	};

	if (!(dm_mod->submod_registry = sid_resource_create(NULL,
	                                                    &sid_resource_type_module_registry,
	                                                    SID_RESOURCE_NO_FLAGS,
	                                                    DM_SUBMODULES_ID,
	                                                    &dm_submod_registry_res_mod_params,
	                                                    SID_RESOURCE_PRIO_NORMAL,
	                                                    SID_RESOURCE_NO_SERVICE_LINKS))) {
		log_error(DM_ID, "Failed to create submodule registry.");
		r = -1;
		goto fail;
	}

	if ((r = sid_ucmd_mod_add_mod_subregistry(module, ucmd_mod_ctx, dm_mod->submod_registry)) < 0) {
		sid_resource_destroy(dm_mod->submod_registry);
		log_error(DM_ID, "Failed to attach submodule registry.");
		goto fail;
	}

	module_set_data(module, dm_mod);
	return 0;
fail:
	free(dm_mod);
	return r;
}
SID_UCMD_MOD_INIT(_dm_init)

static int _dm_exit(struct module *module, struct sid_ucmd_mod_ctx *ucmd_mod_ctx)
{
	struct dm_mod_ctx *dm_mod;

	log_debug(DM_ID, "exit");

	dm_mod = module_get_data(module);
	free(dm_mod);

	return 0;
}
SID_UCMD_MOD_EXIT(_dm_exit)

static int _dm_reset(struct module *module, struct sid_ucmd_mod_ctx *ucmd_mod_ctx)
{
	log_debug(DM_ID, "reset");
	return 0;
}
SID_UCMD_MOD_RESET(_dm_reset)

static int _dm_ident(struct module *module, struct sid_ucmd_ctx *ucmd_ctx)
{
	log_debug(DM_ID, "ident");
	return 0;
}
SID_UCMD_IDENT(_dm_ident)

static int _dm_scan_pre(struct module *module, struct sid_ucmd_ctx *ucmd_ctx)
{
	log_debug(DM_ID, "scan-pre");
	return 0;
}
SID_UCMD_SCAN_PRE(_dm_scan_pre)

static int _dm_scan_current(struct module *module, struct sid_ucmd_ctx *ucmd_ctx)
{
	log_debug(DM_ID, "scan-current");
	return 0;
}
SID_UCMD_SCAN_CURRENT(_dm_scan_current)

static int _dm_scan_next(struct module *module, struct sid_ucmd_ctx *ucmd_ctx)
{
	log_debug(DM_ID, "scan-next");
	return 0;
}
SID_UCMD_SCAN_NEXT(_dm_scan_next)

static int _dm_scan_post_current(struct module *module, struct sid_ucmd_ctx *ucmd_ctx)
{
	log_debug(DM_ID, "scan-post-current");
	return 0;
}
SID_UCMD_SCAN_POST_CURRENT(_dm_scan_post_current)

static int _dm_scan_post_next(struct module *module, struct sid_ucmd_ctx *ucmd_ctx)
{
	log_debug(DM_ID, "scan-post-next");
	return 0;
}
SID_UCMD_SCAN_POST_NEXT(_dm_scan_post_next)

static int _dm_error(struct module *module, struct sid_ucmd_ctx *ucmd_ctx)
{
	log_debug(DM_ID, "error");
	return 0;
}
SID_UCMD_ERROR(_dm_error)
