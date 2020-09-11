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

#ifndef _SID_MODULE_REGISTRY_H
#define _SID_MODULE_REGISTRY_H

#include "resource/module.h"
#include "resource/resource.h"

#ifdef __cplusplus
extern "C" {
#endif

/* For use in struct module_registry_resource_resource_module_params.flags field. */
#define MODULE_REGISTRY_PRELOAD            UINT64_C(0x0000000000000001)

/* For use in struct module_symbol_params.flags field. */
#define MODULE_SYMBOL_WARN_ON_MISSING      UINT64_C(0x0000000000000001)
#define MODULE_SYMBOL_FAIL_ON_MISSING      UINT64_C(0x0000000000000002)
#define MODULE_SYMBOL_INDIRECT             UINT64_C(0x0000000000000004)

struct module_symbol_params {
	const char *name; /* module name (without suffix) */
	uint64_t flags;   /* MODULE_SYMBOL_* flags */
};

#define NULL_MODULE_SYMBOL_PARAMS ((const struct module_symbol_params) {.name = NULL, .flags = 0})

struct module_registry_resource_params {
	const char *directory;                            /* directory with modules */
	const char *module_prefix;                        /* common prefix for all modules */
	const char *module_suffix;                        /* common suffix for all modules */
	uint64_t flags;                                   /* MODULE_REGISTRY_* flags */
	void *cb_arg;                                     /* custom arg passed to module_fn_t (init/exit/reload callbacks) */
	const struct module_symbol_params *symbol_params; /* NULL-terminated list of symbol params */
};

sid_resource_t *module_registry_load_module(sid_resource_t *module_registry_res, const char *module_name);
sid_resource_t *module_registry_get_module(sid_resource_t *module_registry_res, const char *module_name);
int module_registry_unload_module(sid_resource_t *module_res);
int module_registry_get_module_symbols(sid_resource_t *module_res, const void ***ret);

int module_registry_reload_modules(sid_resource_t *module_registry_res);
int module_registry_reload_module(sid_resource_t *module_res);

#ifdef __cplusplus
}
#endif

#endif
