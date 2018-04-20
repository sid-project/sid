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

#ifndef _SID_MODULE_REGISTRY_H
#define _SID_MODULE_REGISTRY_H

#include "module.h"
#include "resource.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SID_MODULE_NAME_SUFFIX                 ".so"
#define SID_MODULE_NAME_SUFFIX_LEN             (sizeof(SID_MODULE_NAME_SUFFIX) - 1)

/* For use in struct sid_module_registry_resource_resource_module_params.flags field. */
#define SID_MODULE_REGISTRY_PRELOAD            UINT64_C(0x0000000000000001)
#define SID_MODULE_REGISTRY_INDIRECT_CALLBACKS UINT64_C(0x0000000000000002)

/* For use in struct sid_module_symbol_params.flags field. */
#define SID_MODULE_SYMBOL_WARN_ON_MISSING      UINT64_C(0x0000000000000001)
#define SID_MODULE_SYMBOL_FAIL_ON_MISSING      UINT64_C(0x0000000000000002)
#define SID_MODULE_SYMBOL_INDIRECT             UINT64_C(0x0000000000000004)

struct sid_module_symbol_params {
	const char *name;
	uint64_t flags;
};

struct sid_module_registry_resource_params {
	const char *directory;
	uint64_t flags;
	const struct sid_module_symbol_params symbol_params[]; /* NULL-terminated list of symbol params */
};

sid_resource_t *sid_module_registry_load_module(sid_resource_t *module_registry_res, const char *module_name);
sid_resource_t *sid_module_registry_get_module(sid_resource_t *module_registry_res, const char *module_name);
int sid_module_registry_unload_module(sid_resource_t *module_res);
int sid_module_registry_get_module_symbols(sid_resource_t *module_res, const void ***ret);

int sid_module_registry_reload_modules(sid_resource_t *module_registry_res);
int sid_module_registry_reload_module(sid_resource_t *module_res);

#ifdef __cplusplus
}
#endif

#endif
