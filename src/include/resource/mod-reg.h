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

#ifndef _SID_MOD_REG_H
#define _SID_MOD_REG_H

#include "resource/mod.h"
#include "resource/res.h"

#ifdef __cplusplus
extern "C" {
#endif

/* For use in struct module_registry_resource_resource_module_params.flags field. */
#define SID_MOD_REG_FL_PRELOAD         UINT64_C(0x0000000000000001)

/* For use in struct module_symbol_params.flags field. */
#define SID_MOD_SYM_FL_WARN_ON_MISSING UINT64_C(0x0000000000000001)
#define SID_MOD_SYM_FL_FAIL_ON_MISSING UINT64_C(0x0000000000000002)
#define SID_MOD_SYM_FL_INDIRECT        UINT64_C(0x0000000000000004)

struct sid_mod_sym_params {
	const char *name;  /* module symbol name */
	uint64_t    flags; /* SID_MOD_SYM_FL_* flags */
};

#define SID_MOD_NULL_SYM_PARAMS ((const struct sid_mod_sym_params) {.name = NULL, .flags = 0})

struct sid_mod_reg_res_params {
	const char                      *directory;     /* directory with modules */
	const char                      *module_prefix; /* common prefix for all modules */
	const char                      *module_suffix; /* common suffix for all modules */
	uint64_t                         flags;         /* SID_MOD_REG_FL_* flags */
	void                            *cb_arg;        /* custom arg passed to module_cb_fn_t (init/exit/reset callbacks) */
	const struct sid_mod_sym_params *symbol_params; /* NULL-terminated list of symbol params */
};

int        sid_mod_reg_load_mods(sid_res_t *mod_registry_res);
sid_res_t *sid_mod_reg_load_mod(sid_res_t *mod_registry_res, const char *mod_name);
sid_res_t *sid_mod_reg_get_mod(sid_res_t *mod_registry_res, const char *mod_name);
int        sid_mod_reg_unload_mod(sid_res_t *mod_res);
int        sid_mod_reg_get_mod_syms(sid_res_t *mod_res, const void ***ret);

int sid_mod_reg_reset_mods(sid_res_t *mod_registry_res);
int sid_mod_reg_reset_mod(sid_res_t *mod_res);

int sid_mod_reg_add_mod_subreg(sid_res_t *mod_res, sid_res_t *mod_subregistry_res);

bool sid_mod_reg_match_dep(sid_res_t *res1, sid_res_t *res2);

#ifdef __cplusplus
}
#endif

#endif
