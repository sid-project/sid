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

#ifndef _SID_MODULE_H
#define _SID_MODULE_H

#include "resource.h"

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

struct sid_mod;

typedef int64_t sid_mod_prio_t;
typedef int     sid_mod_cb_fn_t(sid_res_t *mod_res, void *cb_arg);

#define SID_MOD_NAME_MAX_LEN   255
#define SID_MOD_NAME_DELIM     "/"
#define SID_MOD_NAME_DELIM_LEN (sizeof(SID_MOD_NAME_DELIM) - 1)

#define SID_MOD_FN(name, fn)   sid_mod_cb_fn_t *sid_mod_##name = fn;

#define SID_MOD_PRIO(val)      sid_mod_prio_t sid_mod_prio = val;
#define SID_MOD_ALIASES(val)   const char *sid_mod_aliases = val "\0";
#define SID_MOD_INIT(fn)       SID_MOD_FN(init, fn)
#define SID_MOD_EXIT(fn)       SID_MOD_FN(exit, fn)
#define SID_MOD_RESET(fn)      SID_MOD_FN(reset, fn)

const char *sid_mod_name_full_get(sid_res_t *mod_res);
const char *sid_mod_name_get(sid_res_t *mod_res);
void        sid_mod_data_set(sid_res_t *mod_res, void *data);
void       *sid_mod_data_get(sid_res_t *mod_res);

#ifdef __cplusplus
}
#endif

#endif
