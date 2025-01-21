/*
 * SPDX-FileCopyrightText: (C) 2017-2025 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _SID_MOD_H
#define _SID_MOD_H

#include "res.h"

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

const char *sid_mod_get_full_name(sid_res_t *mod_res);
const char *sid_mod_get_name(sid_res_t *mod_res);
void        sid_mod_set_data(sid_res_t *mod_res, void *data);
void       *sid_mod_get_data(sid_res_t *mod_res);

#ifdef __cplusplus
}
#endif

#endif
