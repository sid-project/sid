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

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

struct module;

typedef int64_t module_prio_t;
typedef int     module_fn_t(struct module *module, void *cb_arg);

#define MODULE_NAME_MAX_LEN 255
#define MODULE_NAME_DELIM   "/"

#define MODULE_FN(name, fn) module_fn_t *module_##name = fn;

#define MODULE_PRIO(val) module_prio_t module_prio = val;
#define MODULE_INIT(fn)  MODULE_FN(init, fn)
#define MODULE_EXIT(fn)  MODULE_FN(exit, fn)
#define MODULE_RESET(fn) MODULE_FN(reset, fn)

const char *module_get_full_name(struct module *module);
const char *module_get_name(struct module *module);
void        module_set_data(struct module *module, void *data);
void *      module_get_data(struct module *module);

#ifdef __cplusplus
}
#endif

#endif
