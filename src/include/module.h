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

#ifndef _SID_MODULE_H
#define _SID_MODULE_H

#ifdef __cplusplus
extern "C" {
#endif

struct sid_module;

typedef int sid_module_fn_t (struct sid_module *module, void *arg);

#define SID_MODULE_FN(name, fn) sid_module_fn_t *sid_module_ ## name = fn;

#define SID_MODULE_INIT(fn)     SID_MODULE_FN(init, fn)
#define SID_MODULE_EXIT(fn)     SID_MODULE_FN(exit, fn)
#define SID_MODULE_RELOAD(fn)   SID_MODULE_FN(reload, fn)

const char *sid_module_get_name(struct sid_module *module);
void sid_module_set_data(struct sid_module *module, void *data);
void *sid_module_get_data(struct sid_module *module);

#ifdef __cplusplus
}
#endif

#endif
