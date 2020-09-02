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

struct module;

typedef int module_fn_t(struct module *module, void *cb_arg);

#define MODULE_FN(name, fn) module_fn_t *module_ ## name = fn;

#define MODULE_INIT(fn)     MODULE_FN(init, fn)
#define MODULE_EXIT(fn)     MODULE_FN(exit, fn)
#define MODULE_RELOAD(fn)   MODULE_FN(reload, fn)

const char *module_get_name(struct module *module);
void module_set_data(struct module *module, void *data);
void *module_get_data(struct module *module);

#ifdef __cplusplus
}
#endif

#endif
