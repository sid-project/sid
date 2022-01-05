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

#ifndef _SID_RESOURCE_TYPE_REGS_H
#define _SID_RESOURCE_TYPE_REGS_H

#ifdef __cplusplus
extern "C" {
#endif

extern const sid_resource_type_t sid_resource_type_aggregate;
extern const sid_resource_type_t sid_resource_type_kv_store_ht;
extern const sid_resource_type_t sid_resource_type_kv_store_db;
extern const sid_resource_type_t sid_resource_type_module_registry;
extern const sid_resource_type_t sid_resource_type_sid;
extern const sid_resource_type_t sid_resource_type_ubridge;
extern const sid_resource_type_t sid_resource_type_worker_control;

#ifdef __cplusplus
}
#endif

#endif
