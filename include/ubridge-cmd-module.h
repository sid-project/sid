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

#ifndef _SID_UBRIDGE_CMD_MODULE_H
#define _SID_UBRIDGE_CMD_MODULE_H

#include "types.h"

#include <stdint.h>
#include <module.h>

#ifdef __cplusplus
extern "C" {
#endif

struct sid_ubridge_cmd_context;

typedef int sid_ubridge_cmd_fn_t(struct sid_module *module, struct sid_ubridge_cmd_context *cmd);

/*
 * Macros to register module's phase functions.
 */
#define SID_UBRIDGE_CMD_FN(name, fn)               sid_ubridge_cmd_fn_t *sid_ubridge_cmd_ ## name = fn;

#define SID_UBRIDGE_CMD_IDENT(fn)                  SID_UBRIDGE_CMD_FN(ident, fn)
#define SID_UBRIDGE_CMD_SCAN_PRE(fn)               SID_UBRIDGE_CMD_FN(scan_pre, fn)
#define SID_UBRIDGE_CMD_SCAN_CURRENT(fn)           SID_UBRIDGE_CMD_FN(scan_current, fn)
#define SID_UBRIDGE_CMD_SCAN_NEXT(fn)              SID_UBRIDGE_CMD_FN(scan_next, fn)
#define SID_UBRIDGE_CMD_SCAN_POST_CURRENT(fn)      SID_UBRIDGE_CMD_FN(scan_post_current, fn)
#define SID_UBRIDGE_CMD_SCAN_POST_NEXT(fn)         SID_UBRIDGE_CMD_FN(scan_post_next, fn)
#define SID_UBRIDGE_CMD_TRIGGER_ACTION_CURRENT(fn) SID_UBRIDGE_CMD_FN(trigger_action_current, fn)
#define SID_UBRIDGE_CMD_TRIGGER_ACTION_NEXT(fn)    SID_UBRIDGE_CMD_FN(trigger_action_next, fn)
#define SID_UBRIDGE_CMD_ERROR(fn)                  SID_UBRIDGE_CMD_FN(error, fn)

/*
 * Functions to retrieve device properties associated with given command context.
 */
udev_action_t sid_ubridge_cmd_dev_get_action(struct sid_ubridge_cmd_context *cmd);
int sid_ubridge_cmd_dev_get_major(struct sid_ubridge_cmd_context *cmd);
int sid_ubridge_cmd_dev_get_minor(struct sid_ubridge_cmd_context *cmd);
const char *sid_ubridge_cmd_dev_get_name(struct sid_ubridge_cmd_context *cmd);
const char *sid_ubridge_cmd_dev_get_type(struct sid_ubridge_cmd_context *cmd);
uint64_t sid_ubridge_cmd_dev_get_seqnum(struct sid_ubridge_cmd_context *cmd);
const char *sid_ubridge_cmd_dev_get_synth_uuid(struct sid_ubridge_cmd_context *cmd);

typedef enum {
	KV_NS_UDEV,
	KV_NS_GLOBAL,
	KV_NS_MODULE,
	KV_NS_DEVICE,
} sid_ubridge_cmd_kv_namespace_t;

#define KV_PERSIST       UINT64_C(0x0000000000000001)
#define KV_MOD_PROTECT   UINT64_C(0x0000000000000002)
#define KV_MOD_PRIVATIZE UINT64_C(0x0000000000000004)
#define KV_MOD_RESERVE   UINT64_C(0x0000000000000008)

void *sid_ubridge_cmd_set_kv(struct sid_ubridge_cmd_context *cmd, sid_ubridge_cmd_kv_namespace_t ns,
			     const char *key, const void *value, size_t value_size, uint64_t flags);
const void *sid_ubridge_cmd_get_kv(struct sid_ubridge_cmd_context *cmd, sid_ubridge_cmd_kv_namespace_t ns,
				   const char *key, size_t *value_size, uint64_t *flags);
#ifdef __cplusplus
}
#endif

#endif
