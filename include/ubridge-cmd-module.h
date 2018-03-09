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

#include <stdint.h>
#include <module.h>
#include "types.h"

struct sid_ubridge_cmd_context;

typedef int sid_ubridge_cmd_fn_t(const struct sid_ubridge_cmd_context *cmd);

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
udev_action_t sid_ubridge_cmd_dev_get_action(const struct sid_ubridge_cmd_context *cmd);
int sid_ubridge_cmd_dev_get_major(const struct sid_ubridge_cmd_context *cmd);
int sid_ubridge_cmd_dev_get_minor(const struct sid_ubridge_cmd_context *cmd);
const char *sid_ubridge_cmd_dev_get_name(const struct sid_ubridge_cmd_context *cmd);
const char *sid_ubridge_cmd_dev_get_type(const struct sid_ubridge_cmd_context *cmd);
uint64_t sid_ubridge_cmd_dev_get_seqnum(const struct sid_ubridge_cmd_context *cmd);
void *sid_ubridge_cmd_dev_get_custom(const struct sid_ubridge_cmd_context *cmd);
const char *sid_ubridge_cmd_dev_get_synth_uuid(const struct sid_ubridge_cmd_context *cmd);
const char *sid_ubridge_cmd_dev_get_synth_arg_value(const struct sid_ubridge_cmd_context *cmd, const char *key);
const char *sid_ubridge_cmd_dev_get_uevent_env_value(const struct sid_ubridge_cmd_context *cmd, const char *key);

#endif
