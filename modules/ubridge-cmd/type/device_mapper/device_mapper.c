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

#include "ubridge-cmd-module.h"
#include "log.h"

#define ID "dm"

static int _device_mapper_init(struct sid_module *module)
{
	log_debug(ID, "init");
	return 0;
}
SID_MODULE_INIT(_device_mapper_init)

static int _device_mapper_exit(struct sid_module *module)
{
	log_debug(ID, "exit");
	return 0;
}
SID_MODULE_EXIT(_device_mapper_exit)

static int _device_mapper_reload(struct sid_module *module)
{
	log_debug(ID, "reload");
	return 0;
}
SID_MODULE_RELOAD(_device_mapper_reload)

static int _device_mapper_ident (const struct sid_ubridge_cmd_context *cmd)
{
	log_debug(ID, "ident");
	return 0;
}
SID_UBRIDGE_CMD_IDENT(_device_mapper_ident)

static int _device_mapper_scan_pre(const struct sid_ubridge_cmd_context *cmd)
{
	log_debug(ID, "scan-pre");
	return 0;
}
SID_UBRIDGE_CMD_SCAN_PRE(_device_mapper_scan_pre)


static int _device_mapper_scan_current(const struct sid_ubridge_cmd_context *cmd)
{
	log_debug(ID, "scan-current");
	return 0;
}
SID_UBRIDGE_CMD_SCAN_CURRENT(_device_mapper_scan_current)

static int _device_mapper_scan_next(const struct sid_ubridge_cmd_context *cmd)
{
	log_debug(ID, "scan-next");
	return 0;
}
SID_UBRIDGE_CMD_SCAN_NEXT(_device_mapper_scan_next)

static int _device_mapper_scan_post_current(const struct sid_ubridge_cmd_context *cmd)
{
	log_debug(ID, "scan-post-current");
	return 0;
}
SID_UBRIDGE_CMD_SCAN_POST_CURRENT(_device_mapper_scan_post_current)

static int _device_mapper_scan_post_next(const struct sid_ubridge_cmd_context *cmd)
{
	log_debug(ID, "scan-post-next");
	return 0;
}
SID_UBRIDGE_CMD_SCAN_POST_NEXT(_device_mapper_scan_post_next)

static int _device_mapper_trigger_action_current(const struct sid_ubridge_cmd_context *cmd)
{
	log_debug(ID, "trigger-action-current");
	return 0;
}
SID_UBRIDGE_CMD_TRIGGER_ACTION_CURRENT(_device_mapper_trigger_action_current)

static int _device_mapper_trigger_action_next(const struct sid_ubridge_cmd_context *cmd)
{
	log_debug(ID, "trigger-action-next");
	return 0;
}
SID_UBRIDGE_CMD_TRIGGER_ACTION_NEXT(_device_mapper_trigger_action_next)

static int _device_mapper_error(const struct sid_ubridge_cmd_context *cmd)
{
	log_debug(ID, "error");
	return 0;
}
SID_UBRIDGE_CMD_ERROR(_device_mapper_error)
