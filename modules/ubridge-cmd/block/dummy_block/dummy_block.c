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

#define ID "dummy_block"

static int _dummy_block_init(struct sid_module *module)
{
	log_debug(ID, "init");
	return 0;
}
SID_MODULE_INIT(_dummy_block_init)

static int _dummy_block_exit(struct sid_module *module)
{
	log_debug(ID, "exit");
	return 0;
}
SID_MODULE_EXIT(_dummy_block_exit)

static int _dummy_block_reload(struct sid_module *module)
{
	log_debug(ID, "reload");
	return 0;
}
SID_MODULE_RELOAD(_dummy_block_reload)

static int _dummy_block_ident(const struct sid_ubridge_cmd_context *cmd)
{
	log_debug(ID, "ident");
	return 0;
}
SID_UBRIDGE_CMD_IDENT(_dummy_block_ident)

static int _dummy_block_scan_pre(const struct sid_ubridge_cmd_context *cmd)
{
	log_debug(ID, "scan-pre");
	return 0;
}
SID_UBRIDGE_CMD_SCAN_PRE(_dummy_block_scan_pre)

static int _dummy_block_scan_current(const struct sid_ubridge_cmd_context *cmd)
{
	log_debug(ID, "scan-current");
	return 0;
}
SID_UBRIDGE_CMD_SCAN_CURRENT(_dummy_block_scan_current)

static int _dummy_block_scan_next(const struct sid_ubridge_cmd_context *cmd)
{
	log_debug(ID, "scan-next");
	return 0;
}
SID_UBRIDGE_CMD_SCAN_NEXT(_dummy_block_scan_next)

static int _dummy_block_scan_post_current(const struct sid_ubridge_cmd_context *cmd)
{
	log_debug(ID, "scan-post-current");
	return 0;
}
SID_UBRIDGE_CMD_SCAN_POST_CURRENT(_dummy_block_scan_post_current)

static int _dummy_block_scan_post_next(const struct sid_ubridge_cmd_context *cmd)
{
	log_debug(ID, "scan-post-next");
	return 0;
}
SID_UBRIDGE_CMD_SCAN_POST_NEXT(_dummy_block_scan_post_next)

static int _dummy_block_trigger_action_current(const struct sid_ubridge_cmd_context *cmd)
{
	log_debug(ID, "trigger-action-current");
	return 0;
}
SID_UBRIDGE_CMD_TRIGGER_ACTION_CURRENT(_dummy_block_trigger_action_current)

static int _dummy_block_trigger_action_next(const struct sid_ubridge_cmd_context *cmd)
{
	log_debug(ID, "trigger-action-next");
	return 0;
}
SID_UBRIDGE_CMD_TRIGGER_ACTION_NEXT(_dummy_block_trigger_action_next)

static int _dummy_block_error(const struct sid_ubridge_cmd_context *cmd)
{
	log_debug(ID, "error");
	return 0;
}
SID_UBRIDGE_CMD_ERROR(_dummy_block_error)
