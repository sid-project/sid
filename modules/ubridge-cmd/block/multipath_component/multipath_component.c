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

#include <mpath_valid.h>

#define ID "multipath_component"

static int _multipath_component_init(struct sid_module *module, struct sid_ubridge_cmd_mod_context *cmd_mod)
{
	log_debug(ID, "init");
	return 0;
}
SID_UBRIDGE_CMD_MOD_INIT(_multipath_component_init)

static int _multipath_component_exit(struct sid_module *module, struct sid_ubridge_cmd_mod_context *cmd_mod)
{
	log_debug(ID, "exit");
	return 0;
}
SID_UBRIDGE_CMD_MOD_EXIT(_multipath_component_exit)

static int _multipath_component_reload(struct sid_module *module, struct sid_ubridge_cmd_mod_context *cmd_mod)
{
	log_debug(ID, "reload");
	return 0;
}
SID_UBRIDGE_CMD_MOD_RELOAD(_multipath_component_reload)

static int _multipath_component_scan_pre(struct sid_module *module, struct sid_ubridge_cmd_context *cmd)
{
	log_debug(ID, "scan-pre");

	if (mpath_is_path(sid_ubridge_cmd_dev_get_name(cmd), MPATH_NORMAL)) {
		// mark with appropriate key=value pair
	}

	return 0;
}
SID_UBRIDGE_CMD_SCAN_PRE(_multipath_component_scan_pre)

static int _multipath_component_error(struct sid_module *module, struct sid_ubridge_cmd_context *cmd)
{
	log_debug(ID, "error");
	return 0;
}
SID_UBRIDGE_CMD_ERROR(_multipath_component_error)
