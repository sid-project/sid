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

#include "log/log.h"
#include "base/util.h"
#include "resource/ubridge-cmd-module.h"

#include <limits.h>
#include <libudev.h>
#include <mpath_valid.h>
#include <stdio.h>

#define ID "multipath_component"
#define KEY "DM_MULTIPATH_DEVICE_PATH"
struct udev *udev;
int logsink = -1;

struct config *get_multipath_config(void)
{
	return mpathvalid_conf;
}

void put_multipath_config(__attribute__((unused))void *conf)
{
	/* Noop */
}

static int _multipath_component_init(struct sid_module *module, struct sid_ubridge_cmd_mod_context *cmd_mod)
{
	log_debug(ID, "init");
	/* TODO - set up dm/udev logging */
	udev = udev_new();
	if (!udev) {
		log_error(ID, "failed to allocate udev context");
		return -1;
	}
	if (sid_ubridge_cmd_mod_reserve_kv(module, cmd_mod, KV_NS_UDEV,
	                                   KEY) < 0) {
		log_error(ID, "Failed to reserve multipath udev key %s", KEY);
		udev_unref(udev);
		udev = NULL;
		return -1;
	}
	return 0;
}
SID_UBRIDGE_CMD_MOD_INIT(_multipath_component_init)

static int _multipath_component_exit(struct sid_module *module, struct sid_ubridge_cmd_mod_context *cmd_mod)
{
	log_debug(ID, "exit");
	// Do we need to unreserve the key here?
	udev_unref(udev);
	udev = NULL;
	return 0;
}
SID_UBRIDGE_CMD_MOD_EXIT(_multipath_component_exit)

static int kernel_cmdline_allow(void)
{
	char *value;
	if (!util_cmdline_get_arg("nompath", NULL, NULL) &&
	    !util_cmdline_get_arg("nompath", &value, NULL))
		return 1;
	if (value && strcmp(value, "off") != 0)
		return 1;
	return 0;
}


static int _multipath_component_reload(struct sid_module *module, struct sid_ubridge_cmd_mod_context *cmd_mod)
{
	log_debug(ID, "reload");
	return 0;
}
SID_UBRIDGE_CMD_MOD_RELOAD(_multipath_component_reload)

static int _multipath_component_scan_pre(struct sid_module *module, struct sid_ubridge_cmd_context *cmd)
{
	int r;
	log_debug(ID, "scan-pre");

	if (!kernel_cmdline_allow()) // treat failure as allowed
		return 0;

	if (mpathvalid_init(-1) < 0) {
		log_error(ID, "failed to initialize mpathvalid");
		return -1;
	}
	// currently treats MPATH_SMART like MPATH_STRICT
	r = mpathvalid_is_path(sid_ubridge_cmd_dev_get_name(cmd), MPATH_DEFAULT,
	                       NULL, NULL, 0);
	log_debug(ID, "mpathvalid_is_path returned %d", r);
	if (r == MPATH_IS_VALID || r == MPATH_IS_VALID_NO_CHECK) {
		sid_ubridge_cmd_set_kv(cmd, KV_NS_UDEV, KEY, "1", 2,
		                       KV_MOD_PROTECTED);
		// mark with appropriate key=value pair
	} else if (r != MPATH_IS_ERROR) {
		sid_ubridge_cmd_set_kv(cmd, KV_NS_UDEV, KEY, "0", 2,
		                       KV_MOD_PROTECTED);
	}
	mpathvalid_exit();
	return (r != MPATH_IS_ERROR);
}
SID_UBRIDGE_CMD_SCAN_PRE(_multipath_component_scan_pre)

static int _multipath_component_error(struct sid_module *module, struct sid_ubridge_cmd_context *cmd)
{
	log_debug(ID, "error");
	return 0;
}
SID_UBRIDGE_CMD_ERROR(_multipath_component_error)
