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
#include "resource/ucmd-module.h"

#include <limits.h>
#include <libudev.h>
#include <mpath_valid.h>
#include <stdio.h>
#include <stdlib.h>

#define ID "multipath_component"
#define PATH_KEY "DM_MULTIPATH_DEVICE_PATH"
#define VALID_KEY "SID_DM_MULTIPATH_VALID"
#define WWID_KEY "SID_DM_MULTIPATH_WWID"
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

static int _multipath_component_init(struct sid_module *module, struct sid_ucmd_mod_ctx *cmd_mod)
{
	log_debug(ID, "init");
	/* TODO - set up dm/udev logging */
	udev = udev_new();
	if (!udev) {
		log_error(ID, "failed to allocate udev context");
		return -1;
	}
	if (sid_ucmd_mod_reserve_kv(module, cmd_mod, KV_NS_UDEV,
	                            PATH_KEY) < 0) {
		log_error(ID, "Failed to reserve multipath udev key %s", PATH_KEY);
		udev_unref(udev);
		udev = NULL;
		return -1;
	}
	if (sid_ucmd_mod_reserve_kv(module, cmd_mod, KV_NS_DEVICE,
	                            VALID_KEY) < 0) {
		log_error(ID, "Failed to reserve multipath udev key %s", PATH_KEY);
		udev_unref(udev);
		udev = NULL;
		return -1;
	}
	if (sid_ucmd_mod_reserve_kv(module, cmd_mod, KV_NS_DEVICE,
	                            WWID_KEY) < 0) {
		log_error(ID, "Failed to reserve multipath device key %s", WWID_KEY);
		udev_unref(udev);
		udev = NULL;
		return -1;
	}
	return 0;
}
SID_UCMD_MOD_INIT(_multipath_component_init)

static int _multipath_component_exit(struct sid_module *module, struct sid_ucmd_mod_ctx *cmd_mod)
{
	log_debug(ID, "exit");
	// Do we need to unreserve the key here?
	udev_unref(udev);
	udev = NULL;
	return 0;
}
SID_UCMD_MOD_EXIT(_multipath_component_exit)

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


static int _multipath_component_reload(struct sid_module *module, struct sid_ucmd_mod_ctx *cmd_mod)
{
	log_debug(ID, "reload");
	return 0;
}
SID_UCMD_MOD_RELOAD(_multipath_component_reload)

static int _is_parent_multipathed(struct sid_ucmd_ctx *cmd)
{
	int r = MPATH_IS_ERROR;
	const char *valid_str;
	char *p;

	valid_str = sid_ucmd_part_get_disk_kv(cmd, VALID_KEY, NULL,
	                                      NULL);
	if (!valid_str || !valid_str[0])
		return 0;
	else {
		errno = 0;
		r = strtol(valid_str, &p, 10);
		if (errno || !p || *p)
			return 0;
	}
	if (r == MPATH_IS_VALID) {
		log_debug(ID, "%s whole disk is a multipath path",
		          sid_ucmd_dev_get_name(cmd));
		sid_ucmd_set_kv(cmd, KV_NS_UDEV, PATH_KEY, "1", 2,
		                KV_MOD_PROTECTED);
	} else
		log_debug(ID, "%s whole disk is not a multipath path",
		          sid_ucmd_dev_get_name(cmd));
	return 0;
}

static int _multipath_component_scan_pre(struct sid_module *module, struct sid_ucmd_ctx *cmd)
{
	int r;
	char *wwid;
	char valid_str[2];
	log_debug(ID, "scan-pre");

	if (!kernel_cmdline_allow()) // treat failure as allowed
		return 0;

	if (sid_ucmd_dev_get_type(cmd) == UDEV_DEVTYPE_UNKNOWN)
		return 0;

	if (sid_ucmd_dev_get_type(cmd) == UDEV_DEVTYPE_PARTITION)
		return _is_parent_multipathed(cmd);

	if (mpathvalid_init(-1) < 0) {
		log_error(ID, "failed to initialize mpathvalid");
		return -1;
	}
	// currently treats MPATH_SMART like MPATH_STRICT
	r = mpathvalid_is_path(sid_ucmd_dev_get_name(cmd), MPATH_DEFAULT,
	                       &wwid, NULL, 0);
	log_debug(ID, "%s mpathvalid_is_path returned %d",
	          sid_ucmd_dev_get_name(cmd), r);

	if (r == MPATH_IS_VALID) {
		const char *old_valid_str;
		char *p;
		int old_valid;

		old_valid_str = sid_ucmd_get_kv(cmd, KV_NS_DEVICE,
		                                VALID_KEY, NULL, NULL);
		if (old_valid_str && old_valid_str[0]) {
			errno = 0;
			old_valid = strtol(old_valid_str, &p, 10);
			// If old_valid is garbage assume the device
			// wasn't claimed before
			if (errno || !p || *p || old_valid != MPATH_IS_VALID) {
				log_debug(ID, "previously released %s. not claiming", sid_ucmd_dev_get_name(cmd));
				r = MPATH_IS_NOT_VALID;
			}
		}
	} else if (r == MPATH_IS_VALID_NO_CHECK)
		r = MPATH_IS_VALID;

	if (r == MPATH_IS_VALID)
		sid_ucmd_set_kv(cmd, KV_NS_UDEV, PATH_KEY, "1", 2,
		                KV_MOD_PROTECTED);
	else if (r != MPATH_IS_ERROR)
		sid_ucmd_set_kv(cmd, KV_NS_UDEV, PATH_KEY, "0", 2,
		                KV_MOD_PROTECTED);

	if (r != MPATH_IS_ERROR && snprintf(valid_str, sizeof(valid_str), "%d", r) < sizeof(valid_str) && valid_str[0])
		sid_ucmd_set_kv(cmd, KV_NS_DEVICE, VALID_KEY, valid_str,
		                sizeof(valid_str),
		                KV_MOD_PROTECTED | KV_PERSISTENT);
	if (wwid) {
		sid_ucmd_set_kv(cmd, KV_NS_DEVICE, WWID_KEY,
		                wwid, strlen(wwid) + 1,
		                KV_MOD_PROTECTED | KV_PERSISTENT);
		free(wwid);
	}
	mpathvalid_exit();
	return (r != MPATH_IS_ERROR)? 0 : -1;
}
SID_UCMD_SCAN_PRE(_multipath_component_scan_pre)

static int _multipath_component_error(struct sid_module *module, struct sid_ucmd_ctx *cmd)
{
	log_debug(ID, "error");
	return 0;
}
SID_UCMD_ERROR(_multipath_component_error)
