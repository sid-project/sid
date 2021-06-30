/*
 * This file is part of SID.
 *
 * Copyright (C) 2020 Red Hat, Inc. All rights reserved.
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

#ifndef _SID_INTERNAL_COMMON_H
#define _SID_INTERNAL_COMMON_H

#include "base/common.h"

#define SYSTEM_DEV_PATH          "/dev"
#define SYSTEM_SYSFS_PATH        "/sys"
#define SYSTEM_PROC_PATH         "/proc"
#define SYSTEM_PROC_DEVICES_PATH SYSTEM_PROC_PATH "/devices"

#define SYSTEM_SYSFS_SLAVES "slaves"

#define UDEV_KEY_ACTION     "ACTION"
#define UDEV_KEY_DEVPATH    "DEVPATH"
#define UDEV_KEY_DEVTYPE    "DEVTYPE"
#define UDEV_KEY_MAJOR      "MAJOR"
#define UDEV_KEY_MINOR      "MINOR"
#define UDEV_KEY_SEQNUM     "SEQNUM"
#define UDEV_KEY_SYNTH_UUID "SYNTH_UUID"

#define UDEV_VALUE_DEVTYPE_UNKNOWN   "unknown"
#define UDEV_VALUE_DEVTYPE_DISK      "disk"
#define UDEV_VALUE_DEVTYPE_PARTITION "partition"

typedef enum
{
	UDEV_ACTION_UNKNOWN,
	UDEV_ACTION_ADD,
	UDEV_ACTION_CHANGE,
	UDEV_ACTION_REMOVE,
	UDEV_ACTION_MOVE,
	UDEV_ACTION_ONLINE,
	UDEV_ACTION_OFFLINE,
	UDEV_ACTION_BIND,
	UDEV_ACTION_UNBIND
} udev_action_t;

typedef enum
{
	UDEV_DEVTYPE_UNKNOWN,
	UDEV_DEVTYPE_DISK,
	UDEV_DEVTYPE_PARTITION,
} udev_devtype_t;

#endif
