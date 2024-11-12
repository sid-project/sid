/*
 * SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _SID_INTERNAL_COMMON_H
#define _SID_INTERNAL_COMMON_H

#define SYSTEM_DEV_PATH              "/dev"
#define SYSTEM_SYSFS_PATH            "/sys"
#define SYSTEM_PROC_PATH             "/proc"

#define SYSTEM_SYSFS_SLAVES          "slaves"

#define UDEV_KEY_ACTION              "ACTION"
#define UDEV_KEY_DEVPATH             "DEVPATH"
#define UDEV_KEY_DEVTYPE             "DEVTYPE"
#define UDEV_KEY_MAJOR               "MAJOR"
#define UDEV_KEY_MINOR               "MINOR"
#define UDEV_KEY_SEQNUM              "SEQNUM"
#define UDEV_KEY_DISKSEQ             "DISKSEQ"
#define UDEV_KEY_SYNTH_UUID          "SYNTH_UUID"
#define UDEV_KEY_PARTN               "PARTN"

#define UDEV_VALUE_DEVTYPE_UNKNOWN   "unknown"
#define UDEV_VALUE_DEVTYPE_DISK      "disk"
#define UDEV_VALUE_DEVTYPE_PARTITION "partition"

typedef enum {
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

typedef enum {
	UDEV_DEVTYPE_UNKNOWN,
	UDEV_DEVTYPE_DISK,
	UDEV_DEVTYPE_PARTITION,
} udev_devtype_t;

#endif
