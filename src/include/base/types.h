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

#ifndef _SID_TYPES_H
#define _SID_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

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

#ifdef __cplusplus
}
#endif

#endif
