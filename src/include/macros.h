/*
 * This file is part of SID.
 *
 * Copyright (C) 2019 Red Hat, Inc. All rights reserved.
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

#ifndef _SID_MACROS_H
#define _SID_MACROS_H

#define SYSTEM_DEV_PATH           "/dev"
#define SYSTEM_SYSFS_PATH         "/sys"
#define SYSTEM_PROC_PATH          "/proc"
#define SYSTEM_PROC_DEVICES_PATH  SYSTEM_PROC_PATH "/devices"

#define SYSTEM_SYSFS_SLAVES       "slaves"

#define SYSTEM_MAX_MAJOR          ((1U << 20) - 1)
#define SYSTEM_MAX_MINOR          ((1U << 12) - 1)

#define UBRIDGE_PROTOCOL          1
#define UBRIDGE_SOCKET_PATH       "\0sid-ubridge.socket"
#define UBRIDGE_SOCKET_PATH_LEN   (sizeof(UBRIDGE_SOCKET_PATH) - 1)

#endif
