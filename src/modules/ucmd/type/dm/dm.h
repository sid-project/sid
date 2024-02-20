/*
 * This file is part of SID.
 *
 * Copyright (C) 2023 Red Hat, Inc. All rights reserved.
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

#ifndef _SID_UCMD_MOD_TYPE_DM_H
#define _SID_UCMD_MOD_TYPE_DM_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SID_UCMD_MOD_DM_FN_NAME_SUBSYS_MATCH "sid_ucmd_dm_subsys_match"
#define SID_UCMD_MOD_DM_SUBSYS_MATCH(fn)     SID_UCMD_FN(dm_subsys_match, _SID_UCMD_FN_CHECK_TYPE(fn))

#define DM_X_NAME                            "name"
#define DM_X_UUID                            "uuid"
#define DM_X_COOKIE_FLAGS                    "cookie_flags"

typedef uint16_t dm_cookie_flags_t;

#define DM_UDEV_DISABLE_DM_RULES_FLAG        0x0001
#define DM_UDEV_DISABLE_SUBSYSTEM_RULES_FLAG 0x0002
#define DM_UDEV_DISABLE_DISK_RULES_FLAG      0x0004
#define DM_UDEV_DISABLE_OTHER_RULES_FLAG     0x0008
#define DM_UDEV_LOW_PRIORITY_FLAG            0x0010
#define DM_UDEV_DISABLE_LIBRARY_FALLBACK     0x0020
#define DM_UDEV_PRIMARY_SOURCE_FLAG          0x0040

#define DM_SUBSYSTEM_UDEV_FLAG0              0x0100
#define DM_SUBSYSTEM_UDEV_FLAG1              0x0200
#define DM_SUBSYSTEM_UDEV_FLAG2              0x0400
#define DM_SUBSYSTEM_UDEV_FLAG3              0x0800
#define DM_SUBSYSTEM_UDEV_FLAG4              0x1000
#define DM_SUBSYSTEM_UDEV_FLAG5              0x2000
#define DM_SUBSYSTEM_UDEV_FLAG6              0x4000
#define DM_SUBSYSTEM_UDEV_FLAG7              0x8000

#ifdef __cplusplus
}
#endif

#endif
