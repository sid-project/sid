/*
 * SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _SID_UCMD_MOD_TYPE_DM_H
#define _SID_UCMD_MOD_TYPE_DM_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SID_UCMD_MOD_DM_FN_NAME_SCAN_SUBSYS_MATCH_CURRENT "sid_ucmd_dm_scan_subsys_match_current"
#define SID_UCMD_MOD_DM_FN_NAME_SCAN_SUBSYS_MATCH_NEXT    "sid_ucmd_dm_scan_subsys_match_next"

#define SID_UCMD_MOD_DM_SCAN_SUBSYS_MATCH_CURRENT(fn)     SID_UCMD_FN(dm_scan_subsys_match_current, _SID_UCMD_FN_CHECK_TYPE(fn))
#define SID_UCMD_MOD_DM_SCAN_SUBSYS_MATCH_NEXT(fn)        SID_UCMD_FN(dm_scan_subsys_match_next, _SID_UCMD_FN_CHECK_TYPE(fn))

#define DM_X_NAME                                         "name"
#define DM_X_UUID                                         "uuid"
#define DM_X_COOKIE_FLAGS                                 "cookie_flags"

typedef uint16_t dm_cookie_fl_t;

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
