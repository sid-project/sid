/*
 * SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SID_BLKID_TYPE_H
#define SID_BLKID_TYPE_H

#include <stddef.h>

#define MOD_NAME_NONE      "-"
#define MOD_NAME_MD        "md"
#define MOD_NAME_BCACHE    "bcache"
#define MOD_NAME_CEPH      "ceph"
#define MOD_NAME_DRBD      "drbd"
#define MOD_NAME_DM        "dm"
#define MOD_NAME_UBI       "ubi"
#define MOD_NAME_VDO       "vdo"
#define MOD_NAME_STRATIS   "stratis"
#define MOD_NAME_BITLOCKER "bitlocker"
#define MOD_NAME_FILEVAULT "filevault"
#define MOD_NAME_SWAP      "swap"
#define MOD_NAME_FS        "fs"

struct blkid_type {
	const char *blkid_type_name;
	const char *module_name;
};

const struct blkid_type *blkid_type_lookup(const char *key, size_t len);

#endif
