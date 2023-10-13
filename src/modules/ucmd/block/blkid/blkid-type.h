/*
 * This file is part of SID.
 *
 * Copyright (C) 2017-2023 Red Hat, Inc. All rights reserved.
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
