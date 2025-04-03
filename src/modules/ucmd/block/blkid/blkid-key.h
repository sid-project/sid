/*
 * SPDX-FileCopyrightText: (C) 2017-2025 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SID_BLKID_KEY_H
#define SID_BLKID_KEY_H

#include <stddef.h>

#define BLKID_FL_NONE 0x00
#define BLKID_FL_ORIG 0x01
#define BLKID_FL_SAFE 0x02
#define BLKID_FL_ENC  0x04

struct blkid_xkey {
	unsigned    num;
	const char *name;
	unsigned    flags;
};

struct blkid_key {
	const char              *blkid_key_name;
	const struct blkid_xkey *xkey;
};

enum {
	U_ID_FS_TYPE,
	U_ID_FS_USAGE,
	U_ID_FS_VERSION,
	U_ID_FS_UUID,
	U_ID_FS_UUID_ENC,
	U_ID_FS_UUID_SUB,
	U_ID_FS_UUID_SUB_ENC,
	U_ID_FS_LABEL,
	U_ID_FS_LABEL_ENC,
	U_ID_FS_SIZE,
	U_ID_FS_LASTBLOCK,
	U_ID_FS_BLOCKSIZE,
	U_ID_FS_SYSTEM_ID,
	U_ID_FS_PUBLISHER_ID,
	U_ID_FS_APPLICATION_ID,
	U_ID_FS_BOOT_SYSTEM_ID,
	U_ID_FS_VOLUME_ID,
	U_ID_FS_LOGICAL_VOLUME_ID,
	U_ID_FS_VOLUME_SET_ID,
	U_ID_FS_DATA_PREPARER_ID,
	U_ID_PART_TABLE_UUID,
	U_ID_PART_TABLE_TYPE,
	U_ID_PART_ENTRY_SCHEME,
	U_ID_PART_ENTRY_NAME,
	U_ID_PART_ENTRY_TYPE,
	U_ID_PART_ENTRY_UUID,
	U_ID_PART_ENTRY_FLAGS,
	U_ID_PART_ENTRY_NUMBER,
	U_ID_PART_ENTRY_OFFSET,
	U_ID_PART_ENTRY_SIZE,
	U_ID_PART_ENTRY_DISK,
	U_ID_NUM_KEYS,
};

extern const struct blkid_xkey blkid_xkey_arr[];

const struct blkid_key *blkid_key_lookup(const char *key, size_t len);

#endif
