/*
 * SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "blkid-type.h"
#include "resource/ucmd-mod.h"

#include <blkid/blkid.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

SID_UCMD_MOD_PRIO(0)

enum {
	U_FS_TYPE = 0,
	U_FS_USAGE,
	U_FS_VERSION,
	U_FS_UUID,
	U_FS_UUID_ENC,
	U_FS_UUID_SUB,
	U_FS_UUID_SUB_ENC,
	U_FS_LABEL,
	U_FS_LABEL_ENC,
	U_PART_TABLE_TYPE,
	U_PART_TABLE_UUID,
	U_PART_ENTRY_NAME,
	U_PART_ENTRY_TYPE,
	U_FS_SYSTEM_ID,
	U_FS_PUBLISHER_ID,
	U_FS_APPLICATION_ID,
	U_FS_BOOT_SYSTEM_ID,
	_UDEV_KEY_START = U_FS_TYPE,
	_UDEV_KEY_END   = U_FS_BOOT_SYSTEM_ID,
	D_NEXT_MOD,
	_DEVICE_KEY_START = D_NEXT_MOD,
	_DEVICE_KEY_END   = D_NEXT_MOD,

	_NUM_KEYS
};

static const char *keys[_NUM_KEYS] = {
	[U_FS_TYPE]           = "ID_FS_TYPE",
	[U_FS_USAGE]          = "ID_FS_USAGE",
	[U_FS_VERSION]        = "ID_FS_VERSION",
	[U_FS_UUID]           = "ID_FS_UUID",
	[U_FS_UUID_ENC]       = "ID_FS_UUID_ENC",
	[U_FS_UUID_SUB]       = "ID_FS_UUID_SUB",
	[U_FS_UUID_SUB_ENC]   = "ID_FS_UUID_SUB_ENC",
	[U_FS_LABEL]          = "ID_FS_LABEL",
	[U_FS_LABEL_ENC]      = "ID_FS_LABEL_ENC",
	[U_PART_TABLE_TYPE]   = "ID_PART_TABLE_TYPE",
	[U_PART_TABLE_UUID]   = "ID_PART_TABLE_UUID",
	[U_PART_ENTRY_NAME]   = "ID_PART_ENTRY_NAME",
	[U_PART_ENTRY_TYPE]   = "ID_PART_ENTRY_TYPE",
	[U_FS_SYSTEM_ID]      = "ID_FS_SYSTEM_ID",
	[U_FS_PUBLISHER_ID]   = "ID_FS_PUBLISHER_ID",
	[U_FS_APPLICATION_ID] = "ID_FS_APPLICATION_ID",
	[U_FS_BOOT_SYSTEM_ID] = "ID_FS_BOOT_SYSTEM_ID",
	[D_NEXT_MOD]          = SID_UCMD_KEY_DEVICE_NEXT_MOD,
};

static int _blkid_init(sid_res_t *mod_res, struct sid_ucmd_common_ctx *ucmd_common_ctx)
{
	unsigned i;

	sid_res_log_debug(mod_res, "init");

	for (i = _UDEV_KEY_START; i <= _UDEV_KEY_END; i++) {
		if (sid_ucmd_kv_reserve(mod_res, ucmd_common_ctx, SID_KV_NS_UDEV, keys[i], SID_KV_FL_FRG_RD) < 0) {
			sid_res_log_error(mod_res, "Failed to reserve blkid udev key %s.", keys[i]);
			return -1;
		}
	}

	for (i = _DEVICE_KEY_START; i <= _DEVICE_KEY_END; i++) {
		if (sid_ucmd_kv_reserve(mod_res, ucmd_common_ctx, SID_KV_NS_DEV, keys[i], SID_KV_FL_FRG_RD) < 0) {
			sid_res_log_error(mod_res, "Failed to reserve blkid device key %s.", keys[i]);
			return -1;
		}
	}

	return 0;
}
SID_UCMD_MOD_INIT(_blkid_init)

static int _blkid_exit(sid_res_t *mod_res, struct sid_ucmd_common_ctx *ucmd_common_ctx)
{
	unsigned i;

	sid_res_log_debug(mod_res, "exit");

	for (i = _UDEV_KEY_START; i <= _UDEV_KEY_END; i++) {
		if (sid_ucmd_kv_unreserve(mod_res, ucmd_common_ctx, SID_KV_NS_UDEV, keys[i]) < 0) {
			sid_res_log_error(mod_res, "Failed to unreserve blkid udev key %s.", keys[i]);
			return -1;
		}
	}

	for (i = _DEVICE_KEY_START; i <= _DEVICE_KEY_END; i++) {
		if (sid_ucmd_kv_unreserve(mod_res, ucmd_common_ctx, SID_KV_NS_DEV, keys[i]) < 0) {
			sid_res_log_error(mod_res, "Failed to unreserve blkid device key %s.", keys[i]);
			return -1;
		}
	}

	return 0;
}
SID_UCMD_MOD_EXIT(_blkid_exit)

static int _blkid_reset(sid_res_t *mod_res, struct sid_ucmd_common_ctx *ucmd_common_ctx)
{
	sid_res_log_debug(mod_res, "reset");
	return 0;
}
SID_UCMD_MOD_RESET(_blkid_reset)

/* TODO: Also add ID_PART_GPT_AUTO_ROOT_UUID - see udev-builtin-blkid in systemd source tree. */
static void _add_property(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx, const char *name, const char *value)
{
	char                     s[256];
	const struct blkid_type *blkid_type;

	s[0] = '\0';

	if (!strcmp(name, "TYPE")) {
		sid_ucmd_kv_va_set(mod_res,
		                   ucmd_ctx,
		                   .ns  = SID_KV_NS_UDEV,
		                   .key = keys[U_FS_TYPE],
		                   .val = value,
		                   .fl  = SID_KV_FL_RD);

		/* Translate blkid type name to sid module name and save the result in SID_UCMD_KEY_DEVICE_NEXT_MOD variable in
		 * KV_NS_DEVICE. */
		if ((blkid_type = blkid_type_lookup(value, strlen(value))))
			sid_ucmd_kv_va_set(mod_res,
			                   ucmd_ctx,
			                   .ns  = SID_KV_NS_DEV,
			                   .key = keys[D_NEXT_MOD],
			                   .val = blkid_type->module_name,
			                   .fl  = SID_KV_FL_SCPS | SID_KV_FL_RD);
	} else if (!strcmp(name, "USAGE")) {
		sid_ucmd_kv_va_set(mod_res,
		                   ucmd_ctx,
		                   .ns  = SID_KV_NS_UDEV,
		                   .key = keys[U_FS_USAGE],
		                   .val = value,
		                   .fl  = SID_KV_FL_RD);
	} else if (!strcmp(name, "VERSION")) {
		sid_ucmd_kv_va_set(mod_res,
		                   ucmd_ctx,
		                   .ns  = SID_KV_NS_UDEV,
		                   .key = keys[U_FS_VERSION],
		                   .val = value,
		                   .fl  = SID_KV_FL_RD);
	} else if (!strcmp(name, "UUID")) {
		blkid_safe_string(value, s, sizeof(s));
		sid_ucmd_kv_va_set(mod_res,
		                   ucmd_ctx,
		                   .ns  = SID_KV_NS_UDEV,
		                   .key = keys[U_FS_UUID],
		                   .val = value,
		                   .fl  = SID_KV_FL_RD);
		blkid_encode_string(value, s, sizeof(s));
		sid_ucmd_kv_va_set(mod_res, ucmd_ctx, .ns = SID_KV_NS_UDEV, .key = keys[U_FS_UUID_ENC], s, SID_KV_FL_RD);
	} else if (!strcmp(name, "UUID_SUB")) {
		blkid_safe_string(value, s, sizeof(s));
		sid_ucmd_kv_va_set(mod_res,
		                   ucmd_ctx,
		                   .ns  = SID_KV_NS_UDEV,
		                   .key = keys[U_FS_UUID_SUB],
		                   .val = value,
		                   .fl  = SID_KV_FL_RD);
		blkid_encode_string(value, s, sizeof(s));
		sid_ucmd_kv_va_set(mod_res,
		                   ucmd_ctx,
		                   .ns  = SID_KV_NS_UDEV,
		                   .key = keys[U_FS_UUID_SUB_ENC],
		                   .val = s,
		                   .fl  = SID_KV_FL_RD);
	} else if (!strcmp(name, "LABEL")) {
		blkid_safe_string(value, s, sizeof(s));
		sid_ucmd_kv_va_set(mod_res, ucmd_ctx, .ns = SID_KV_NS_UDEV, .key = keys[U_FS_LABEL], .val = s, .fl = SID_KV_FL_RD);
		blkid_encode_string(value, s, sizeof(s));
		sid_ucmd_kv_va_set(mod_res,
		                   ucmd_ctx,
		                   .ns  = SID_KV_NS_UDEV,
		                   .key = keys[U_FS_LABEL_ENC],
		                   .val = s,
		                   .fl  = SID_KV_FL_RD);
	} else if (!strcmp(name, "PTTYPE")) {
		sid_ucmd_kv_va_set(mod_res,
		                   ucmd_ctx,
		                   .ns  = SID_KV_NS_UDEV,
		                   .key = keys[U_PART_TABLE_TYPE],
		                   .val = value,
		                   .fl  = SID_KV_FL_RD);
	} else if (!strcmp(name, "PTUUID")) {
		sid_ucmd_kv_va_set(mod_res,
		                   ucmd_ctx,
		                   .ns  = SID_KV_NS_UDEV,
		                   .key = keys[U_PART_TABLE_UUID],
		                   .val = value,
		                   .fl  = SID_KV_FL_RD);
	} else if (!strcmp(name, "PART_ENTRY_NAME")) {
		blkid_encode_string(value, s, sizeof(s));
		sid_ucmd_kv_va_set(mod_res,
		                   ucmd_ctx,
		                   .ns  = SID_KV_NS_UDEV,
		                   .key = keys[U_PART_ENTRY_NAME],
		                   .val = s,
		                   .fl  = SID_KV_FL_RD);
	} else if (!strcmp(name, "PART_ENTRY_TYPE")) {
		blkid_encode_string(value, s, sizeof(s));
		sid_ucmd_kv_va_set(mod_res,
		                   ucmd_ctx,
		                   .ns  = SID_KV_NS_UDEV,
		                   .key = keys[U_PART_ENTRY_TYPE],
		                   .val = s,
		                   .fl  = SID_KV_FL_RD);
	} else if (!strncmp(name, "PART_ENTRY_", strlen("PART_ENTRY_"))) {
		snprintf(s, sizeof(s), "ID_%s", name);
		sid_ucmd_kv_va_set(mod_res, ucmd_ctx, .ns = SID_KV_NS_UDEV, .key = s, .val = value, .fl = SID_KV_FL_RD);
	} else if (!strcmp(name, "SYSTEM_ID")) {
		blkid_encode_string(value, s, sizeof(s));
		sid_ucmd_kv_va_set(mod_res,
		                   ucmd_ctx,
		                   .ns  = SID_KV_NS_UDEV,
		                   .key = keys[U_FS_SYSTEM_ID],
		                   .val = s,
		                   .fl  = SID_KV_FL_RD);
	} else if (!strcmp(name, "PUBLISHER_ID")) {
		blkid_encode_string(value, s, sizeof(s));
		sid_ucmd_kv_va_set(mod_res,
		                   ucmd_ctx,
		                   .ns  = SID_KV_NS_UDEV,
		                   .key = keys[U_FS_PUBLISHER_ID],
		                   .val = s,
		                   .fl  = SID_KV_FL_RD);
	} else if (!strcmp(name, "APPLICATION_ID")) {
		blkid_encode_string(value, s, sizeof(s));
		sid_ucmd_kv_va_set(mod_res,
		                   ucmd_ctx,
		                   .ns  = SID_KV_NS_UDEV,
		                   .key = keys[U_FS_APPLICATION_ID],
		                   .val = s,
		                   .fl  = SID_KV_FL_RD);
	} else if (!strcmp(name, "BOOT_SYSTEM_ID")) {
		blkid_encode_string(value, s, sizeof(s));
		sid_ucmd_kv_va_set(mod_res,
		                   ucmd_ctx,
		                   .ns  = SID_KV_NS_UDEV,
		                   .key = keys[U_FS_BOOT_SYSTEM_ID],
		                   .val = s,
		                   .fl  = SID_KV_FL_RD);
	}
}

static int _probe_superblocks(blkid_probe pr)
{
	struct stat st;
	int         rc;

	if (fstat(blkid_probe_get_fd(pr), &st))
		return -errno;

	blkid_probe_enable_partitions(pr, 1);

	if (!S_ISCHR(st.st_mode) && blkid_probe_get_size(pr) <= 1024 * 1440 && blkid_probe_is_wholedisk(pr)) {
		/*
		 * check if the small disk is partitioned, if yes then
		 * don't probe for filesystems.
		 */
		blkid_probe_enable_superblocks(pr, 0);

		rc = blkid_do_fullprobe(pr);
		if (rc < 0)
			return rc; /* -1 = error, 1 = nothing, 0 = success */

		if (blkid_probe_lookup_value(pr, "PTTYPE", NULL, NULL) == 0)
			return 0; /* partition table detected */
	}

	blkid_probe_set_partitions_flags(pr, BLKID_PARTS_ENTRY_DETAILS);
	blkid_probe_enable_superblocks(pr, 1);

	return blkid_do_safeprobe(pr);
}

static int _blkid_scan_next(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	char        dev_path[PATH_MAX];
	int64_t     offset = 0;
	int         noraid = 0;
	int         fd     = -1;
	blkid_probe pr     = NULL;
	const char *data;
	const char *name;
	int         nvals;
	int         i;
	int         r = -1;

	sid_res_log_debug(mod_res, "scan-next");

	pr = blkid_new_probe();
	if (!pr)
		goto out;

	blkid_probe_set_superblocks_flags(pr,
	                                  BLKID_SUBLKS_LABEL | BLKID_SUBLKS_UUID | BLKID_SUBLKS_TYPE | BLKID_SUBLKS_SECTYPE |
	                                          BLKID_SUBLKS_USAGE | BLKID_SUBLKS_VERSION);

	// TODO: Also decide when to use offset (including exact value) and noraid options.

	snprintf(dev_path, sizeof(dev_path), SYSTEM_DEV_PATH "/%s", sid_ucmd_ev_get_dev_name(ucmd_ctx));

	if ((fd = open(dev_path, O_RDONLY | O_CLOEXEC)) < 0) {
		sid_res_log_error_errno(mod_res, errno, "Failed to open device %s", dev_path);
		goto out;
	}

	if ((r = blkid_probe_set_device(pr, fd, offset, 0)) < 0)
		goto out;

	sid_res_log_debug(mod_res, "Probe %s %sraid offset=%" PRIi64, dev_path, noraid ? "no" : "", offset);

	if ((r = _probe_superblocks(pr)) < 0)
		goto out;

	nvals = blkid_probe_numof_values(pr);
	for (i = 0; i < nvals; i++) {
		if (blkid_probe_get_value(pr, i, &name, &data, NULL))
			continue;

		_add_property(mod_res, ucmd_ctx, name, data);
	}

	r = 0;
out:
	if (fd >= 0)
		(void) close(fd);
	if (pr)
		blkid_free_probe(pr);

	return r;
}
SID_UCMD_SCAN_NEXT(_blkid_scan_next)

static int _blkid_scan_error(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-error");
	return 0;
}
SID_UCMD_SCAN_ERROR(_blkid_scan_error)
