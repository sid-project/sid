/*
 * SPDX-FileCopyrightText: (C) 2017-2025 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "blkid-key.h"
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

static int _blkid_init(sid_res_t *mod_res, struct sid_ucmd_common_ctx *ucmd_common_ctx)
{
	const struct blkid_xkey *xkey;
	unsigned                 i;

	sid_res_log_debug(mod_res, "init");

	xkey = &blkid_xkey_arr[i = 0];
	while (xkey->num < U_ID_NUM_KEYS) {
		if (sid_ucmd_kv_reserve(mod_res, ucmd_common_ctx, SID_KV_NS_UDEV, xkey->name, SID_KV_FL_FRG_RD) < 0) {
			sid_res_log_error(mod_res, "Failed to reserve blkid udev key %s.", xkey->name);
			return -1;
		}

		xkey = &blkid_xkey_arr[++i];
	}

	if (sid_ucmd_kv_reserve(mod_res, ucmd_common_ctx, SID_KV_NS_DEV, SID_UCMD_KEY_DEVICE_NEXT_MOD, SID_KV_FL_FRG_RD) < 0) {
		sid_res_log_error(mod_res, "Failed to reserve blkid device key %s.", SID_UCMD_KEY_DEVICE_NEXT_MOD);
		return -1;
	}

	return 0;
}
SID_UCMD_MOD_INIT(_blkid_init)

static int _blkid_exit(sid_res_t *mod_res, struct sid_ucmd_common_ctx *ucmd_common_ctx)
{
	const struct blkid_xkey *xkey;
	unsigned                 i;

	sid_res_log_debug(mod_res, "exit");

	xkey = &blkid_xkey_arr[i = 0];
	while (xkey->num < U_ID_NUM_KEYS) {
		if (sid_ucmd_kv_unreserve(mod_res, ucmd_common_ctx, SID_KV_NS_UDEV, xkey->name) < 0) {
			sid_res_log_error(mod_res, "Failed to unreserve blkid udev key %s.", xkey->name);
			return -1;
		}

		xkey = &blkid_xkey_arr[++i];
	}

	if (sid_ucmd_kv_unreserve(mod_res, ucmd_common_ctx, SID_KV_NS_DEV, SID_UCMD_KEY_DEVICE_NEXT_MOD) < 0) {
		sid_res_log_error(mod_res, "Failed to unreserve blkid device key %s.", SID_UCMD_KEY_DEVICE_NEXT_MOD);
		return -1;
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

static int _add_property(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx, const char *name, const char *value)
{
	const struct blkid_key  *blkid_key;
	const struct blkid_type *blkid_type;
	char                     s[256];
	const char              *k;
	const char              *v;
	int                      r = 0;

	if (!(blkid_key = blkid_key_lookup(name, strlen(name)))) {
		sid_res_log_warning(mod_res, "Unhandled blkid key %s.", name);
		return -ENOKEY;
	}

	if (blkid_key->xkey->flags & BLKID_FL_ORIG) {
		if (blkid_key->xkey->flags & BLKID_FL_SAFE) {
			blkid_safe_string(value, s, sizeof(s));
			v = s;
		} else
			v = value;

		if ((r = sid_ucmd_kv_va_set(mod_res,
		                            ucmd_ctx,
		                            .ns  = SID_KV_NS_UDEV,
		                            .key = blkid_key->xkey->name,
		                            .val = v,
		                            .fl  = SID_KV_FL_SC | SID_KV_FL_RD)) < 0)
			goto out;
	}

	if (blkid_key->xkey->flags & BLKID_FL_ENC) {
		blkid_encode_string(value, s, sizeof(s));
		v = s;

		if (blkid_key->xkey->flags & BLKID_FL_ORIG)
			k = blkid_xkey_arr[blkid_key->xkey->num + 1].name;
		else
			k = blkid_key->xkey->name;

		if ((r = sid_ucmd_kv_va_set(mod_res, ucmd_ctx, .ns = SID_KV_NS_UDEV, .key = k, .val = v, .fl = SID_KV_FL_SC | SID_KV_FL_RD)) < 0)
			goto out;
	}

	if (blkid_key->xkey->num == U_ID_FS_TYPE) {
		if ((blkid_type = blkid_type_lookup(value, strlen(value)))) {
			if ((r = sid_ucmd_kv_va_set(mod_res,
			                            ucmd_ctx,
			                            .ns  = SID_KV_NS_DEV,
			                            .key = SID_UCMD_KEY_DEVICE_NEXT_MOD,
			                            .val = blkid_type->module_name,
			                            .fl  = SID_KV_FL_SCPS | SID_KV_FL_RD)) < 0)
				goto out;
		}
	}

out:
	return r;
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
	                                          BLKID_SUBLKS_FSINFO | BLKID_SUBLKS_USAGE | BLKID_SUBLKS_VERSION);

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

		if (_add_property(mod_res, ucmd_ctx, name, data) < 0)
			sid_res_log_warning(mod_res, "Failed to add property %s.", name);
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
