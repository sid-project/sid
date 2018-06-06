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

#include "blkid-type.h"
#include "ubridge-cmd-module.h"
#include "log.h"

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

#define ID "blkid"

static int _blkid_init(struct sid_module *module)
{
	log_debug(ID, "init");
	return 0;
}
SID_MODULE_INIT(_blkid_init)

static int _blkid_exit(struct sid_module *module)
{
	log_debug(ID, "exit");
	return 0;
}
SID_MODULE_EXIT(_blkid_exit)

static int _blkid_reload(struct sid_module *module)
{
	log_debug(ID, "reload");
	return 0;
}
SID_MODULE_RELOAD(_blkid_reload)

/* TODO: Also add ID_PART_GPT_AUTO_ROOT_UUID - see udev-builtin-blkid in systemd source tree. */
static void _add_property(struct sid_ubridge_cmd_context *cmd, const char *name, const char *value) {
        char s[256];
	const struct blkid_type *blkid_type;
	size_t len;

        s[0] = '\0';

        if (!strcmp(name, "TYPE")) {
		len = strlen(value);
		sid_ubridge_cmd_set_kv(cmd, KV_NS_UDEV, "ID_FS_TYPE", value, len + 1, 0);

		/* Translate blkid type name to sid module name and save the result in SID_NEXT_MOD variable in KV_NS_DEVICE. */
		if ((blkid_type = blkid_type_lookup(value, len)))
			sid_ubridge_cmd_set_kv(cmd, KV_NS_DEVICE, "SID_NEXT_MOD", blkid_type->sid_module_name, strlen(blkid_type->sid_module_name) + 1, KV_PERSIST);
        }
	else if (!strcmp(name, "USAGE")) {
		sid_ubridge_cmd_set_kv(cmd, KV_NS_UDEV, "ID_FS_USAGE", value, strlen(value) + 1, 0);
        }
	else if (!strcmp(name, "VERSION")) {
		sid_ubridge_cmd_set_kv(cmd, KV_NS_UDEV, "ID_FS_VERSION", value, strlen(value) + 1, 0);
        }
	else if (!strcmp(name, "UUID")) {
                blkid_safe_string(value, s, sizeof(s));
		sid_ubridge_cmd_set_kv(cmd, KV_NS_UDEV, "ID_FS_UUID", value, strlen(value) + 1, 0);
                blkid_encode_string(value, s, sizeof(s));
		sid_ubridge_cmd_set_kv(cmd, KV_NS_UDEV, "ID_FS_UUID_ENC", s, strlen(s) + 1, 0);
        }
	else if (!strcmp(name, "UUID_SUB")) {
                blkid_safe_string(value, s, sizeof(s));
		sid_ubridge_cmd_set_kv(cmd, KV_NS_UDEV, "ID_FS_UUID_SUB", value, strlen(value) + 1, 0);
                blkid_encode_string(value, s, sizeof(s));
		sid_ubridge_cmd_set_kv(cmd, KV_NS_UDEV, "ID_FS_UUID_SUB_ENC", s, strlen(s) + 1, 0);
        }
	else if (!strcmp(name, "LABEL")) {
                blkid_safe_string(value, s, sizeof(s));
		sid_ubridge_cmd_set_kv(cmd, KV_NS_UDEV, "ID_FS_LABEL", s, strlen(s) + 1, 0);
                blkid_encode_string(value, s, sizeof(s));
		sid_ubridge_cmd_set_kv(cmd, KV_NS_UDEV, "ID_FS_LABEL_ENC", s, strlen(s) + 1, 0);
        }
	else if (!strcmp(name, "PTTYPE")) {
		sid_ubridge_cmd_set_kv(cmd, KV_NS_UDEV, "ID_PART_TABLE_TYPE", value, strlen(value) + 1, 0);
        }
	else if (!strcmp(name, "PTUUID")) {
		sid_ubridge_cmd_set_kv(cmd, KV_NS_UDEV, "ID_PART_TABLE_UUID", value, strlen(value) + 1, 0);
        }
	else if (!strcmp(name, "PART_ENTRY_NAME")) {
                blkid_encode_string(value, s, sizeof(s));
		sid_ubridge_cmd_set_kv(cmd, KV_NS_UDEV, "ID_PART_ENTRY_NAME", s, strlen(s) + 1, 0);
        }
	else if (!strcmp(name, "PART_ENTRY_TYPE")) {
                blkid_encode_string(value, s, sizeof(s));
		sid_ubridge_cmd_set_kv(cmd, KV_NS_UDEV, "ID_PART_ENTRY_TYPE", s, strlen(s) + 1, 0);
        }
	else if (!strncmp(name, "PART_ENTRY_", strlen("PART_ENTRY_"))) {
		snprintf(s, sizeof(s), "ID_%s",	name);
		sid_ubridge_cmd_set_kv(cmd, KV_NS_UDEV, s, value, strlen(value) + 1, 0);
        }
	else if (!strcmp(name, "SYSTEM_ID")) {
                blkid_encode_string(value, s, sizeof(s));
		sid_ubridge_cmd_set_kv(cmd, KV_NS_UDEV, "ID_FS_SYSTEM_ID", s, strlen(s) + 1, 0);
        }
	else if (!strcmp(name, "PUBLISHER_ID")) {
                blkid_encode_string(value, s, sizeof(s));
		sid_ubridge_cmd_set_kv(cmd, KV_NS_UDEV, "ID_FS_PUBLISHER_ID", s, strlen(s) + 1, 0);
        }
	else if (!strcmp(name, "APPLICATION_ID")) {
                blkid_encode_string(value, s, sizeof(s));
		sid_ubridge_cmd_set_kv(cmd, KV_NS_UDEV, "ID_FS_APPLICATION_ID", s, strlen(s) + 1, 0);
        }
	else if (!strcmp(name, "BOOT_SYSTEM_ID")) {
                blkid_encode_string(value, s, sizeof(s));
		sid_ubridge_cmd_set_kv(cmd, KV_NS_UDEV, "ID_FS_BOOT_SYSTEM_ID", s, strlen(s) + 1, 0);
        }
}

static int _probe_superblocks(blkid_probe pr) {
        struct stat st;
        int rc;

        if (fstat(blkid_probe_get_fd(pr), &st))
                return -errno;

        blkid_probe_enable_partitions(pr, 1);

        if (!S_ISCHR(st.st_mode) &&
            blkid_probe_get_size(pr) <= 1024 * 1440 &&
            blkid_probe_is_wholedisk(pr)) {
                /*
                 * check if the small disk is partitioned, if yes then
                 * don't probe for filesystems.
                 */
                blkid_probe_enable_superblocks(pr, 0);

                rc = blkid_do_fullprobe(pr);
                if (rc < 0)
                        return rc;        /* -1 = error, 1 = nothing, 0 = success */

                if (blkid_probe_lookup_value(pr, "PTTYPE", NULL, NULL) == 0)
                        return 0;        /* partition table detected */
        }

        blkid_probe_set_partitions_flags(pr, BLKID_PARTS_ENTRY_DETAILS);
        blkid_probe_enable_superblocks(pr, 1);

        return blkid_do_safeprobe(pr);
}

static int _blkid_scan_next(struct sid_module *module, struct sid_ubridge_cmd_context *cmd)
{
	const char *dev_path;
        int64_t offset = 0;
        int noraid = 0;
        int fd = -1;
        blkid_probe pr = NULL;
        const char *data;
        const char *name;
        int nvals;
        int i;
        int r = -1;

        pr = blkid_new_probe();
        if (!pr)
		goto out;

        blkid_probe_set_superblocks_flags(pr,
                BLKID_SUBLKS_LABEL | BLKID_SUBLKS_UUID |
                BLKID_SUBLKS_TYPE | BLKID_SUBLKS_SECTYPE |
                BLKID_SUBLKS_USAGE | BLKID_SUBLKS_VERSION);

	// TODO: Also decide when to use offset (including exact value) and noraid options.

        if (noraid)
                blkid_probe_filter_superblocks_usage(pr, BLKID_FLTR_NOTIN, BLKID_USAGE_RAID);

	dev_path = sid_ubridge_cmd_dev_get_name(cmd);

        if ((fd = open(dev_path, O_RDONLY|O_CLOEXEC)) < 0) {
                log_error_errno(ID, errno, "Failed to open device %s.", dev_path);
                goto out;
        }

        if ((r = blkid_probe_set_device(pr, fd, offset, 0)) < 0) 
                goto out;

        log_debug(ID, "Probe %s %sraid offset=%"PRIi64, dev_path, noraid ? "no" : "", offset);

        if ((r = _probe_superblocks(pr)) < 0)
                goto out;

        nvals = blkid_probe_numof_values(pr);
        for (i = 0; i < nvals; i++) {
                if (blkid_probe_get_value(pr, i, &name, &data, NULL))
                        continue;

                _add_property(cmd, name, data);
        }

	r = 0;
out:
	if (fd >= 0)
		close(fd);
	if (pr)
		blkid_free_probe(pr);

        return r;
}
SID_UBRIDGE_CMD_SCAN_NEXT(_blkid_scan_next)

static int _blkid_error(struct sid_module *module, struct sid_ubridge_cmd_context *cmd)
{
	log_debug(ID, "error");
	return 0;
}
SID_UBRIDGE_CMD_ERROR(_blkid_error)
