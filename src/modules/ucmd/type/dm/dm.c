/*
 * SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "internal/comp-attrs.h"

#include "dm.h"

#include "base/util.h"
#include "internal/mem.h"
#include "resource/mod-reg.h"
#include "resource/ucmd-mod.h"

#include <limits.h>
#include <linux/dm-ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sem.h>

#define DM_ID                "dm"
#define DM_SUBMODULES_ID     DM_ID "_sub"
#define DM_SUBMODULE_ID_NONE "none"

SID_UCMD_MOD_PRIO(0)
SID_UCMD_MOD_ALIASES("device_mapper")

typedef enum {
	DM_SUBMOD_SCAN_PHASE_SUBSYS_MATCH_CURRENT,
	DM_SUBMOD_SCAN_PHASE_SUBSYS_MATCH_NEXT,
	DM_SUBMOD_SCAN_PHASE_A_INIT,
	DM_SUBMOD_SCAN_PHASE_SCAN_PRE,
	DM_SUBMOD_SCAN_PHASE_SCAN_CURRENT,
	DM_SUBMOD_SCAN_PHASE_SCAN_NEXT,
	DM_SUBMOD_SCAN_PHASE_SCAN_POST_CURRENT,
	DM_SUBMOD_SCAN_PHASE_SCAN_POST_NEXT,
	DM_SUBMOD_SCAN_PHASE_A_EXIT,
	DM_SUBMOD_SCAN_PHASE_REMOVE_INIT,
	DM_SUBMOD_SCAN_PHASE_REMOVE,
	DM_SUBMOD_SCAN_PHASE_REMOVE_EXIT,
	DM_SUBMOD_SCAN_PHASE_B_INIT,
	DM_SUBMOD_SCAN_PHASE_ACTION_CURRENT,
	DM_SUBMOD_SCAN_PHASE_ACTION_NEXT,
	DM_SUBMOD_SCAN_PHASE_B_EXIT,
	DM_SUBMOD_SCAN_PHASE_ERROR,
} dm_submod_cmd_scan_phase_t;

struct scan_dm_submod_fns {
	sid_ucmd_fn_t *scan_subsys_match_current;
	sid_ucmd_fn_t *scan_subsys_match_next;
	sid_ucmd_fn_t *scan_a_init;
	sid_ucmd_fn_t *scan_pre;
	sid_ucmd_fn_t *scan_current;
	sid_ucmd_fn_t *scan_next;
	sid_ucmd_fn_t *scan_post_current;
	sid_ucmd_fn_t *scan_post_next;
	sid_ucmd_fn_t *scan_a_exit;
	sid_ucmd_fn_t *scan_remove_init;
	sid_ucmd_fn_t *scan_remove;
	sid_ucmd_fn_t *scan_remove_exit;
	sid_ucmd_fn_t *scan_b_init;
	sid_ucmd_fn_t *scan_action_current;
	sid_ucmd_fn_t *scan_action_next;
	sid_ucmd_fn_t *scan_b_exit;
	sid_ucmd_fn_t *scan_error;
} __packed;

struct dm_mod_ctx {
	sid_res_t *submod_registry;
	sid_res_t *submod_res_current;
	sid_res_t *submod_res_next;
	sid_res_t *submod_res;
};

typedef uint16_t dm_cookie_base_t;

#define COOKIE_MAGIC       0x0D4D
#define COOKIE_FLAGS_MASK  0xFFFF0000
#define COOKIE_FLAGS_SHIFT 16

static const char *_udev_cookie_flag_names[] = {"DM_UDEV_DISABLE_DM_RULES_FLAG",
                                                "DM_UDEV_DISABLE_SUBSYSTEM_RULES_FLAG",
                                                "DM_UDEV_DISABLE_DISK_RULES_FLAG",
                                                "DM_UDEV_DISABLE_OTHER_RULES_FLAG",
                                                "DM_UDEV_LOW_PRIORITY_FLAG",
                                                "DM_UDEV_DISABLE_LIBRARY_FALLBACK_FLAG",
                                                "DM_UDEV_PRIMARY_SOURCE_FLAG",
                                                "DM_UDEV_FLAG7",
                                                "DM_SUBSYSTEM_UDEV_FLAG0",
                                                "DM_SUBSYSTEM_UDEV_FLAG1",
                                                "DM_SUBSYSTEM_UDEV_FLAG2",
                                                "DM_SUBSYSTEM_UDEV_FLAG3",
                                                "DM_SUBSYSTEM_UDEV_FLAG4",
                                                "DM_SUBSYSTEM_UDEV_FLAG5",
                                                "DM_SUBSYSTEM_UDEV_FLAG6",
                                                "DM_SUBSYSTEM_UDEV_FLAG7",
                                                NULL};

#define DM_UDEV_RULES_VSN   "3"

#define DM_U_UDEV_RULES_VSN "DM_UDEV_RULES_VSN"
#define DM_U_COOKIE         "DM_COOKIE"
#define DM_U_NAME           "DM_NAME"
#define DM_U_UUID           "DM_UUID"
#define DM_U_SUSPENDED      ".DM_SUSPENDED"
#define DM_U_ACTIVATION     "DM_ACTIVATION"

#define DM_X_COOKIE_BASE    "cookie_base"

#define ALS_NAME            "name"
#define ALS_UUID            "uuid"

#define SYSFS_DM_UUID       "dm/uuid"
#define SYSFS_DM_NAME       "dm/name"
#define SYSFS_DM_SUSPENDED  "dm/suspended"

static const char _failed_to_set_msg[]       = "Failed to set value for key \"%s\"";
static const char _failed_to_get_msg[]       = "Failed to get value for key \"%s\"";
static const char _failed_to_set_alias_msg[] = "Failed to add alias for key \"%s\"";
static const char _failed_to_get_sysfs_msg[] = "Failed to get sysfs property for entry \"%s\"";

#define DEV_PRINT_FMT "%s (%d_%d/%" PRIu64 ")"
#define DEV_PRINT(ucmd_ctx)                                                                                                        \
	sid_ucmd_ev_get_dev_name(ucmd_ctx), sid_ucmd_ev_get_dev_major(ucmd_ctx), sid_ucmd_ev_get_dev_minor(ucmd_ctx),              \
		sid_ucmd_ev_get_dev_diskseq(ucmd_ctx)

static int _get_dm_submod_syms(sid_res_t *mod_res, sid_res_t *submod_res, struct scan_dm_submod_fns **submod_fns)
{
	if (!submod_res)
		return -EINVAL;

	if (sid_mod_reg_get_mod_syms(submod_res, (const void ***) submod_fns) < 0) {
		sid_res_log_error(mod_res, "Failed to retrieve symbols for submodule %s", sid_res_get_id(submod_res));
		return -1;
	}

	return 0;
}

static int _do_exec_dm_submod(sid_res_t                 *mod_res,
                              sid_res_t                 *submod_res,
                              dm_submod_cmd_scan_phase_t phase,
                              struct sid_ucmd_ctx       *ucmd_ctx)
{
	struct scan_dm_submod_fns *submod_fns;
	sid_ucmd_fn_t             *submod_fn;

	if (!submod_res)
		return 0;

	if (sid_mod_reg_get_mod_syms(submod_res, (const void ***) &submod_fns) < 0) {
		sid_res_log_error(mod_res, "Failed to get symbols for submodule %s.", sid_res_get_id(submod_res));
		return -1;
	}

	if ((submod_fn = *(((sid_ucmd_fn_t **) submod_fns) + phase)))
		return submod_fn(submod_res, ucmd_ctx);

	return 0;
}

static int _exec_dm_submod(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx, dm_submod_cmd_scan_phase_t phase)
{
	static const char          _failed_to_create_submod_iter_msg[] = "Failed to create submodule iterator.";
	struct dm_mod_ctx         *dm_mod                              = sid_mod_get_data(mod_res);
	struct scan_dm_submod_fns *submod_fns;
	sid_res_iter_t            *iter;
	int                        r;

	switch (phase) {
		case DM_SUBMOD_SCAN_PHASE_SUBSYS_MATCH_CURRENT:
			if (!(iter = sid_res_iter_create(dm_mod->submod_registry))) {
				sid_res_log_error(mod_res, _failed_to_create_submod_iter_msg);
				return -1;
			}

			while ((dm_mod->submod_res = sid_res_iter_next(iter))) {
				if (_get_dm_submod_syms(mod_res, dm_mod->submod_res, &submod_fns) < 0)
					continue;

				if (submod_fns->scan_subsys_match_current) {
					if (submod_fns->scan_subsys_match_current(dm_mod->submod_res, ucmd_ctx)) {
						dm_mod->submod_res_current = dm_mod->submod_res;
						sid_res_log_debug(mod_res,
						                  "%s submodule claimed " DEV_PRINT_FMT " for 'current' phases.",
						                  sid_res_get_id(dm_mod->submod_res),
						                  DEV_PRINT(ucmd_ctx));
						break;
					}
				}
			}

			sid_res_iter_destroy(iter);
			break;

		case DM_SUBMOD_SCAN_PHASE_SUBSYS_MATCH_NEXT:
			if (!(iter = sid_res_iter_create(dm_mod->submod_registry))) {
				sid_res_log_error(mod_res, _failed_to_create_submod_iter_msg);
				return -1;
			}

			while ((dm_mod->submod_res = sid_res_iter_next(iter))) {
				if (_get_dm_submod_syms(mod_res, dm_mod->submod_res, &submod_fns) < 0)
					continue;

				if (submod_fns->scan_subsys_match_next) {
					if (submod_fns->scan_subsys_match_next(dm_mod->submod_res, ucmd_ctx)) {
						dm_mod->submod_res_next = dm_mod->submod_res;
						sid_res_log_debug(mod_res,
						                  "%s submodule claimed " DEV_PRINT_FMT " for 'next' phases.",
						                  sid_res_get_id(dm_mod->submod_res),
						                  DEV_PRINT(ucmd_ctx));
					}
				}
			}

			sid_res_iter_destroy(iter);
			break;

		case DM_SUBMOD_SCAN_PHASE_A_INIT:
		case DM_SUBMOD_SCAN_PHASE_SCAN_PRE:
		case DM_SUBMOD_SCAN_PHASE_SCAN_CURRENT:
		case DM_SUBMOD_SCAN_PHASE_SCAN_POST_CURRENT:
		case DM_SUBMOD_SCAN_PHASE_A_EXIT:
		case DM_SUBMOD_SCAN_PHASE_REMOVE_INIT:
		case DM_SUBMOD_SCAN_PHASE_REMOVE:
		case DM_SUBMOD_SCAN_PHASE_REMOVE_EXIT:
		case DM_SUBMOD_SCAN_PHASE_B_INIT:
		case DM_SUBMOD_SCAN_PHASE_ACTION_CURRENT:
		case DM_SUBMOD_SCAN_PHASE_B_EXIT:
			if (_do_exec_dm_submod(mod_res, dm_mod->submod_res = dm_mod->submod_res_current, phase, ucmd_ctx) < 0)
				return -1;
			break;

		case DM_SUBMOD_SCAN_PHASE_SCAN_NEXT:
		case DM_SUBMOD_SCAN_PHASE_SCAN_POST_NEXT:
		case DM_SUBMOD_SCAN_PHASE_ACTION_NEXT:
			if (_do_exec_dm_submod(mod_res, dm_mod->submod_res = dm_mod->submod_res_next, phase, ucmd_ctx) < 0)
				return -1;
			break;

		case DM_SUBMOD_SCAN_PHASE_ERROR:
			r  = _do_exec_dm_submod(mod_res, dm_mod->submod_res = dm_mod->submod_res_current, phase, ucmd_ctx);
			r |= _do_exec_dm_submod(mod_res, dm_mod->submod_res = dm_mod->submod_res_next, phase, ucmd_ctx);
			return r;
	}

	return 0;
}

static int _get_cookie_props(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx, dm_cookie_flags_t *cookie_flags)
{
	const char       *str;
	unsigned long int val;
	dm_cookie_base_t  base;
	dm_cookie_flags_t flags;
	char             *p;

	if (!(str = sid_ucmd_kv_get(mod_res, ucmd_ctx, SID_KV_NS_UDEV, DM_U_COOKIE, NULL, NULL, 0))) {
		if (sid_ucmd_kv_va_set(mod_res,
		                       ucmd_ctx,
		                       .ns    = SID_KV_NS_DEVMOD,
		                       .key   = DM_X_COOKIE_FLAGS,
		                       .flags = SID_KV_FL_AR | SID_KV_FL_SYNC | SID_KV_FL_SUB_RD) < 0) {
			sid_res_log_error(mod_res, _failed_to_set_msg, DM_X_COOKIE_FLAGS);
			return -1;
		}
		return 0;
	}

	errno = 0;
	val   = strtoul(str, &p, 0);
	if (errno | !val || (*p) || (val > UINT32_MAX)) {
		sid_res_log_error(mod_res, "Invalid cookie value.");
		return -1;
	}

	base  = (dm_cookie_base_t) val;
	flags = (dm_cookie_flags_t) (val >> COOKIE_FLAGS_SHIFT);

	/*
	 * Store cookie base and flags in SID_KV_NS_DEVMOD for use in SID.
	 * Cookie base is of interest in dm module only, the flags
	 * may be of interest in dm module as well as its submodules.
	 */
	if (sid_ucmd_kv_va_set(mod_res,
	                       ucmd_ctx,
	                       .ns    = SID_KV_NS_DEVMOD,
	                       .key   = DM_X_COOKIE_BASE,
	                       .value = &base,
	                       .size  = sizeof(base),
	                       .flags = SID_KV_FL_ALIGN) < 0) {
		sid_res_log_error(mod_res, _failed_to_set_msg, DM_X_COOKIE_BASE);
		return -1;
	}

	if (sid_ucmd_kv_va_set(mod_res,
	                       ucmd_ctx,
	                       .ns    = SID_KV_NS_DEVMOD,
	                       .key   = DM_X_COOKIE_FLAGS,
	                       .value = &flags,
	                       .size  = sizeof(flags),
	                       .flags = SID_KV_FL_ALIGN | SID_KV_FL_AR | SID_KV_FL_SYNC | SID_KV_FL_SUB_RD) < 0) {
		sid_res_log_error(mod_res, _failed_to_set_msg, DM_X_COOKIE_FLAGS);
		return -1;
	}

	if (cookie_flags)
		*cookie_flags = flags;
	return 1;
}

static int _get_sysfs_value(sid_res_t *mod_res, const char *sysfs_path, char *sysfs_entry, char *buf, size_t buf_size)
{
	char path[PATH_MAX];
	int  r;

	if (snprintf(path, sizeof(path), "%s%s/%s", SYSTEM_SYSFS_PATH, sysfs_path, sysfs_entry) < 0) {
		sid_res_log_error(mod_res, "Failed to construct sysfs path for entry %s", sysfs_entry);
		return -ENOMEM;
	}

	if ((r = sid_util_sysfs_get(path, buf, buf_size, NULL)) < 0) {
		sid_res_log_error_errno(mod_res, r, _failed_to_get_sysfs_msg, path);
		return r;
	}

	return 0;
}

static int _get_sysfs_props(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	const char *sysfs_dev_path;
	char        name[DM_NAME_LEN];
	char        uuid[DM_UUID_LEN];
	char        suspended[10]; /* "Active" or "Suspended" value */
	int         r;

	/* uuid may be blank, name and suspended property is always set  */

	sysfs_dev_path = sid_ucmd_ev_get_dev_path(ucmd_ctx);

	if (_get_sysfs_value(mod_res, sysfs_dev_path, SYSFS_DM_UUID, uuid, sizeof(uuid)) < 0)
		return -1;

	if (_get_sysfs_value(mod_res, sysfs_dev_path, SYSFS_DM_NAME, name, sizeof(name)) < 0 || !name[0])
		return -1;

	if (_get_sysfs_value(mod_res, sysfs_dev_path, SYSFS_DM_SUSPENDED, suspended, sizeof(suspended)) < 0 || !suspended[0])
		return -1;

	if (uuid[0] && (r = sid_ucmd_dev_alias_add(mod_res, ucmd_ctx, ALS_UUID, uuid)) < 0) {
		sid_res_log_error_errno(mod_res, r, _failed_to_set_alias_msg, ALS_UUID);
		return -1;
	}

	if ((r = sid_ucmd_dev_alias_add(mod_res, ucmd_ctx, ALS_NAME, name)) < 0) {
		sid_res_log_error_errno(mod_res, r, _failed_to_set_alias_msg, ALS_NAME);
		return -1;
	}

	if (sid_ucmd_kv_va_set(mod_res,
	                       ucmd_ctx,
	                       .ns    = SID_KV_NS_DEVMOD,
	                       .key   = DM_X_UUID,
	                       .value = uuid,
	                       .size  = strlen(uuid) + 1,
	                       .flags = SID_KV_FL_SYNC | SID_KV_FL_SUB_RD) < 0) {
		sid_res_log_error(mod_res, _failed_to_set_msg, DM_X_UUID);
		return -1;
	}

	if (sid_ucmd_kv_va_set(mod_res,
	                       ucmd_ctx,
	                       .ns    = SID_KV_NS_DEVMOD,
	                       .key   = DM_X_NAME,
	                       .value = name,
	                       .size  = strlen(name) + 1,
	                       .flags = SID_KV_FL_SYNC | SID_KV_FL_SUB_RD) < 0) {
		sid_res_log_error(mod_res, _failed_to_set_msg, DM_X_NAME);
		return -1;
	}

	if (uuid[0] && sid_ucmd_kv_va_set(mod_res,
	                                  ucmd_ctx,
	                                  .ns    = SID_KV_NS_UDEV,
	                                  .key   = DM_U_UUID,
	                                  .value = uuid,
	                                  .size  = strlen(uuid) + 1,
	                                  .flags = SID_KV_FL_SYNC_P) < 0) {
		sid_res_log_error(mod_res, _failed_to_set_msg, DM_U_UUID);
		return -1;
	}

	if (sid_ucmd_kv_va_set(mod_res,
	                       ucmd_ctx,
	                       .ns    = SID_KV_NS_UDEV,
	                       .key   = DM_U_NAME,
	                       .value = name,
	                       .size  = strlen(name) + 1,
	                       .flags = SID_KV_FL_SYNC_P) < 0) {
		sid_res_log_error(mod_res, _failed_to_set_msg, DM_U_NAME);
		return -1;
	}

	if (sid_ucmd_kv_va_set(mod_res,
	                       ucmd_ctx,
	                       .ns    = SID_KV_NS_UDEV,
	                       .key   = DM_U_SUSPENDED,
	                       .value = suspended,
	                       .size  = strlen(suspended) + 1,
	                       .flags = SID_KV_FL_SYNC_P) < 0) {
		sid_res_log_error(mod_res, _failed_to_set_msg, DM_U_SUSPENDED);
		return -1;
	}

	return 0;
}

static int _dm_init(sid_res_t *mod_res, struct sid_ucmd_common_ctx *ucmd_common_ctx)
{
	struct sid_mod_reg_res_params *submod_reg_res_params;
	struct dm_mod_ctx             *dm_mod = NULL;
	const char                   **flag_name;

	sid_res_log_debug(mod_res, "init");

	if (!(dm_mod = mem_zalloc(sizeof(*dm_mod)))) {
		sid_res_log_error(mod_res, "Failed to allocate memory module context structure.");
		return -1;
	}

	{
		submod_reg_res_params = &(struct sid_mod_reg_res_params) {
			.directory     = SID_UCMD_TYPE_MOD_DIR "/" DM_ID,
			.module_prefix = NULL,
			.module_suffix = ".so",
			.flags         = 0,
			.symbol_params = SID_MOD_SYM_PARAMS_ARRAY(
				SID_MOD_SYM_PARAMS(.name  = SID_UCMD_MOD_DM_FN_NAME_SCAN_SUBSYS_MATCH_CURRENT,
		                                   .flags = SID_MOD_SYM_FL_FAIL_ON_MISSING | SID_MOD_SYM_FL_INDIRECT),
				SID_MOD_SYM_PARAMS(.name  = SID_UCMD_MOD_DM_FN_NAME_SCAN_SUBSYS_MATCH_NEXT,
		                                   .flags = SID_MOD_SYM_FL_FAIL_ON_MISSING | SID_MOD_SYM_FL_INDIRECT),
				SID_MOD_SYM_PARAMS(.name  = SID_UCMD_MOD_FN_NAME_SCAN_A_INIT,
		                                   .flags = SID_MOD_SYM_FL_FAIL_ON_MISSING | SID_MOD_SYM_FL_INDIRECT),
				SID_MOD_SYM_PARAMS(.name = SID_UCMD_MOD_FN_NAME_SCAN_PRE, .flags = SID_MOD_SYM_FL_INDIRECT),
				SID_MOD_SYM_PARAMS(.name = SID_UCMD_MOD_FN_NAME_SCAN_CURRENT, .flags = SID_MOD_SYM_FL_INDIRECT),
				SID_MOD_SYM_PARAMS(.name = SID_UCMD_MOD_FN_NAME_SCAN_NEXT, .flags = SID_MOD_SYM_FL_INDIRECT),
				SID_MOD_SYM_PARAMS(.name  = SID_UCMD_MOD_FN_NAME_SCAN_POST_CURRENT,
		                                   .flags = SID_MOD_SYM_FL_INDIRECT),
				SID_MOD_SYM_PARAMS(.name = SID_UCMD_MOD_FN_NAME_SCAN_POST_NEXT, .flags = SID_MOD_SYM_FL_INDIRECT),
				SID_MOD_SYM_PARAMS(.name = SID_UCMD_MOD_FN_NAME_SCAN_A_EXIT, .flags = SID_MOD_SYM_FL_INDIRECT),
				SID_MOD_SYM_PARAMS(.name = SID_UCMD_MOD_FN_NAME_SCAN_REMOVE_INIT, .flags = SID_MOD_SYM_FL_INDIRECT),
				SID_MOD_SYM_PARAMS(.name = SID_UCMD_MOD_FN_NAME_SCAN_REMOVE, .flags = SID_MOD_SYM_FL_INDIRECT),
				SID_MOD_SYM_PARAMS(.name = SID_UCMD_MOD_FN_NAME_SCAN_REMOVE_EXIT, .flags = SID_MOD_SYM_FL_INDIRECT),
				SID_MOD_SYM_PARAMS(.name = SID_UCMD_MOD_FN_NAME_SCAN_B_INIT, .flags = SID_MOD_SYM_FL_INDIRECT),
				SID_MOD_SYM_PARAMS(.name  = SID_UCMD_MOD_FN_NAME_SCAN_ACTION_CURRENT,
		                                   .flags = SID_MOD_SYM_FL_INDIRECT),
				SID_MOD_SYM_PARAMS(.name = SID_UCMD_MOD_FN_NAME_SCAN_ACTION_NEXT, .flags = SID_MOD_SYM_FL_INDIRECT),
				SID_MOD_SYM_PARAMS(.name = SID_UCMD_MOD_FN_NAME_SCAN_B_EXIT, .flags = SID_MOD_SYM_FL_INDIRECT),
				SID_MOD_SYM_PARAMS(.name  = SID_UCMD_MOD_FN_NAME_SCAN_ERROR,
		                                   .flags = SID_MOD_SYM_FL_FAIL_ON_MISSING | SID_MOD_SYM_FL_INDIRECT)),
			.cb_arg = ucmd_common_ctx,
		};

		if (!(dm_mod->submod_registry = sid_res_create(SID_RES_NO_PARENT,
		                                               &sid_res_type_mod_reg,
		                                               SID_RES_FL_NONE,
		                                               DM_SUBMODULES_ID,
		                                               submod_reg_res_params,
		                                               SID_RES_PRIO_NORMAL,
		                                               SID_RES_NO_SERVICE_LINKS))) {
			sid_res_log_error(mod_res, "Failed to create submodule registry.");
			goto fail;
		}
	}

	if (sid_mod_reg_add_mod_subreg(mod_res, dm_mod->submod_registry) < 0) {
		sid_res_log_error(mod_res, "Failed to attach submodule registry.");
		goto fail;
	}

	for (flag_name = _udev_cookie_flag_names; *flag_name; flag_name++) {
		if (sid_ucmd_kv_reserve(mod_res, ucmd_common_ctx, SID_KV_NS_UDEV, *flag_name, SID_KV_FL_SUB_RD) < 0) {
			sid_res_log_error(mod_res, "Failed to reserve dm udev key %s.", *flag_name);
			goto fail;
		}
	}

	if (sid_mod_reg_load_mods(dm_mod->submod_registry) < 0) {
		sid_res_log_error(mod_res, "Failed to load submodules.");
		goto fail;
	}

	sid_mod_set_data(mod_res, dm_mod);
	return 0;
fail:
	sid_res_unref(dm_mod->submod_registry);
	free(dm_mod);
	return -1;
}
SID_UCMD_MOD_INIT(_dm_init)

static int _dm_exit(sid_res_t *mod_res, struct sid_ucmd_common_ctx *ucmd_common_ctx)
{
	struct dm_mod_ctx *dm_mod;
	const char       **flag_name;
	int                r = 0;

	sid_res_log_debug(mod_res, "exit");

	for (flag_name = _udev_cookie_flag_names; *flag_name; flag_name++) {
		if (sid_ucmd_kv_unreserve(mod_res, ucmd_common_ctx, SID_KV_NS_UDEV, *flag_name) < 0) {
			sid_res_log_error(mod_res, "Failed to unreserve dm udev key %s.", *flag_name);
			r = -1;
		}
	}

	dm_mod = sid_mod_get_data(mod_res);
	free(dm_mod);

	return r;
}
SID_UCMD_MOD_EXIT(_dm_exit)

static int _dm_reset(sid_res_t *mod_res, struct sid_ucmd_common_ctx *ucmd_common_ctx)
{
	sid_res_log_debug(mod_res, "reset");
	return 0;
}
SID_UCMD_MOD_RESET(_dm_reset)

static int _dm_submod_common_scan_init(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	struct dm_mod_ctx *dm_mod;
	const char        *submod_name = NULL;

	dm_mod                         = sid_mod_get_data(mod_res);
	submod_name                    = sid_ucmd_kv_get(mod_res, ucmd_ctx, SID_KV_NS_DEVICE, DM_SUBMODULES_ID, NULL, NULL, 0);

	if (submod_name) {
		if (strcmp(submod_name, DM_SUBMODULE_ID_NONE) != 0) {
			if (!(dm_mod->submod_res_current = sid_mod_reg_get_mod(dm_mod->submod_registry, submod_name))) {
				sid_res_log_debug(mod_res, "Module %s not loaded.", submod_name);
				return 0;
			}
		}
	} else {
		if (_exec_dm_submod(mod_res, ucmd_ctx, DM_SUBMOD_SCAN_PHASE_SUBSYS_MATCH_CURRENT) < 0)
			return -1;

		if (dm_mod->submod_res_current)
			submod_name = sid_res_get_id(dm_mod->submod_res_current);
		else
			submod_name = DM_SUBMODULE_ID_NONE;

		if (sid_ucmd_kv_va_set(mod_res,
		                       ucmd_ctx,
		                       .ns    = SID_KV_NS_DEVICE,
		                       .key   = DM_SUBMODULES_ID,
		                       .value = submod_name,
		                       .size  = strlen(submod_name) + 1,
		                       .flags = SID_KV_FL_SYNC_P | SID_KV_FL_FRG_RD) < 0) {
			sid_res_log_error(mod_res, _failed_to_set_msg, DM_SUBMODULES_ID);
			return -1;
		}
	}

	dm_mod->submod_res = dm_mod->submod_res_current;
	if (_exec_dm_submod(mod_res, ucmd_ctx, DM_SUBMOD_SCAN_PHASE_A_INIT) < 0)
		return -1;

	return 0;
}

static int _dm_scan_a_init(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-a-init");

	if (_get_sysfs_props(mod_res, ucmd_ctx) < 0)
		return -1;

	return _dm_submod_common_scan_init(mod_res, ucmd_ctx);
}
SID_UCMD_SCAN_A_INIT(_dm_scan_a_init)

/*
 * We expect this sequence for DM device activation:
 *
 *    1) Device creation (DM_DEV_CREATE ioctl).
 *       There is no table for the device yet.
 *       Based on kernel version (kernel commit 89f871af1b26d98d983cba7ed0e86effa45ba5f8):
 *
 *         -  kernel < 5.15
 *            UDEV_ACTION_ADD notification.
 *            DEV_RDY_UNPROCESSED transitions to DEV_RDY_UNCONFIGURED.
 *
 *         -  kernel >= 5.15: no UDEV_ACTION_* notification.
 *            No UDEV_ACTION_* notification.
 *            No RDY state transition.
 *
 *    2) Device table load (DM_TABLE_LOAD ioctl).
 *       There is inactive table present for the device.
 *       Based on kernel version (kernel commit 89f871af1b26d98d983cba7ed0e86effa45ba5f8):
 *
 *         - kernel < 5.15: no UDEV_ACTION_* notification.
 *           No UDEV_ACTION_* notification.
 *           No RDY state transition.
 *
 *         - kernel >= 5.15: notified by UDEV_ACTION_ADD.
 *            UDEV_ACTION_ADD notification.
 *            DEV_RDY_UNPROCESSED transitions to DEV_RDY_UNCONFIGURED.
 *
 *    3) Device resume (DM_DEV_SUSPEND with 'resume' flag ioctl).
 *       There is active table present for the device.
 *       Notified by UDEV_ACTION_CHANGE with DM cookie set.
 *       DEV_RDY_UNCONFIGURED transitions to one of:
 *
 *         - DEV_RDY_PUBLIC
 *
 *         - DEV_RDY_FLAT
 *           (DM_UDEV_DISABLE_DISK_RULES_FLAG is set)
 *
 *         - DEV_RDY_PRIVATE
 *           (DM_UDEV_DISABLE_OTHER_RULES_FLAG is set)
 *
 *         - DEV_RDY_UNAVAILABLE
 *           (is suspended)
 *
 *
 * We expect this sequence for DM device table reload:
 *
 *    1) Device table load (DM_TABLE_LOAD ioctl).
 *       There is active and inactive table present for the device.
 *       No UDEV_ACTION_* notification.
 *       No RDY state transition.
 *
 *    2) Device resume (DM_DEV_SUSPEND with 'resume' flag ioctl).
 *       The inactive table switches to active.
 *       Notified by UDEV_ACTION_CHANGE with DM cookie set.
 *       Ready state transitions to one of:
 *
 *         - DEV_RDY_PUBLIC
 *
 *         - DEV_RDY_FLAT
 *
 *         - DEV_RDY_PRIVATE
 *
 *         - DEV_RDY_UNAVAILABLE
 *
 *
 * We expect this sequence for DM device rename and/or UUID change:
 *
 *   1) Device rename (DM_DEV_RENAME ioctl).
 *      The name and/or uuid changes.
 *      Notified by UDEV_ACTION_CHANGE with DM cookie set
 *      (only if it was active before, no udev action otherwise!)
 *      Ready state transitions to one of:
 *
 *        - DEV_RDY_PUBLIC
 *
 *        - DEV_RDY_FLAT
 *
 *        - DEV_RDY_PRIVATE
 *
 *        - DEV_RDY_UNAVAILABLE
 *
 *
 * We expect this sequence for DM device remove:
 *
 *   1) Device remove (DM_DEV_REMOVE ioctl).
 *      Notified by UDEV_ACTION_REMOVE with DM cookie set.
 *	Ready state transitions to:
 *
 *	  - DEV_RDY_REMOVED
 */
static int _dm_scan_pre(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_ucmd_dev_ready_t ready;
	int                  has_cookie, is_synth, is_suspended;
	const void          *val;
	udev_action_t        action;
	dm_cookie_flags_t    cookie_flags = 0;
	int                  r            = 0;

	sid_res_log_debug(mod_res, "scan-pre");

	if ((has_cookie = _get_cookie_props(mod_res, ucmd_ctx, &cookie_flags)) < 0) {
		r = -1;
		goto out;
	}

	if (!(val = sid_ucmd_kv_get(mod_res, ucmd_ctx, SID_KV_NS_UDEV, DM_U_SUSPENDED, NULL, NULL, 0))) {
		sid_res_log_error(mod_res, _failed_to_get_msg, DM_U_SUSPENDED);
		r = -1;
		goto out;
	}
	is_suspended = !strcmp(val, "1");

	action       = sid_ucmd_ev_get_dev_action(ucmd_ctx);
	is_synth     = sid_ucmd_ev_get_dev_synth_uuid(ucmd_ctx) != NULL;
	ready        = sid_ucmd_dev_get_ready(mod_res, ucmd_ctx, 0);

	/* Quick sanity check. */
	if (has_cookie && (is_synth || (action != UDEV_ACTION_CHANGE))) {
		/* very unlikely, but just in case something fakes events incorrectly */
		sid_res_log_error(
			mod_res,
			"Incorrect combination of properties detected in udev event: action=%d, is_synth=%d, has_cookie=%d.",
			action,
			is_synth,
			has_cookie);
		r = -1;
		goto out;
	}

	if (is_suspended) {
		/* whenever we find the device in suspended state, switch ready state to DEV_RDY_UNAVAILABLE */
		r = sid_ucmd_dev_set_ready(mod_res, ucmd_ctx, SID_DEV_RDY_UNAVAILABLE);
		goto out;
	}

	switch (ready) {
		case SID_DEV_RDY_UNDEFINED:
			r = -1;
			goto out;

		case SID_DEV_RDY_REMOVED:
			// TODO: handle device reappeareance
			break;

		case SID_DEV_RDY_UNPROCESSED:
			/*
			 * The first time we see an event for this device.
			 * (Or we don't have any records about possible previous events.)
			 */
			if (has_cookie) {
				/*
				 * We have step 3) from the activation sequence here
				 * without having a record about previous steps.
				 * We transition the state to DEV_RDY_UNCONFIGURED directly
				 * here and jump to processing the event from this state.
				 */
				sid_res_log_warning(mod_res, "Genuine udev event received, but no previous records found.");

				if ((r = sid_ucmd_dev_set_ready(mod_res, ucmd_ctx, SID_DEV_RDY_UNCONFIGURED)) < 0)
					goto out;

				goto handle_unconfigured;
			} else {
				if (is_synth) {
					/* A synthetic uevent without any previous records - skip it. */
					sid_res_log_warning(mod_res,
					                    "Synthetic udev event received, but no previous records found.");

					/*
					 * FIXME: this is not that correct in case we have a device without any
					 * active table yet. We cannot detect this case using only sysfs, but we'd
					 * need to call dmsetup table (or issue a dm ioctl directly) to get more info.
					 */
					if ((r = sid_ucmd_dev_set_ready(mod_res, ucmd_ctx, SID_DEV_RDY_PUBLIC)) < 0)
						goto out;
				} else {
					/* Tracking step 1) from activation sequence. */
					if (action == UDEV_ACTION_ADD) {
						if ((r = sid_ucmd_dev_set_ready(mod_res, ucmd_ctx, SID_DEV_RDY_UNCONFIGURED)) < 0)
							goto out;
					} else {
						/*
						 * Genuine event without DM cookie set and it's not ADD event.
						 * This must be a special-purpose event (e.g. DISK_RO, RESIZE,
						 * DISK_EVENT_MEDIA_CHANGE...).
						 */
						sid_res_log_warning(mod_res,
						                    "Special-purpose udev event received, but no previous records "
						                    "found.");
					}
				}
			}
			break;

		case SID_DEV_RDY_UNCONFIGURED:
handle_unconfigured:
			if (has_cookie) {
				/*
				 * The device has already been created (step 1).
				 * Now, we are expecting CHANGE event with a DM cookie set that comes
				 * right after the DM table load (step 2) + DM resume (step 3).
				 *
				 * We don't need to actually test whether this is a CHANGE event because
				 * if it has a cookie, it can't be anything else - see the sanity check at
				 * the beginning of this function.
				 *
				 * Set ready state according to flags from the cookie.
				 */
				if (cookie_flags & DM_UDEV_DISABLE_OTHER_RULES_FLAG)
					r = sid_ucmd_dev_set_ready(mod_res, ucmd_ctx, SID_DEV_RDY_PRIVATE);
				else if (cookie_flags & DM_UDEV_DISABLE_DISK_RULES_FLAG)
					r = sid_ucmd_dev_set_ready(mod_res, ucmd_ctx, SID_DEV_RDY_FLAT);
				else
					r = sid_ucmd_dev_set_ready(mod_res, ucmd_ctx, SID_DEV_RDY_PUBLIC);

				if (r < 0)
					goto out;
			} else {
				if (is_synth)
					sid_res_log_warning(mod_res,
					                    "Synthetic udev event received, but device not yet configured.");
				else
					sid_res_log_warning(mod_res, "Unexpected udev event received.");
				goto out;
			}
			break;

		case SID_DEV_RDY_UNINITIALIZED:
			/*
			 * Nothing to do here at DM level.
			 * The DM submodules handle the initialization on their own.
			 */
			break;

		case SID_DEV_RDY_PRIVATE:
		case SID_DEV_RDY_FLAT:
		case SID_DEV_RDY_UNAVAILABLE:
		case SID_DEV_RDY_PUBLIC:
			/*
			 * Device is fully activated at this stage.
			 * Transition among ready states based on DM udev flags.
			 */
			if (has_cookie) {
				if (cookie_flags & DM_UDEV_DISABLE_OTHER_RULES_FLAG)
					r = sid_ucmd_dev_set_ready(mod_res, ucmd_ctx, SID_DEV_RDY_PRIVATE);
				else if (cookie_flags & DM_UDEV_DISABLE_DISK_RULES_FLAG)
					r = sid_ucmd_dev_set_ready(mod_res, ucmd_ctx, SID_DEV_RDY_FLAT);
				else
					r = sid_ucmd_dev_set_ready(mod_res, ucmd_ctx, SID_DEV_RDY_PUBLIC);
			}
			break;
	}
out:
	if (r < 0)
		return -1;

	return _exec_dm_submod(mod_res, ucmd_ctx, DM_SUBMOD_SCAN_PHASE_SCAN_PRE);
}
SID_UCMD_SCAN_PRE(_dm_scan_pre)

static int _dm_scan_current(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-current");
	return _exec_dm_submod(mod_res, ucmd_ctx, DM_SUBMOD_SCAN_PHASE_SCAN_CURRENT);
}
SID_UCMD_SCAN_CURRENT(_dm_scan_current)

static int _dm_scan_next(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-next");

	if (_exec_dm_submod(mod_res, ucmd_ctx, DM_SUBMOD_SCAN_PHASE_SUBSYS_MATCH_NEXT) < 0)
		return -1;

	return _exec_dm_submod(mod_res, ucmd_ctx, DM_SUBMOD_SCAN_PHASE_SCAN_NEXT);
}
SID_UCMD_SCAN_NEXT(_dm_scan_next)

static int _dm_scan_post_current(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-post-current");

	(void) _exec_dm_submod(mod_res, ucmd_ctx, DM_SUBMOD_SCAN_PHASE_SCAN_POST_CURRENT);
	return 0;
}
SID_UCMD_SCAN_POST_CURRENT(_dm_scan_post_current)

static int _dm_scan_post_next(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-post-next");
	return _exec_dm_submod(mod_res, ucmd_ctx, DM_SUBMOD_SCAN_PHASE_SCAN_POST_NEXT);
}
SID_UCMD_SCAN_POST_NEXT(_dm_scan_post_next)

static int _dm_scan_a_exit(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_ucmd_dev_ready_t     ready;
	const dm_cookie_flags_t *flags;
	const char              *flag_name;
	int                      i;

	sid_res_log_debug(mod_res, "scan-a-exit");

	ready = sid_ucmd_dev_get_ready(mod_res, ucmd_ctx, 0);

	/*
	 *  Store DM_UDEV_RULES_VSN and all decoded flags to SID_KV_NS_UDEV
	 *  for backwards compatibility and for use in udev rules
	 */

	if (ready >= _SID_DEV_RDY) {
		if (sid_ucmd_kv_va_set(mod_res,
		                       ucmd_ctx,
		                       .ns    = SID_KV_NS_UDEV,
		                       .key   = DM_U_UDEV_RULES_VSN,
		                       .value = DM_UDEV_RULES_VSN,
		                       .size  = sizeof(DM_UDEV_RULES_VSN),
		                       .flags = SID_KV_FL_SYNC_P) < 0) {
			sid_res_log_error(mod_res, _failed_to_set_msg, DM_U_UDEV_RULES_VSN);
			return -1;
		}
	}

	if (!(flags = sid_ucmd_kv_get(mod_res, ucmd_ctx, SID_KV_NS_DEVMOD, DM_X_COOKIE_FLAGS, NULL, NULL, 0)))
		return 0;

	for (i = 0; i < COOKIE_FLAGS_SHIFT; i++) {
		flag_name = _udev_cookie_flag_names[i];

		if (1 << i & (*flags)) {
			if (sid_ucmd_kv_va_set(mod_res,
			                       ucmd_ctx,
			                       .ns    = SID_KV_NS_UDEV,
			                       .key   = flag_name,
			                       .value = "1",
			                       .size  = 2,
			                       .flags = SID_KV_FL_FRG_RD | SID_KV_FL_SUB_RD) < 0)
				goto fail;
		} else {
			if (sid_ucmd_kv_va_set(mod_res,
			                       ucmd_ctx,
			                       .ns    = SID_KV_NS_UDEV,
			                       .key   = flag_name,
			                       .flags = SID_KV_FL_FRG_RD | SID_KV_FL_SUB_RD) < 0)
				goto fail;
		}
	}

	/* override the flags from cookie based on actual ready state */
	switch (ready) {
		case SID_DEV_RDY_UNINITIALIZED:
		case SID_DEV_RDY_PRIVATE:
		case SID_DEV_RDY_UNAVAILABLE:
			if (sid_ucmd_kv_va_set(mod_res,
			                       ucmd_ctx,
			                       .ns  = SID_KV_NS_UDEV,
			                       .key = flag_name =
			                               _udev_cookie_flag_names[__builtin_ctz(DM_UDEV_DISABLE_OTHER_RULES_FLAG)],
			                       .value = "1",
			                       .size  = 2,
			                       .flags = SID_KV_FL_FRG_RD | SID_KV_FL_SUB_RD) < 0)
				goto fail;
		case SID_DEV_RDY_FLAT:
			if (sid_ucmd_kv_va_set(mod_res,
			                       ucmd_ctx,
			                       .ns  = SID_KV_NS_UDEV,
			                       .key = flag_name =
			                               _udev_cookie_flag_names[__builtin_ctz(DM_UDEV_DISABLE_DISK_RULES_FLAG)],
			                       .value = "1",
			                       .size  = 2,
			                       .flags = SID_KV_FL_FRG_RD | SID_KV_FL_SUB_RD) < 0)
				goto fail;
			break;
		default:
			break;
	}

	return 0;
fail:
	sid_res_log_error(mod_res, _failed_to_set_msg, flag_name);
	return -1;
}
SID_UCMD_SCAN_A_EXIT(_dm_scan_a_exit)

static int _dm_scan_remove_init(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-remove-init");

	if (_get_cookie_props(mod_res, ucmd_ctx, NULL) < 0)
		return -1;

	if (_dm_submod_common_scan_init(mod_res, ucmd_ctx) < 0)
		return -1;

	return _exec_dm_submod(mod_res, ucmd_ctx, DM_SUBMOD_SCAN_PHASE_REMOVE_INIT);
}

SID_UCMD_SCAN_REMOVE_INIT(_dm_scan_remove_init);

static int _dm_scan_remove(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-remove");

	return _exec_dm_submod(mod_res, ucmd_ctx, DM_SUBMOD_SCAN_PHASE_REMOVE);
}
SID_UCMD_SCAN_REMOVE(_dm_scan_remove)

static int _dm_scan_remove_exit(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-remove-exit");
	return _exec_dm_submod(mod_res, ucmd_ctx, DM_SUBMOD_SCAN_PHASE_REMOVE_EXIT);
}

SID_UCMD_SCAN_REMOVE_EXIT(_dm_scan_remove_exit);

static int _dm_scan_b_init(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-b-init");
	return _exec_dm_submod(mod_res, ucmd_ctx, DM_SUBMOD_SCAN_PHASE_B_INIT);
}

SID_UCMD_SCAN_B_INIT(_dm_scan_b_init);

static int _udevcomplete(sid_res_t *mod_res, dm_cookie_base_t cookie_base)
{
	key_t         semkey;
	struct sembuf sb = {0, -1, IPC_NOWAIT};
	int           semid, val;

	semkey = (COOKIE_MAGIC << 16) | cookie_base;

	if ((semid = semget(semkey, 1, 0)) < 0) {
		sid_res_log_error_errno(mod_res, errno, "Failed to get semaphore id for cookie %" PRIx16, cookie_base);
		return -1;
	}

	if ((val = semctl(semid, 0, GETVAL)) < 0) {
		sid_res_log_error_errno(mod_res,
		                        errno,
		                        "Failed to perform semaphore control operation for cookie %" PRIx16 "(semid %d)",
		                        cookie_base,
		                        semid);
		return -1;
	}

	if (semop(semid, &sb, 1) < 0) {
		sid_res_log_error_errno(mod_res,
		                        errno,
		                        "Failed to perform semaphore operation for cookie %" PRIx16 "(semid %d)",
		                        cookie_base,
		                        semid);
		return -1;
	}

	sid_res_log_debug(mod_res, "Cookie 0x%" PRIx16 " (semid %d) decremented to %d.", cookie_base, semid, val - 1);
	return 0;
}

static int _dm_scan_action_current(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	dm_cookie_base_t *cookie_base_p;

	sid_res_log_debug(mod_res, "scan-action-current");

	if ((cookie_base_p =
	             (dm_cookie_base_t *) sid_ucmd_kv_get(mod_res, ucmd_ctx, SID_KV_NS_DEVMOD, DM_X_COOKIE_BASE, NULL, NULL, 0))) {
		if (_udevcomplete(mod_res, *cookie_base_p) < 0)
			return -1;
	}

	return _exec_dm_submod(mod_res, ucmd_ctx, DM_SUBMOD_SCAN_PHASE_ACTION_CURRENT);
}
SID_UCMD_SCAN_ACTION_CURRENT(_dm_scan_action_current)

static int _dm_scan_action_next(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-action-next");
	return _exec_dm_submod(mod_res, ucmd_ctx, DM_SUBMOD_SCAN_PHASE_ACTION_NEXT);
}
SID_UCMD_SCAN_ACTION_NEXT(_dm_scan_action_next)

static int _dm_scan_b_exit(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-b-exit");
	return _exec_dm_submod(mod_res, ucmd_ctx, DM_SUBMOD_SCAN_PHASE_B_EXIT);
}

SID_UCMD_SCAN_B_EXIT(_dm_scan_b_exit);

static int _dm_scan_error(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-error");
	return 0;
}
SID_UCMD_SCAN_ERROR(_dm_scan_error)
