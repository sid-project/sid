/*
 * This file is part of SID.
 *
 * Copyright (C) 2017-2020 Red Hat, Inc. All rights reserved.
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

#ifndef _SID_UCMD_MODULE_H
#define _SID_UCMD_MODULE_H

#include "internal/comp-attrs.h"

#include "internal/common.h"

#include "resource/module.h"

#include <inttypes.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SID_UCMD_BLOCK_MOD_DIR                 LIBDIR "/" PACKAGE "/modules/ucmd/block"
#define SID_UCMD_TYPE_MOD_DIR                  LIBDIR "/" PACKAGE "/modules/ucmd/type"

#define SID_UCMD_MOD_FN_NAME_IDENT             "sid_ucmd_ident"
#define SID_UCMD_MOD_FN_NAME_SCAN_PRE          "sid_ucmd_scan_pre"
#define SID_UCMD_MOD_FN_NAME_SCAN_CURRENT      "sid_ucmd_scan_current"
#define SID_UCMD_MOD_FN_NAME_SCAN_NEXT         "sid_ucmd_scan_next"
#define SID_UCMD_MOD_FN_NAME_SCAN_POST_CURRENT "sid_ucmd_scan_post_current"
#define SID_UCMD_MOD_FN_NAME_SCAN_POST_NEXT    "sid_ucmd_scan_post_next"

#define SID_UCMD_MOD_FN_NAME_SCAN_REMOVE       "sid_ucmd_scan_remove"

#define SID_UCMD_MOD_FN_NAME_ERROR             "sid_ucmd_error"

struct sid_ucmd_common_ctx;
struct sid_ucmd_ctx;
typedef struct sid_resource sid_resource_t;

typedef module_prio_t sid_ucmd_mod_prio_t;
typedef int           sid_ucmd_mod_fn_t(struct module *module, struct sid_ucmd_common_ctx *ucmd_common_ctx);
typedef int           sid_ucmd_fn_t(struct module *module, struct sid_ucmd_ctx *ucmd_ctx);

struct sid_ucmd_mod_fns {
	sid_ucmd_fn_t *ident;
	sid_ucmd_fn_t *scan_pre;
	sid_ucmd_fn_t *scan_current;
	sid_ucmd_fn_t *scan_next;
	sid_ucmd_fn_t *scan_post_current;
	sid_ucmd_fn_t *scan_post_next;
	sid_ucmd_fn_t *trigger_action_current;
	sid_ucmd_fn_t *trigger_action_next;
	sid_ucmd_fn_t *scan_remove;
	sid_ucmd_fn_t *error;
} __packed;

/*
 * Macros to register module's management functions.
 */

#define SID_UCMD_MOD_PRIO(val)    MODULE_PRIO(val)

/*
 * Aliases are encoded as a single string where each alias is delimited by '\0'.
 * For example, "abc\0def\0ijk" defines three aliases - "abc", "def" and "ijk".
 */

#define SID_UCMD_MOD_ALIASES(val) MODULE_ALIASES(val)

#ifdef __GNUC__

	#define _SID_UCMD_MOD_FN_TO_MODULE_FN_SAFE_CAST(fn)                                                                        \
		(__builtin_choose_expr(__builtin_types_compatible_p(typeof(fn), sid_ucmd_mod_fn_t),                                \
		                       (module_cb_fn_t *) fn,                                                                      \
		                       (void) 0))

	#define SID_UCMD_MOD_INIT(fn)  MODULE_INIT(_SID_UCMD_MOD_FN_TO_MODULE_FN_SAFE_CAST(fn))
	#define SID_UCMD_MOD_RESET(fn) MODULE_RESET(_SID_UCMD_MOD_FN_TO_MODULE_FN_SAFE_CAST(fn))
	#define SID_UCMD_MOD_EXIT(fn)  MODULE_EXIT(_SID_UCMD_MOD_FN_TO_MODULE_FN_SAFE_CAST(fn))

#else /* __GNUC__ */

	#define SID_UCMD_MOD_FN(name, fn) sid_ucmd_mod_fn_t *sid_ucmd_mod_##name = fn;

	#define SID_UCMD_MOD_INIT(fn)     SID_UCMD_MOD_FN(init, fn) MODULE_INIT((module_cb_fn_t *) fn)
	#define SID_UCMD_MOD_RESET(fn)    SID_UCMD_MOD_FN(reset, fn) MODULE_RESET((module_cb_fn_t *) fn)
	#define SID_UCMD_MOD_EXIT(fn)     SID_UCMD_MOD_FN(exit, fn) MODULE_EXIT((module_cb_fn_t *) fn)

#endif /* __GNUC__ */

/*
 * Macros to register module's phase functions.
 */
#define SID_UCMD_FN(name, fn) sid_ucmd_fn_t *sid_ucmd_##name = fn;

#ifdef __GNUC__

	#define _SID_UCMD_FN_CHECK_TYPE(fn)                                                                                        \
		(__builtin_choose_expr(__builtin_types_compatible_p(typeof(fn), sid_ucmd_fn_t), fn, (void) 0))

#else /* __GNUC__ */

	#define _SID_UCMD_FN_CHECK_TYPE(fn) fn

#endif /* __GNUC__ */

#define SID_UCMD_IDENT(fn)                  SID_UCMD_FN(ident, _SID_UCMD_FN_CHECK_TYPE(fn))
#define SID_UCMD_SCAN_PRE(fn)               SID_UCMD_FN(scan_pre, _SID_UCMD_FN_CHECK_TYPE(fn))
#define SID_UCMD_SCAN_CURRENT(fn)           SID_UCMD_FN(scan_current, _SID_UCMD_FN_CHECK_TYPE(fn))
#define SID_UCMD_SCAN_NEXT(fn)              SID_UCMD_FN(scan_next, _SID_UCMD_FN_CHECK_TYPE(fn))
#define SID_UCMD_SCAN_POST_CURRENT(fn)      SID_UCMD_FN(scan_post_current, _SID_UCMD_FN_CHECK_TYPE(fn))
#define SID_UCMD_SCAN_POST_NEXT(fn)         SID_UCMD_FN(scan_post_next, _SID_UCMD_FN_CHECK_TYPE(fn))
#define SID_UCMD_TRIGGER_ACTION_CURRENT(fn) SID_UCMD_FN(trigger_action_current, _SID_UCMD_FN_CHECK_TYPE(fn))
#define SID_UCMD_TRIGGER_ACTION_NEXT(fn)    SID_UCMD_FN(trigger_action_next, _SID_UCMD_FN_CHECK_TYPE(fn))
#define SID_UCMD_SCAN_REMOVE(fn)            SID_UCMD_FN(scan_emove, _SID_UCMD_FN_CHECK_TYPE(fn))
#define SID_UCMD_ERROR(fn)                  SID_UCMD_FN(error, _SID_UCMD_FN_CHECK_TYPE(fn))

/*
 * Functions to retrieve device properties associated with given command ctx.
 */
udev_action_t  sid_ucmd_event_get_dev_action(struct sid_ucmd_ctx *ucmd_ctx);
udev_devtype_t sid_ucmd_event_get_dev_type(struct sid_ucmd_ctx *ucmd_ctx);
int            sid_ucmd_event_get_dev_major(struct sid_ucmd_ctx *ucmd_ctx);
int            sid_ucmd_event_get_dev_minor(struct sid_ucmd_ctx *ucmd_ctx);
const char    *sid_ucmd_event_get_dev_path(struct sid_ucmd_ctx *ucmd_ctx);
const char    *sid_ucmd_event_get_dev_name(struct sid_ucmd_ctx *ucmd_ctx);
uint64_t       sid_ucmd_event_get_dev_seqnum(struct sid_ucmd_ctx *ucmd_ctx);
uint64_t       sid_ucmd_event_get_dev_diskseq(struct sid_ucmd_ctx *ucmd_ctx);
const char    *sid_ucmd_event_get_dev_synth_uuid(struct sid_ucmd_ctx *ucmd_ctx);

typedef enum {
	KV_NS_UNDEFINED, /* namespace not defined */
	KV_NS_UDEV,      /* per-device ns with records in the scope of current device
	                    records automatically imported from udev and all
	                    changed/new records are exported back to udev */
	KV_NS_DEVICE,    /* per-device ns with records in the scope of current device */
	KV_NS_MODULE,    /* per-module ns with records in the scope of current module */
	KV_NS_DEVMOD,    /* per-device ns with records in the scope of current device and module */
	KV_NS_GLOBAL,    /* global ns with records visible for all modules and when processing any device */
} sid_ucmd_kv_namespace_t;

typedef enum {
	KV_FLAGS_UNSET = UINT64_C(0x0000000000000000),

	KV_ALIGN       = UINT64_C(0x0000000000000001), /* make sure value's address is aligned to sizeof(void *) */

	KV_SYNC        = UINT64_C(0x0000000000000002), /* synchronize with main KV store */
	KV_PERSIST     = UINT64_C(0x0000000000000004), /* make record persistent */
	KV_SYNC_P      = UINT64_C(0x0000000000000006), /* shortcut for KV_SYNC | KV_PERSISTENT */

	KV_AR          = UINT64_C(0x0000000000000008), /* create an archive of current value */

	KV_RS          = UINT64_C(0x00000000000000010), /* reserve key */

	KV_FRG_RD      = UINT64_C(0x0000000000000020), /* foreign modules can read */
	KV_SUB_RD      = UINT64_C(0x0000000000000040), /* subordinate modules can read */
	KV_SUP_RD      = UINT64_C(0x0000000000000080), /* superior modules can read */
	KV_RD          = UINT64_C(0x00000000000000E0), /* shortcut for KV_FRG_RD | KV_SUB_RD | KV_SUP_RD */

	KV_FRG_WR      = UINT64_C(0x0000000000000100), /* foreign modules can write */
	KV_SUB_WR      = UINT64_C(0x0000000000000200), /* subordinate modules can write */
	KV_SUP_WR      = UINT64_C(0x0000000000000400), /* superior modules can write */
	KV_WR          = UINT64_C(0x0000000000000700), /* shortcut for KV_FRG_WR | KV_SUB_WR | KV_SUP_WR */

	_KV_ENUM_SIZE  = UINT64_C(0x7fffffffffffffff), /* used to force the enum to 64 bits */
} sid_ucmd_kv_flags_t;

#define SID_UCMD_KV_UNSET            ((void *) -1)
#define SID_UCMD_KEY_DEVICE_NEXT_MOD "SID_NEXT_MOD"

void *sid_ucmd_set_kv(struct module          *mod,
                      struct sid_ucmd_ctx    *ucmd_ctx,
                      sid_ucmd_kv_namespace_t ns,
                      const char             *key,
                      const void             *value,
                      size_t                  value_size,
                      sid_ucmd_kv_flags_t     flags);

const void *sid_ucmd_get_kv(struct module          *mod,
                            struct sid_ucmd_ctx    *ucmd_ctx,
                            sid_ucmd_kv_namespace_t ns,
                            const char             *key,
                            size_t                 *value_size,
                            sid_ucmd_kv_flags_t    *flags,
                            unsigned int            archive);

const void *sid_ucmd_get_foreign_mod_kv(struct module          *mod,
                                        struct sid_ucmd_ctx    *ucmd_ctx,
                                        const char             *foreign_mod_name,
                                        sid_ucmd_kv_namespace_t ns,
                                        const char             *key,
                                        size_t                 *value_size,
                                        sid_ucmd_kv_flags_t    *flags,
                                        unsigned int            archive);

const void *sid_ucmd_get_foreign_dev_kv(struct module          *mod,
                                        struct sid_ucmd_ctx    *ucmd_ctx,
                                        const char             *foreign_dev_id,
                                        sid_ucmd_kv_namespace_t ns,
                                        const char             *key,
                                        size_t                 *value_size,
                                        sid_ucmd_kv_flags_t    *flags,
                                        unsigned int            archive);

const void *sid_ucmd_get_foreign_dev_mod_kv(struct module          *mod,
                                            struct sid_ucmd_ctx    *ucmd_ctx,
                                            const char             *foreign_dev_id,
                                            const char             *foreign_mod_name,
                                            sid_ucmd_kv_namespace_t ns,
                                            const char             *key,
                                            size_t                 *value_size,
                                            sid_ucmd_kv_flags_t    *flags,
                                            unsigned int            archive);

// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// TODO: The sid_ucmd_part_get_disk_kv doesn't work right now.
//
// 	 Instead, we should be using sid_ucmd_get_foreign_dev_mod_kv with the
// 	 dev ID of the parent disk and then remove this function.
//
// 	 We will be adding ucmd-module.h API to get the layer/list of devices
// 	 underneath given device and also the layer/list of devices above
// 	 (thinking in the form of an iterator). This still needs some thinking
// 	 of a good way how to represent it as we'll be using this for both
// 	 partitions and other devices which are not partitions, but layered
// 	 devices in general.
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
const void *sid_ucmd_part_get_disk_kv(struct module       *mod,
                                      struct sid_ucmd_ctx *ucmd_ctx,
                                      const char          *key,
                                      size_t              *value_size,
                                      sid_ucmd_kv_flags_t *flags);

int sid_ucmd_mod_reserve_kv(struct module              *mod,
                            struct sid_ucmd_common_ctx *ucmd_common_ctx,
                            sid_ucmd_kv_namespace_t     ns,
                            const char                 *key,
                            sid_ucmd_kv_flags_t         flags);

int sid_ucmd_mod_unreserve_kv(struct module              *mod,
                              struct sid_ucmd_common_ctx *ucmd_common_ctx,
                              sid_ucmd_kv_namespace_t     ns,
                              const char                 *key);

int sid_ucmd_mod_add_subresource(struct module *mod, struct sid_ucmd_common_ctx *ucmd_common_ctx, sid_resource_t *mod_subresource);

typedef enum {
	/* states in which any layers above are not possible */
	DEV_RDY_UNDEFINED,     /* undefined or invalid */
	DEV_RDY_REMOVED,       /* not ready - removed */
	DEV_RDY_UNPROCESSED,   /* not ready - not yet processed by SID */
	DEV_RDY_UNCONFIGURED,  /* not ready - not able to perform IO */
	DEV_RDY_UNINITIALIZED, /* not ready - able to perform IO, but not yet initialized */
	DEV_RDY_PRIVATE,       /* ready     - but only for private use of the module/subsystem */
	DEV_RDY_FLAT,          /* ready     - publicly available for use, but possible layers on top kept folded intentionally */

	/* states in which layers above possible */
	DEV_RDY_UNAVAILABLE, /* ready     - but temporarily unavailable at the moment, e.g. suspended device */
	DEV_RDY_PUBLIC,      /* ready     - publicly available for use */
} dev_ready_t;

typedef enum {
	DEV_RES_UNDEFINED,   /* undefined or invalid */
	DEV_RES_UNPROCESSED, /* not yet processed by SID */
	DEV_RES_RESERVED,    /* reserved by a layer above */
	DEV_RES_USED,        /* used by a layer above */
	DEV_RES_FREE,        /* not yet reserved or used by a layer above */
} dev_reserved_t;

int         sid_ucmd_dev_set_ready(struct module *mod, struct sid_ucmd_ctx *ucmd_ctx, dev_ready_t ready);
dev_ready_t sid_ucmd_dev_get_ready(struct module *mod, struct sid_ucmd_ctx *ucmd_ctx, unsigned int archive);

int            sid_ucmd_dev_set_reserved(struct module *mod, struct sid_ucmd_ctx *ucmd_ctx, dev_reserved_t reserved);
dev_reserved_t sid_ucmd_dev_get_reserved(struct module *mod, struct sid_ucmd_ctx *ucmd_ctx, unsigned int archive);

int sid_ucmd_dev_add_alias(struct module *mod, struct sid_ucmd_ctx *ucmd_ctx, const char *alias_cat, const char *alias_id);
int sid_ucmd_dev_remove_alias(struct module *mod, struct sid_ucmd_ctx *ucmd_ctx, const char *alias_cat, const char *alias_id);

int sid_ucmd_group_create(struct module          *mod,
                          struct sid_ucmd_ctx    *ucmd_ctx,
                          sid_ucmd_kv_namespace_t group_ns,
                          sid_ucmd_kv_flags_t     group_flags,
                          const char             *group_cat,
                          const char             *group_id);

int sid_ucmd_group_add_current_dev(struct module          *mod,
                                   struct sid_ucmd_ctx    *ucmd_ctx,
                                   sid_ucmd_kv_namespace_t group_ns,
                                   const char             *group_cat,
                                   const char             *group_id);

int sid_ucmd_group_remove_current_dev(struct module          *mod,
                                      struct sid_ucmd_ctx    *ucmd_ctx,
                                      sid_ucmd_kv_namespace_t group_ns,
                                      const char             *group_cat,
                                      const char             *group_id);

int sid_ucmd_group_destroy(struct module          *mod,
                           struct sid_ucmd_ctx    *ucmd_ctx,
                           sid_ucmd_kv_namespace_t group_ns,
                           const char             *group_cat,
                           const char             *group_id,
                           int                     force);

#ifdef __cplusplus
}
#endif

#endif
