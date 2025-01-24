/*
 * SPDX-FileCopyrightText: (C) 2017-2025 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _SID_UCMD_MODULE_H
#define _SID_UCMD_MODULE_H

#include "internal/comp-attrs.h"

#include "internal/common.h"

#include "resource/mod.h"

#include <inttypes.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SID_UCMD_BLOCK_MOD_DIR                   LIBDIR "/" PACKAGE "/modules/ucmd/block"
#define SID_UCMD_TYPE_MOD_DIR                    LIBDIR "/" PACKAGE "/modules/ucmd/type"

#define SID_UCMD_MOD_FN_NAME_SCAN_A_INIT         "sid_ucmd_scan_a_init"
#define SID_UCMD_MOD_FN_NAME_SCAN_PRE            "sid_ucmd_scan_pre"
#define SID_UCMD_MOD_FN_NAME_SCAN_CURRENT        "sid_ucmd_scan_current"
#define SID_UCMD_MOD_FN_NAME_SCAN_NEXT           "sid_ucmd_scan_next"
#define SID_UCMD_MOD_FN_NAME_SCAN_POST_CURRENT   "sid_ucmd_scan_post_current"
#define SID_UCMD_MOD_FN_NAME_SCAN_POST_NEXT      "sid_ucmd_scan_post_next"
#define SID_UCMD_MOD_FN_NAME_SCAN_A_EXIT         "sid_ucmd_scan_a_exit"
#define SID_UCMD_MOD_FN_NAME_SCAN_REMOVE_INIT    "sid_ucmd_scan_remove_init"
#define SID_UCMD_MOD_FN_NAME_SCAN_REMOVE         "sid_ucmd_scan_remove"
#define SID_UCMD_MOD_FN_NAME_SCAN_REMOVE_EXIT    "sid_ucmd_scan_remove_exit"
#define SID_UCMD_MOD_FN_NAME_SCAN_B_INIT         "sid_ucmd_scan_b_init"
#define SID_UCMD_MOD_FN_NAME_SCAN_ACTION_CURRENT "sid_ucmd_scan_action_current"
#define SID_UCMD_MOD_FN_NAME_SCAN_ACTION_NEXT    "sid_ucmd_scan_action_next"
#define SID_UCMD_MOD_FN_NAME_SCAN_B_EXIT         "sid_ucmd_scan_b_exit"
#define SID_UCMD_MOD_FN_NAME_SCAN_ERROR          "sid_ucmd_scan_error"

struct sid_ucmd_common_ctx;
struct sid_ucmd_ctx;

typedef int sid_ucmd_mod_fn_t(sid_res_t *mod_res, struct sid_ucmd_common_ctx *ucmd_common_ctx);
typedef int sid_ucmd_fn_t(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx);

/*
 * Macros to register module's management functions.
 */

#define SID_UCMD_MOD_PRIO(val)    SID_MOD_PRIO(val)

/*
 * Aliases are encoded as a single string where each alias is delimited by '\0'.
 * For example, "abc\0def\0ijk" defines three aliases - "abc", "def" and "ijk".
 */

#define SID_UCMD_MOD_ALIASES(val) SID_MOD_ALIASES(val)

#ifdef __GNUC__

	#define _SID_UCMD_MOD_FN_SAFE_CAST(fn)                                                                                     \
		(__builtin_choose_expr(__builtin_types_compatible_p(typeof(fn), sid_ucmd_mod_fn_t),                                \
		                       (sid_mod_cb_fn_t *) fn,                                                                     \
		                       (void) 0))

	#define SID_UCMD_MOD_INIT(fn)  SID_MOD_INIT(_SID_UCMD_MOD_FN_SAFE_CAST(fn))
	#define SID_UCMD_MOD_RESET(fn) SID_MOD_RESET(_SID_UCMD_MOD_FN_SAFE_CAST(fn))
	#define SID_UCMD_MOD_EXIT(fn)  SID_MOD_EXIT(_SID_UCMD_MOD_FN_SAFE_CAST(fn))

#else /* __GNUC__ */

	#define SID_UCMD_MOD_FN(name, fn) sid_ucmd_mod_fn_t *sid_ucmd_mod_##name = fn;

	#define SID_UCMD_MOD_INIT(fn)     SID_UCMD_MOD_FN(init, fn) SID_MOD_INIT((module_cb_fn_t *) fn)
	#define SID_UCMD_MOD_RESET(fn)    SID_UCMD_MOD_FN(reset, fn) SID_MOD_RESET((module_cb_fn_t *) fn)
	#define SID_UCMD_MOD_EXIT(fn)     SID_UCMD_MOD_FN(exit, fn) SID_MOD_EXIT((module_cb_fn_t *) fn)

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

#define SID_UCMD_SCAN_A_INIT(fn)         SID_UCMD_FN(scan_a_init, _SID_UCMD_FN_CHECK_TYPE(fn))
#define SID_UCMD_SCAN_PRE(fn)            SID_UCMD_FN(scan_pre, _SID_UCMD_FN_CHECK_TYPE(fn))
#define SID_UCMD_SCAN_CURRENT(fn)        SID_UCMD_FN(scan_current, _SID_UCMD_FN_CHECK_TYPE(fn))
#define SID_UCMD_SCAN_NEXT(fn)           SID_UCMD_FN(scan_next, _SID_UCMD_FN_CHECK_TYPE(fn))
#define SID_UCMD_SCAN_POST_CURRENT(fn)   SID_UCMD_FN(scan_post_current, _SID_UCMD_FN_CHECK_TYPE(fn))
#define SID_UCMD_SCAN_POST_NEXT(fn)      SID_UCMD_FN(scan_post_next, _SID_UCMD_FN_CHECK_TYPE(fn))
#define SID_UCMD_SCAN_A_EXIT(fn)         SID_UCMD_FN(scan_a_exit, _SID_UCMD_FN_CHECK_TYPE(fn))
#define SID_UCMD_SCAN_REMOVE_INIT(fn)    SID_UCMD_FN(scan_remove_init, _SID_UCMD_FN_CHECK_TYPE(fn))
#define SID_UCMD_SCAN_REMOVE(fn)         SID_UCMD_FN(scan_remove, _SID_UCMD_FN_CHECK_TYPE(fn))
#define SID_UCMD_SCAN_REMOVE_EXIT(fn)    SID_UCMD_FN(scan_remove_exit, _SID_UCMD_FN_CHECK_TYPE(fn))
#define SID_UCMD_SCAN_B_INIT(fn)         SID_UCMD_FN(scan_b_init, _SID_UCMD_FN_CHECK_TYPE(fn))
#define SID_UCMD_SCAN_ACTION_CURRENT(fn) SID_UCMD_FN(scan_action_current, _SID_UCMD_FN_CHECK_TYPE(fn))
#define SID_UCMD_SCAN_ACTION_NEXT(fn)    SID_UCMD_FN(scan_action_next, _SID_UCMD_FN_CHECK_TYPE(fn))
#define SID_UCMD_SCAN_B_EXIT(fn)         SID_UCMD_FN(scan_b_exit, _SID_UCMD_FN_CHECK_TYPE(fn))
#define SID_UCMD_SCAN_ERROR(fn)          SID_UCMD_FN(scan_error, _SID_UCMD_FN_CHECK_TYPE(fn))

/*
 * Functions to retrieve device properties associated with given command ctx.
 */
udev_action_t  sid_ucmd_ev_get_dev_action(struct sid_ucmd_ctx *ucmd_ctx);
udev_devtype_t sid_ucmd_ev_get_dev_type(struct sid_ucmd_ctx *ucmd_ctx);
int            sid_ucmd_ev_get_dev_major(struct sid_ucmd_ctx *ucmd_ctx);
int            sid_ucmd_ev_get_dev_minor(struct sid_ucmd_ctx *ucmd_ctx);
const char    *sid_ucmd_ev_get_dev_path(struct sid_ucmd_ctx *ucmd_ctx);
const char    *sid_ucmd_ev_get_dev_name(struct sid_ucmd_ctx *ucmd_ctx);
uint64_t       sid_ucmd_ev_get_dev_partn(struct sid_ucmd_ctx *ucmd_ctx);
uint64_t       sid_ucmd_ev_get_dev_seqnum(struct sid_ucmd_ctx *ucmd_ctx);
uint64_t       sid_ucmd_ev_get_dev_diskseq(struct sid_ucmd_ctx *ucmd_ctx);
const char    *sid_ucmd_ev_get_dev_synth_uuid(struct sid_ucmd_ctx *ucmd_ctx);

typedef enum {
	SID_KV_NS_UNDEFINED, /* namespace not defined */
	SID_KV_NS_UDEV,      /* per-device ns with records in the scope of current device
	                    records automatically imported from udev and all
	                    changed/new records are exported back to udev */
	SID_KV_NS_DEV,       /* per-device ns with records in the scope of current device */
	SID_KV_NS_MOD,       /* per-module ns with records in the scope of current module */
	SID_KV_NS_DEVMOD,    /* per-device ns with records in the scope of current device and module */
	SID_KV_NS_GLOB,      /* global ns with records visible for all modules and when processing any device */
} sid_kv_ns_t;

#define SID_KV_FL_NONE   UINT64_C(0x0000000000000000)
#define SID_KV_FL_AL     UINT64_C(0x0000000000000001) /* make sure value's address is aligned to sizeof(void *) */

#define SID_KV_FL_SC     UINT64_C(0x0000000000000002) /* synchronize with main KV store */
#define SID_KV_FL_PS     UINT64_C(0x0000000000000004) /* make record persistent */
#define SID_KV_FL_SCPS   UINT64_C(0x0000000000000006) /* shortcut for KV_SC | KV_PS */

#define SID_KV_FL_AR     UINT64_C(0x0000000000000008) /* create an archive of current value */

#define SID_KV_FL_RS     UINT64_C(0x0000000000000010) /* reserve key */

#define SID_KV_FL_FRG_RD UINT64_C(0x0000000000000020) /* foreign modules can read */
#define SID_KV_FL_SUB_RD UINT64_C(0x0000000000000040) /* subordinate modules can read */
#define SID_KV_FL_SUP_RD UINT64_C(0x0000000000000080) /* superior modules can read */
#define SID_KV_FL_RD     UINT64_C(0x00000000000000E0) /* shortcut for KV_FRG_RD | KV_SUB_RD | KV_SUP_RD */

#define SID_KV_FL_FRG_WR UINT64_C(0x0000000000000100) /* foreign modules can write */
#define SID_KV_FL_SUB_WR UINT64_C(0x0000000000000200) /* subordinate modules can write */
#define SID_KV_FL_SUP_WR UINT64_C(0x0000000000000400) /* superior modules can write */
#define SID_KV_FL_WR     UINT64_C(0x0000000000000700) /* shortcut for KV_FRG_WR | KV_SUB_WR | KV_SUP_WR */

typedef uint64_t sid_kv_fl_t;

#define SID_UCMD_KV_UNSET            ((void *) -1)
#define SID_UCMD_KEY_DEVICE_NEXT_MOD "SID_NEXT_MOD"

struct sid_ucmd_kv_set_args {
	sid_kv_ns_t  ns;
	const char  *key;
	const void  *val;
	size_t       sz;
	sid_kv_fl_t  fl;
	const void **st_val;
};

int sid_ucmd_kv_set(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx, struct sid_ucmd_kv_set_args *args);
#define sid_ucmd_kv_va_set(mod_res, ucmd_ctx, ...)                                                                                 \
	sid_ucmd_kv_set(mod_res, ucmd_ctx, &((struct sid_ucmd_kv_set_args) {__VA_ARGS__}))

struct sid_ucmd_kv_get_args {
	sid_kv_ns_t  ns;
	const char  *frg_mod_name;
	const char  *frg_dev_key;
	const char  *key;
	unsigned int ar;
	sid_kv_fl_t *fl;
	size_t      *sz;
	int         *ret_code;
};

const void *sid_ucmd_kv_get(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx, struct sid_ucmd_kv_get_args *args);
#define sid_ucmd_kv_va_get(mod_res, ucmd_ctx, ...)                                                                                 \
	sid_ucmd_kv_get(mod_res, ucmd_ctx, &((struct sid_ucmd_kv_get_args) {__VA_ARGS__}))

int sid_ucmd_kv_reserve(sid_res_t                  *mod_res,
                        struct sid_ucmd_common_ctx *sid_ucmd_common_ctx,
                        sid_kv_ns_t                 ns,
                        const char                 *key,
                        sid_kv_fl_t                 fl);

int sid_ucmd_kv_unreserve(sid_res_t *mod_res, struct sid_ucmd_common_ctx *sid_ucmd_common_ctx, sid_kv_ns_t ns, const char *key);

typedef enum {
	/* states in which any layers above are not possible */
	SID_DEV_RDY_UNDEFINED,    /* undefined or invalid */
	SID_DEV_RDY_REMOVED,      /* not ready - removed */
	SID_DEV_RDY_UNPROCESSED,  /* not ready - not yet processed by SID */
	SID_DEV_RDY_UNCONFIGURED, /* not ready - not able to perform IO */

	SID_DEV_RDY_UNINITIALIZED, /* ready     - able to perform IO, but not initialized yet */
	SID_DEV_RDY_PRIVATE,       /* ready     - only for private use of the module/subsystem */
	SID_DEV_RDY_FLAT,          /* ready     - publicly available for use, but layers on top disabled */

	/* states in which layers above are possible */
	SID_DEV_RDY_UNAVAILABLE, /* ready     - temporarily unavailable at the moment, e.g. suspended device */
	SID_DEV_RDY_PUBLIC,      /* ready     - publicly available for use, layers on top enabled */

	/* markers for easier state matching */
	_SID_DEV_RDY         = SID_DEV_RDY_UNINITIALIZED,
	_SID_DEV_RDY_LAYERED = SID_DEV_RDY_UNAVAILABLE,
} sid_dev_ready_t;

typedef enum {
	SID_DEV_RES_UNDEFINED,   /* undefined or invalid */
	SID_DEV_RES_UNPROCESSED, /* not yet processed by SID */
	SID_DEV_RES_RESERVED,    /* reserved by a layer above */
	SID_DEV_RES_USED,        /* used by a layer above */
	SID_DEV_RES_FREE,        /* not yet reserved or used by a layer above */
} sid_dev_reserved_t;

int             sid_ucmd_dev_set_ready(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx, sid_dev_ready_t ready);
sid_dev_ready_t sid_ucmd_dev_get_ready(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx, unsigned int archive);

int                sid_ucmd_dev_set_reserved(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx, sid_dev_reserved_t reserved);
sid_dev_reserved_t sid_ucmd_dev_get_reserved(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx, unsigned int archive);

int sid_ucmd_dev_alias_add(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx, const char *alias_key, const char *alias);

int sid_ucmd_dev_alias_rename(sid_res_t           *mod_res,
                              struct sid_ucmd_ctx *ucmd_ctx,
                              const char          *alias_key,
                              const char          *old_alias,
                              const char          *new_alias);

int sid_ucmd_dev_alias_del(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx, const char *alias_key, const char *alias);

struct sid_ucmd_dev_alias_get_args {
	const char *dev_key;
	const char *mod_name;
	const char *alias_key;
	size_t     *count;
	int        *ret_code;
};

const char **sid_ucmd_dev_alias_get(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx, struct sid_ucmd_dev_alias_get_args *args);
#define sid_ucmd_dev_alias_va_get(mod_res, ucmd_ctx, ...)                                                                          \
	sid_ucmd_dev_alias_get(mod_res, ucmd_ctx, &((struct sid_ucmd_dev_alias_get_args) {__VA_ARGS__}))

int sid_ucmd_group_create(sid_res_t           *mod_res,
                          struct sid_ucmd_ctx *ucmd_ctx,
                          sid_kv_ns_t          group_ns,
                          sid_kv_fl_t          group_flags,
                          const char          *group_cat,
                          const char          *group_id);

int sid_ucmd_group_add_current_dev(sid_res_t           *mod_res,
                                   struct sid_ucmd_ctx *ucmd_ctx,
                                   sid_kv_ns_t          group_ns,
                                   const char          *group_cat,
                                   const char          *group_id);

int sid_ucmd_group_del_current_dev(sid_res_t           *mod_res,
                                   struct sid_ucmd_ctx *ucmd_ctx,
                                   sid_kv_ns_t          group_ns,
                                   const char          *group_cat,
                                   const char          *group_id);

int sid_ucmd_group_destroy(sid_res_t           *mod_res,
                           struct sid_ucmd_ctx *ucmd_ctx,
                           sid_kv_ns_t          group_ns,
                           const char          *group_cat,
                           const char          *group_id,
                           int                  force);

typedef enum {
	SID_DEV_SEARCH_IMM_ANC,
	SID_DEV_SEARCH_ANC,
	SID_DEV_SEARCH_BASE,
	SID_DEV_SEARCH_IMM_DESC,
	SID_DEV_SEARCH_DESC,
	SID_DEV_SEARCH_TOP,
} sid_dev_search_t;

struct sid_ucmd_dev_stack_get_args {
	const char      *dev_key;
	sid_dev_search_t method;
	size_t          *count;
	int             *ret_code;
};

const char **sid_ucmd_dev_stack_get(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx, struct sid_ucmd_dev_stack_get_args *args);
#define sid_ucmd_dev_stack_va_get(mod_res, ucmd_ctx, ...)                                                                          \
	sid_ucmd_dev_stack_get(mod_res, ucmd_ctx, &((struct sid_ucmd_dev_stack_get_args) {__VA_ARGS__}))

#ifdef __cplusplus
}
#endif

#endif
