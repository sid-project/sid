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

#ifndef _SID_UBRIDGE_CMD_MODULE_H
#define _SID_UBRIDGE_CMD_MODULE_H

#include "types.h"

#include <stdint.h>
#include <module.h>

#ifdef __cplusplus
extern "C" {
#endif

struct sid_ubridge_cmd_mod_context;
struct sid_ubridge_cmd_context;

typedef int sid_ubridge_cmd_fn_t(struct sid_module *module, struct sid_ubridge_cmd_context *cmd);
typedef int sid_ubridge_cmd_mod_fn_t(struct sid_module *module, struct sid_ubridge_cmd_mod_context *cmd_mod);

/*
 * Macros to register module's management functions.
 */
#define SID_UBRIDGE_CMD_MOD_FN(name, fn)           sid_ubridge_cmd_mod_fn_t *sid_ubridge_cmd_mod_ ## name = fn;

#ifdef __GNUC__

#define _SID_UBRIDGE_CMD_MOD_FN_TO_SID_MODULE_FN_SAFE_CAST(fn) \
	(__builtin_choose_expr(__builtin_types_compatible_p(typeof(fn), sid_ubridge_cmd_mod_fn_t), (sid_module_fn_t *) fn, (void) 0))

#define SID_UBRIDGE_CMD_MOD_INIT(fn)               SID_MODULE_INIT(_SID_UBRIDGE_CMD_MOD_FN_TO_SID_MODULE_FN_SAFE_CAST(fn))
#define SID_UBRIDGE_CMD_MOD_RELOAD(fn)             SID_MODULE_RELOAD(_SID_UBRIDGE_CMD_MOD_FN_TO_SID_MODULE_FN_SAFE_CAST(fn))
#define SID_UBRIDGE_CMD_MOD_EXIT(fn)               SID_MODULE_EXIT(_SID_UBRIDGE_CMD_MOD_FN_TO_SID_MODULE_FN_SAFE_CAST(fn))

#else /* __GNUC__ */

#define SID_UBRIDGE_CMD_MOD_INIT(fn)               SID_UBRIDGE_CMD_MOD_FN(mod_init, fn)   SID_MODULE_INIT((sid_module_fn_t *) fn)
#define SID_UBRIDGE_CMD_MOD_RELOAD(fn)             SID_UBRIDGE_CMD_MOD_FN(mod_reload, fn) SID_MODULE_RELOAD((sid_module_fn_t *) fn)
#define SID_UBRIDGE_CMD_MOD_EXIT(fn)               SID_UBRIDGE_CMD_MOD_FN(mod_exit, fn)   SID_MODULE_EXIT((sid_module_fn_t *) fn)

#endif /* __GNUC__ */

/*
 * Macros to register module's phase functions.
 */
#define SID_UBRIDGE_CMD_FN(name, fn)               sid_ubridge_cmd_fn_t *sid_ubridge_cmd_ ## name = fn;

#ifdef __GNUC__

#define _SID_UBRIDGE_CMD_FN_CHECK_TYPE(fn) \
	(__builtin_choose_expr(__builtin_types_compatible_p(typeof(fn), sid_ubridge_cmd_fn_t), fn, (void) 0))

#else /* __GNUC__ */

#define _SID_UBRIDGE_CMD_FN_CHECK_TYPE(fn) fn

#endif /* __GNUC__ */

#define SID_UBRIDGE_CMD_IDENT(fn)                  SID_UBRIDGE_CMD_FN(ident, _SID_UBRIDGE_CMD_FN_CHECK_TYPE(fn))
#define SID_UBRIDGE_CMD_SCAN_PRE(fn)               SID_UBRIDGE_CMD_FN(scan_pre, _SID_UBRIDGE_CMD_FN_CHECK_TYPE(fn))
#define SID_UBRIDGE_CMD_SCAN_CURRENT(fn)           SID_UBRIDGE_CMD_FN(scan_current, _SID_UBRIDGE_CMD_FN_CHECK_TYPE(fn))
#define SID_UBRIDGE_CMD_SCAN_NEXT(fn)              SID_UBRIDGE_CMD_FN(scan_next, _SID_UBRIDGE_CMD_FN_CHECK_TYPE(fn))
#define SID_UBRIDGE_CMD_SCAN_POST_CURRENT(fn)      SID_UBRIDGE_CMD_FN(scan_post_current, _SID_UBRIDGE_CMD_FN_CHECK_TYPE(fn))
#define SID_UBRIDGE_CMD_SCAN_POST_NEXT(fn)         SID_UBRIDGE_CMD_FN(scan_post_next, _SID_UBRIDGE_CMD_FN_CHECK_TYPE(fn))
#define SID_UBRIDGE_CMD_TRIGGER_ACTION_CURRENT(fn) SID_UBRIDGE_CMD_FN(trigger_action_current, _SID_UBRIDGE_CMD_FN_CHECK_TYPE(fn))
#define SID_UBRIDGE_CMD_TRIGGER_ACTION_NEXT(fn)    SID_UBRIDGE_CMD_FN(trigger_action_next, _SID_UBRIDGE_CMD_FN_CHECK_TYPE(fn))
#define SID_UBRIDGE_CMD_ERROR(fn)                  SID_UBRIDGE_CMD_FN(error, _SID_UBRIDGE_CMD_FN_CHECK_TYPE(fn))

/*
 * Functions to retrieve device properties associated with given command context.
 */
udev_action_t sid_ubridge_cmd_dev_get_action(struct sid_ubridge_cmd_context *cmd);
int sid_ubridge_cmd_dev_get_major(struct sid_ubridge_cmd_context *cmd);
int sid_ubridge_cmd_dev_get_minor(struct sid_ubridge_cmd_context *cmd);
const char *sid_ubridge_cmd_dev_get_name(struct sid_ubridge_cmd_context *cmd);
const char *sid_ubridge_cmd_dev_get_type(struct sid_ubridge_cmd_context *cmd);
uint64_t sid_ubridge_cmd_dev_get_seqnum(struct sid_ubridge_cmd_context *cmd);
const char *sid_ubridge_cmd_dev_get_synth_uuid(struct sid_ubridge_cmd_context *cmd);

typedef enum {
	KV_NS_UDEV,
	KV_NS_GLOBAL,
	KV_NS_MODULE,
	KV_NS_DEVICE,
} sid_ubridge_cmd_kv_namespace_t;

#define KV_PERSISTENT    UINT64_C(0x0000000000000001)
#define KV_MOD_PROTECTED UINT64_C(0x0000000000000002)
#define KV_MOD_PRIVATE   UINT64_C(0x0000000000000004)
#define KV_MOD_RESERVED  UINT64_C(0x0000000000000008)

#define SID_UBRIDGE_CMD_KEY_DEVICE_NEXT_MOD "SID_NEXT_MOD"

void *sid_ubridge_cmd_set_kv(struct sid_ubridge_cmd_context *cmd, sid_ubridge_cmd_kv_namespace_t ns,
			     const char *key, const void *value, size_t value_size, uint64_t flags);
const void *sid_ubridge_cmd_get_kv(struct sid_ubridge_cmd_context *cmd, sid_ubridge_cmd_kv_namespace_t ns,
				   const char *key, size_t *value_size, uint64_t *flags);

int sid_ubridge_cmd_mod_reserve_kv(struct sid_module *mod, struct sid_ubridge_cmd_mod_context *cmd_mod,
				  sid_ubridge_cmd_kv_namespace_t ns, const char *key);
int sid_ubridge_cmd_mod_unreserve_kv(struct sid_module *mod, struct sid_ubridge_cmd_mod_context *cmd_mod,
				     sid_ubridge_cmd_kv_namespace_t ns, const char *key);

typedef enum {
	DEV_NOT_RDY_UNPROCESSED,  /* not ready and not yet processed by SID */
	DEV_NOT_RDY_INACCESSIBLE, /* not ready and not able to perform IO */
	DEV_NOT_RDY_ACCESSIBLE,   /* not ready and able to perform IO */
	DEV_RDY_PRIVATE,          /* ready and for private use of the module/subsystem */
	DEV_RDY_PUBLIC,           /* ready and publicly available for use */
	DEV_RDY_UNAVAILABLE,      /* ready but temporarily unavailable at the moment, e.g. suspended device */
} dev_ready_t;

typedef enum {
	DEV_RES_UNPROCESSED,	  /* not yet processed by SID */
	DEV_RES_FREE,             /* not yet reserved by a layer above */
	DEV_RES_RESERVED,         /* reserved by a layer above */
} dev_reserved_t;

int sid_ubridge_cmd_dev_set_ready(struct sid_ubridge_cmd_context *cmd, dev_ready_t ready);
dev_ready_t sid_ubridge_cmd_dev_get_ready(struct sid_ubridge_cmd_context *cmd);
int sid_ubridge_cmd_dev_set_reserved(struct sid_ubridge_cmd_context *cmd, dev_reserved_t reserved);
dev_reserved_t sid_ubridge_cmd_dev_get_reserved(struct sid_ubridge_cmd_context *cmd);

#ifdef __cplusplus
}
#endif

#endif
