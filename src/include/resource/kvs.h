/*
 * SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _SID_KVS_H
#define _SID_KVS_H

#include "resource/res.h"

#include <sys/uio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SID_KVS_KEY_JOIN     ":"
#define SID_KVS_KEY_JOIN_LEN (sizeof(SID_KVS_KEY_JOIN) - 1)

typedef enum {
	SID_KVS_BACKEND_HASH,
	SID_KVS_BACKEND_BPTREE,
} sid_kvs_backend_t;

#define SID_KVS_VAL_FL_NONE     UINT32_C(0x00000000)
#define SID_KVS_VAL_FL_VECTOR   UINT32_C(0x00000001)
#define SID_KVS_VAL_FL_REF      UINT32_C(0x00000002)
#define SID_KVS_VAL_FL_AUTOFREE UINT32_C(0x00000004)

typedef uint32_t sid_kvs_val_fl_t;

#define SID_KVS_VAL_OP_NONE  UINT32_C(0x00000000)
#define SID_KVS_VAL_OP_MERGE UINT32_C(0x00000001)

typedef uint32_t sid_kvs_val_op_fl_t;

struct sid_kvs_res_params {
	sid_kvs_backend_t backend;

	union {
		struct {
			size_t initial_size;
		} hash;

		struct {
			int order;
		} bptree;
	};
};

struct sid_kvs_update_spec {
	const char         *key;
	void               *old_data;
	size_t              old_data_size;
	sid_kvs_val_fl_t    old_flags;
	void               *new_data;
	size_t              new_data_size;
	sid_kvs_val_fl_t    new_flags;
	sid_kvs_val_op_fl_t op_flags;
	void               *arg; /* fn_arg from sid_kvs_set/unset call */
};

/*
 * Returns:
 *   0 to keep old_data
 *   1 to update old_data with new_data
 */
typedef int (*sid_kvs_update_cb_fn_t)(struct sid_kvs_update_spec *update_spec);

// clang-format off
/*
 * Sets key-value pair:
 *   - fn callback with fn_arg is called before updating the value.
 *   - Value and size depend on flags with KV_STORE_VALUE_ prefix, see table below.
 *     INPUT VALUE:  value as provided via kv_store_set_value's "value" argument.
 *     INPUT SIZE:   value size as provided via kv_store_set_value's "size" argument.
 *     OUTPUT VALUE: value as returned by kv_store_{set,get}_value.
 *     OUTPUT SIZE:  value size as returned by kv_store_get_value.
 *
 *  - Flag support depends on used backend.
 *
 *
 *                     INPUT                               OUTPUT (DB RECORD)                                  NOTES
 *                       |                                         |
 *           -------------------------                     -------------------
 *          /        |                \                   /                   \
 *        FLAGS   OP_FLAG            VALUE             FLAGS                 VALUE
 *          |        |                 |                 |                     |
 *        ----       |            ------------         -----          --------------------
 *       /    \      |           /            \       /     \        /                    \
 * #  VECTOR  REF  MERGE      VALUE        SIZE    VECTOR  REF     VALUE                  SIZE
 * ---------------------------------------------------------------------------------------------------------------------------------------------------------------
 * A     0     0     0     value ref    value size    0     0    value copy ref         value size
 * B     0     0     1     value ref    value size    0     0    value copy ref         value size   merge flag has no effect: B == A
 * C     0     1     0     value ref    value size    0     1    value ref              value size
 * D     0     1     1     value ref    value size    0     1    value ref              value size   merge flag has no effect: D == C
 * E     1     0     0     iovec ref    iovec size    1     0    iovec deep copy ref    iovec size   allocated both iovec copy and value parts
 * F     1     0     1     iovec ref    iovec size    0     0    value merger ref       value size   iovec members merged into single value
 * G     1     1     0     iovec ref    iovec size    1     1    iovec ref              iovec size
 * H     1     1     1     iovec ref    iovec size    1     1    value merger iovec ref iovec size   iovec members merged into single value, iovec has refs to merged value parts
 *
 *
 * The AUTOFREE flag may be used together with REF flag (it has no effect otherwise). Then, if the reference to the
 * value is not needed anymore due to an update or edit, there's "free" called automatically on such a reference.
 * Of course, this assumes that caller allocated the value (for which there's the reference) by "malloc".
 * For vectors, this also means that both the struct iovec and values reference by iovec.iov_base have
 * been allocated by "malloc" too.
 *
 *
 * Returns:
 *   The value that has been set.
 */
// clang-format on

struct sid_kvs_set_args {
	const char            *key;
	void                  *value;
	size_t                 size;
	sid_kvs_val_fl_t       flags;
	sid_kvs_val_op_fl_t    op_flags;
	const char            *archive_key;
	sid_kvs_update_cb_fn_t fn;
	void                  *fn_arg;
	void                 **stored_value;
};

int sid_kvs_set(sid_res_t *kv_store_res, struct sid_kvs_set_args *args);
#define sid_kvs_va_set(kv_store_res, ...) sid_kvs_set((kv_store_res), &((struct sid_kvs_set_args) {__VA_ARGS__}))

struct sid_kvs_get_args {
	const char       *key;
	size_t           *size;
	sid_kvs_val_fl_t *flags;
	int              *ret_code;
};

/*
 * Gets value for given key.
 *   - If size is not NULL, the function returns the size of the value through this output argument.
 *   - If flags is not NULL, the function returns the flags attached to the value through this output argument.
 */
void *sid_kvs_get(sid_res_t *kv_store_res, struct sid_kvs_get_args *args);
#define sid_kvs_va_get(kv_store_res, ...) sid_kvs_get((kv_store_res), &((struct sid_kvs_get_args) {__VA_ARGS__}))

struct sid_kvs_unset_args {
	const char            *key;
	const char            *archive_key;
	sid_kvs_update_cb_fn_t fn;
	void                  *fn_arg;
};

/*
 * Unset given key. If this is the last key for the value (no more aliases), unsets the value too.
 *   - Before unsetting, fn with fn_arg is called to confirm the action.
 *
 * Returns:
 *    0 if value unset
 *   -1 if value not unset
 */
int sid_kvs_unset(sid_res_t *kv_store_res, struct sid_kvs_unset_args *args);
#define sid_kvs_va_unset(kv_store_res, ...) sid_kvs_unset((kv_store_res), &((struct sid_kvs_unset_args) {__VA_ARGS__}))

/*
 * Add alias for given key.
 *   - if the alias is already used and is pointing to a different record
 *     than the original key, the 'force=true' will cause the alias to
 *     point to the same record as key (otherwise returns -1 to indicate error)
 *
 *  Returns:
 *      0 if alias added
 *     -1 if alias not added
 */
int sid_kvs_add_alias(sid_res_t *kv_store_res, const char *key, const char *alias, bool force);

size_t sid_kvs_get_size(sid_res_t *kv_store_res, size_t *meta_size, size_t *data_size);

int  sid_kvs_transaction_begin(sid_res_t *kv_store_res);
void sid_kvs_transaction_end(sid_res_t *kv_store_res, bool rollback);
bool sid_kvs_transaction_active(sid_res_t *kv_store_res);

typedef struct sid_kvs_iter sid_kvs_iter_t;

sid_kvs_iter_t *sid_kvs_iter_create(sid_res_t *kv_store_res, const char *key_start, const char *key_end);
sid_kvs_iter_t *sid_kvs_iter_create_prefix(sid_res_t *kv_store_res, const char *prefix);
int             sid_kvs_iter_current_size(sid_kvs_iter_t *iter,
                                          size_t         *int_size,
                                          size_t         *int_data_size,
                                          size_t         *ext_size,
                                          size_t         *ext_data_size);
const char     *sid_kvs_iter_current_key(sid_kvs_iter_t *iter);
void           *sid_kvs_iter_current(sid_kvs_iter_t *iter, size_t *size, sid_kvs_val_fl_t *flags);
void           *sid_kvs_iter_next(sid_kvs_iter_t *iter, size_t *size, const char **return_key, sid_kvs_val_fl_t *flags);
void            sid_kvs_iter_reset(sid_kvs_iter_t *iter, const char *key_start, const char *key_end);
void            sid_kvs_iter_reset_prefix(sid_kvs_iter_t *kv_store_res, const char *prefix);
void            sid_kvs_iter_destroy(sid_kvs_iter_t *iter);

#ifdef __cplusplus
}
#endif

#endif
