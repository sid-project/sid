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

#include "internal/common.h"

#include "base/buffer.h"
#include "base/comms.h"
#include "iface/iface_internal.h"
#include "internal/bitmap.h"
#include "internal/formatter.h"
#include "internal/mem.h"
#include "internal/util.h"
#include "log/log.h"
#include "resource/kv-store.h"
#include "resource/module-registry.h"
#include "resource/resource.h"
#include "resource/ucmd-module.h"
#include "resource/worker-control.h"

#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <libudev.h>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define UBRIDGE_NAME    "ubridge"
#define CONNECTION_NAME "connection"
#define COMMAND_NAME    "command"

#define INTERNAL_AGGREGATE_ID "ubridge-internal"
#define MODULES_AGGREGATE_ID  "modules"
#define MODULES_BLOCK_ID      "block"
#define MODULES_TYPE_ID       "type"

#define UDEV_TAG_SID               "sid"
#define KV_KEY_UDEV_SID_SESSION_ID "SID_SESSION_ID"

#define SID_UCMD_MOD_FN_NAME_TRIGGER_ACTION_CURRENT "sid_ucmd_trigger_action_current"
#define SID_UCMD_MOD_FN_NAME_TRIGGER_ACTION_NEXT    "sid_ucmd_trigger_action_next"

#define MAIN_KV_STORE_NAME     "main"
#define MAIN_WORKER_CHANNEL_ID "main"

#define KV_PAIR_C "="
#define KV_END_C  ""

#define ID_NULL  ""
#define KEY_NULL ID_NULL

#define KV_PREFIX_OP_ILLEGAL_C   "X"
#define KV_PREFIX_OP_SET_C       ""
#define KV_PREFIX_OP_PLUS_C      "+"
#define KV_PREFIX_OP_MINUS_C     "-"
#define KV_PREFIX_NS_UNDEFINED_C ""
#define KV_PREFIX_NS_UDEV_C      "U"
#define KV_PREFIX_NS_DEVICE_C    "D"
#define KV_PREFIX_NS_MODULE_C    "M"
#define KV_PREFIX_NS_GLOBAL_C    "G"

#define KEY_SYS_C "#"

#define KV_KEY_DEV_READY    KEY_SYS_C "RDY"
#define KV_KEY_DEV_RESERVED KEY_SYS_C "RES"
#define KV_KEY_DEV_MOD      KEY_SYS_C "MOD"

#define KV_KEY_DOM_LAYER "LYR"
#define KV_KEY_DOM_USER  "USR"

#define KV_KEY_GEN_GROUP_MEMBERS KEY_SYS_C "GMB"
#define KV_KEY_GEN_GROUP_IN      KEY_SYS_C "GIN"

#define MOD_NAME_CORE         "#core"
#define OWNER_CORE            MOD_NAME_CORE
#define DEFAULT_KV_FLAGS_CORE KV_PERSISTENT | KV_MOD_RESERVED | KV_MOD_PRIVATE

#define CMD_DEV_ID_FMT       "%s (%d:%d)"
#define CMD_DEV_ID(ucmd_ctx) ucmd_ctx->udev_dev.name, ucmd_ctx->udev_dev.major, ucmd_ctx->udev_dev.minor

/* internal resources */
const sid_resource_type_t sid_resource_type_ubridge_connection;
const sid_resource_type_t sid_resource_type_ubridge_command;

struct sid_ucmd_mod_ctx {
	sid_resource_t *kv_store_res; /* KV store main or snapshot */
	sid_resource_t *modules_res;  /* top-level resource for all ucmd module registries */
	struct buffer * gen_buf;      /* generic buffer */
};

struct umonitor {
	struct udev *        udev;
	struct udev_monitor *mon;
};

struct ubridge {
	int                     socket_fd;
	struct sid_ucmd_mod_ctx ucmd_mod_ctx;
	struct umonitor         umonitor;
};

typedef enum
{
	CMD_SCAN_PHASE_A_INIT = 0,          /* core initializes phase "A" */
	CMD_SCAN_PHASE_A_IDENT,             /* module */
	CMD_SCAN_PHASE_A_SCAN_PRE,          /* module */
	CMD_SCAN_PHASE_A_SCAN_CURRENT,      /* module */
	CMD_SCAN_PHASE_A_SCAN_NEXT,         /* module */
	CMD_SCAN_PHASE_A_SCAN_POST_CURRENT, /* module */
	CMD_SCAN_PHASE_A_SCAN_POST_NEXT,    /* module */
	CMD_SCAN_PHASE_A_WAITING,           /* core waits for confirmation */
	CMD_SCAN_PHASE_A_EXIT,              /* core exits phase "A" */

	CMD_SCAN_PHASE_B_TRIGGER_ACTION_CURRENT,
	__CMD_SCAN_PHASE_B_TRIGGER_ACTION_START = CMD_SCAN_PHASE_B_TRIGGER_ACTION_CURRENT,
	CMD_SCAN_PHASE_B_TRIGGER_ACTION_NEXT,
	__CMD_SCAN_PHASE_B_TRIGGER_ACTION_END = CMD_SCAN_PHASE_B_TRIGGER_ACTION_NEXT,

	CMD_SCAN_PHASE_ERROR,
} cmd_scan_phase_t;

struct udevice {
	udev_action_t  action;
	udev_devtype_t type;
	const char *   path;
	const char *   name; /* just a pointer to devpath's last element */
	int            major;
	int            minor;
	uint64_t       seqnum;
	const char *   synth_uuid;
};

struct connection {
	int            fd;
	struct buffer *buf;
};

struct sid_ucmd_ctx {
	char *                  dev_id;         /* device identifier (major_minor) */
	struct udevice          udev_dev;       /* udev context for currently processed device */
	cmd_scan_phase_t        scan_phase;     /* current phase at the time of use of this context */
	struct sid_ucmd_mod_ctx ucmd_mod_ctx;   /* commod module context */
	struct buffer *         res_buf;        /* result buffer */
	struct buffer *         exp_buf;        /* export buffer */
	struct sid_msg_header   request_header; /* original request header (keep last, contains flexible array) */
};

struct cmd_mod_fns {
	sid_ucmd_fn_t *ident;
	sid_ucmd_fn_t *scan_pre;
	sid_ucmd_fn_t *scan_current;
	sid_ucmd_fn_t *scan_next;
	sid_ucmd_fn_t *scan_post_current;
	sid_ucmd_fn_t *scan_post_next;
	sid_ucmd_fn_t *trigger_action_current;
	sid_ucmd_fn_t *trigger_action_next;
	sid_ucmd_fn_t *error;
} __attribute__((packed));

struct cmd_exec_arg {
	sid_resource_t *     cmd_res;
	sid_resource_t *     type_mod_registry_res;
	sid_resource_iter_t *block_mod_iter;       /* all block modules to execute */
	sid_resource_t *     type_mod_res_current; /* one type module for current layer to execute */
	sid_resource_t *     type_mod_res_next;    /* one type module for next layer to execute */
};

struct cmd_reg {
	const char *name;
	uint32_t    flags;
	int (*exec)(struct cmd_exec_arg *exec_arg);
};

struct kv_value {
	uint64_t            seqnum;
	sid_ucmd_kv_flags_t flags;
	char                data[]; /* contains both internal and external data */
} __attribute__((packed));

enum
{
	KV_VALUE_IDX_SEQNUM,
	KV_VALUE_IDX_FLAGS,
	KV_VALUE_IDX_OWNER,
	KV_VALUE_IDX_DATA,
	_KV_VALUE_IDX_COUNT,
};

#define KV_VALUE_PREPARE_HEADER(iov, seqnum, flags, owner)                                                                         \
	iov[KV_VALUE_IDX_SEQNUM] = (struct iovec) {&(seqnum), sizeof(seqnum)};                                                     \
	iov[KV_VALUE_IDX_FLAGS]  = (struct iovec) {&(flags), sizeof(flags)};                                                       \
	iov[KV_VALUE_IDX_OWNER]  = (struct iovec)                                                                                  \
	{                                                                                                                          \
		owner, strlen(owner) + 1                                                                                           \
	}

#define KV_VALUE_SEQNUM(iov) (*((uint64_t *) ((struct iovec *) iov)[KV_VALUE_IDX_SEQNUM].iov_base))
#define KV_VALUE_FLAGS(iov)  (*((sid_ucmd_kv_flags_t *) ((struct iovec *) iov)[KV_VALUE_IDX_FLAGS].iov_base))
#define KV_VALUE_OWNER(iov)  ((char *) ((struct iovec *) iov)[KV_VALUE_IDX_OWNER].iov_base)
#define KV_VALUE_DATA(iov)   (((struct iovec *) iov)[KV_VALUE_IDX_DATA].iov_base)

struct kv_update_arg {
	sid_resource_t *res;
	struct buffer * gen_buf;
	const char *    owner;    /* in */
	void *          custom;   /* in/out */
	int             ret_code; /* out */
};

typedef enum
{
	KV_OP_ILLEGAL, /* illegal operation */
	KV_OP_SET,     /* set value for kv */
	KV_OP_PLUS,    /* add value to vector kv */
	KV_OP_MINUS,   /* remove value fomr vector kv */
} kv_op_t;

typedef enum
{
	DELTA_NO_FLAGS  = 0x0,
	DELTA_WITH_DIFF = 0x1, /* calculate difference between old and new value, update records */
	DELTA_WITH_REL  = 0x2, /* as DELTA_WITH_DIFF, but also update referenced relatives */
} delta_flags_t;

struct kv_delta {
	kv_op_t        op;
	delta_flags_t  flags;
	struct buffer *plus;
	struct buffer *minus;
	struct buffer *final;
};

typedef enum
{
	__KEY_PART_START = 0x0,
	KEY_PART_OP      = 0x0,
	KEY_PART_DOM     = 0x1,
	KEY_PART_NS      = 0x2,
	KEY_PART_NS_PART = 0x3,
	KEY_PART_ID      = 0x4,
	KEY_PART_ID_PART = 0x5,
	KEY_PART_CORE    = 0x6,
	__KEY_PART_COUNT,
} key_part_t;

struct kv_key_spec {
	kv_op_t                 op;
	const char *            dom;
	sid_ucmd_kv_namespace_t ns;
	const char *            ns_part;
	const char *            id;
	const char *            id_part;
	const char *            key;
};

struct kv_rel_spec {
	struct kv_delta *   delta;
	struct kv_key_spec *cur_key_spec;
	struct kv_key_spec *rel_key_spec;
};

struct kv_key_res_def {
	sid_ucmd_kv_namespace_t ns;
	const char *            key;
};

struct cross_bitmap_calc_arg {
	struct iovec * old_value;
	size_t         old_size;
	struct bitmap *old_bmp;
	struct iovec * new_value;
	size_t         new_size;
	struct bitmap *new_bmp;
};

struct sid_stats {
	uint64_t key_size;
	uint64_t value_int_size;
	uint64_t value_int_data_size;
	uint64_t value_ext_size;
	uint64_t value_ext_data_size;
	uint64_t meta_size;
	uint32_t nr_kv_pairs;
};

struct sid_msg {
	size_t                 size; /* header + data */
	struct sid_msg_header *header;
};

/*
 * Generic flags for all commands.
 */
#define CMD_KV_IMPORT_UDEV UINT32_C(0x00000001) /* imports udev environment as KV_NS_UDEV records */

#define CMD_KV_EXPORT_UDEV   UINT32_C(0x00000002) /* exports KV_NS_UDEV records */
#define CMD_KV_EXPORT_SID    UINT32_C(0x00000004) /* exports KV_NS_<!UDEV> records */
#define CMD_KV_EXPORT_CLIENT UINT32_C(0x00000008) /* exports KV records to client */

#define CMD_SESSION_ID UINT32_C(0x00000010) /* uses session ID */

/*
 * Capability flags for 'scan' command phases (phases are represented as subcommands).
 */
#define CMD_SCAN_CAP_RDY UINT32_C(0x00000001) /* can set ready state */
#define CMD_SCAN_CAP_RES UINT32_C(0x00000002) /* can set reserved state */
#define CMD_SCAN_CAP_ALL UINT32_C(0xFFFFFFFF) /* can set anything */

static bool _cmd_root_only[] = {
	[SID_CMD_UNDEFINED]  = false,
	[SID_CMD_UNKNOWN]    = false,
	[SID_CMD_ACTIVE]     = false,
	[SID_CMD_CHECKPOINT] = true,
	[SID_CMD_REPLY]      = false,
	[SID_CMD_SCAN]       = true,
	[SID_CMD_VERSION]    = false,
	[SID_CMD_DUMP]       = true,
	[SID_CMD_STATS]      = true,
	[SID_CMD_TREE]       = true,
};

static struct cmd_reg      _cmd_scan_phase_regs[];
static sid_ucmd_kv_flags_t kv_flags_no_persist = (DEFAULT_KV_FLAGS_CORE) & ~KV_PERSISTENT;
static sid_ucmd_kv_flags_t kv_flags_persist    = DEFAULT_KV_FLAGS_CORE;
static char *              core_owner          = OWNER_CORE;

static int        _kv_delta(const char *full_key, struct kv_store_update_spec *spec, void *arg);
static const char _key_prefix_err_msg[] = "Failed to get key prefix to store hierarchy records for device " CMD_DEV_ID_FMT ".";

udev_action_t sid_ucmd_dev_get_action(struct sid_ucmd_ctx *ucmd_ctx)
{
	return ucmd_ctx->udev_dev.action;
}

int sid_ucmd_dev_get_major(struct sid_ucmd_ctx *ucmd_ctx)
{
	return ucmd_ctx->udev_dev.major;
}

int sid_ucmd_dev_get_minor(struct sid_ucmd_ctx *ucmd_ctx)
{
	return ucmd_ctx->udev_dev.minor;
}

const char *sid_ucmd_dev_get_name(struct sid_ucmd_ctx *ucmd_ctx)
{
	return ucmd_ctx->udev_dev.name;
}

udev_devtype_t sid_ucmd_dev_get_type(struct sid_ucmd_ctx *ucmd_ctx)
{
	return ucmd_ctx->udev_dev.type;
}

uint64_t sid_ucmd_dev_get_seqnum(struct sid_ucmd_ctx *ucmd_ctx)
{
	return ucmd_ctx->udev_dev.seqnum;
}

const char *sid_ucmd_dev_get_synth_uuid(struct sid_ucmd_ctx *ucmd_ctx)
{
	return ucmd_ctx->udev_dev.synth_uuid;
}

static const char *_do_buffer_compose_key(struct buffer *buf, struct kv_key_spec *spec, int prefix_only)
{
	static const char *op_to_key_prefix_map[] = {[KV_OP_ILLEGAL] = KV_PREFIX_OP_ILLEGAL_C,
	                                             [KV_OP_SET]     = KV_PREFIX_OP_SET_C,
	                                             [KV_OP_PLUS]    = KV_PREFIX_OP_PLUS_C,
	                                             [KV_OP_MINUS]   = KV_PREFIX_OP_MINUS_C};

	static const char *ns_to_key_prefix_map[] = {[KV_NS_UNDEFINED] = KV_PREFIX_NS_UNDEFINED_C,
	                                             [KV_NS_UDEV]      = KV_PREFIX_NS_UDEV_C,
	                                             [KV_NS_DEVICE]    = KV_PREFIX_NS_DEVICE_C,
	                                             [KV_NS_MODULE]    = KV_PREFIX_NS_MODULE_C,
	                                             [KV_NS_GLOBAL]    = KV_PREFIX_NS_GLOBAL_C};

	/* <op>:<dom>:<ns>:<ns_part>:<id>:<id_part>[:<key>] */

	return sid_buffer_fmt_add(buf,
	                          NULL,
	                          "%s" KV_STORE_KEY_JOIN /* op */
	                          "%s" KV_STORE_KEY_JOIN /* dom */
	                          "%s" KV_STORE_KEY_JOIN /* ns */
	                          "%s" KV_STORE_KEY_JOIN /* ns_part */
	                          "%s" KV_STORE_KEY_JOIN /* id */
	                          "%s"
	                          "%s" /* id_part */
	                          "%s",
	                          op_to_key_prefix_map[spec->op],
	                          spec->dom,
	                          ns_to_key_prefix_map[spec->ns],
	                          spec->ns_part,
	                          spec->id,
	                          spec->id_part,
	                          prefix_only ? KEY_NULL : KV_STORE_KEY_JOIN,
	                          prefix_only ? KEY_NULL : spec->key);
}

static const char *_buffer_compose_key(struct buffer *buf, struct kv_key_spec *spec)
{
	/* <op>:<dom>:<ns>:<ns_part>:<id>:<id_part>:<key> */
	return _do_buffer_compose_key(buf, spec, 0);
}

static const char *_buffer_compose_key_prefix(struct buffer *buf, struct kv_key_spec *spec)
{
	/* <op>:<dom>:<ns>:<ns_part><id>:<id_part> */
	return _do_buffer_compose_key(buf, spec, 1);
}

static const char *_get_key_part(const char *key, key_part_t req_part, size_t *len)
{
	key_part_t  part;
	const char *start = key, *end;

	for (part = __KEY_PART_START; part < req_part; part++) {
		if (!(start = strstr(start, KV_STORE_KEY_JOIN)))
			return NULL;
		start++;
	}

	if (len) {
		if (req_part == __KEY_PART_COUNT - 1)
			*len = strlen(start);
		else {
			if (!(end = strstr(start, KV_STORE_KEY_JOIN)))
				return NULL;
			*len = end - start;
		}
	}

	return start;
}

static kv_op_t _get_op_from_key(const char *key)
{
	const char *str;
	size_t      len;

	/* |<>|
	 * <op>:<dom>:<ns>:<ns_part>:<id>:<id_part>[:<key>]
	 */

	if (!(str = _get_key_part(key, KEY_PART_OP, &len)) || len > 1)
		return KV_OP_ILLEGAL;

	if (!len)
		return KV_OP_SET;

	if (str[0] == KV_PREFIX_OP_PLUS_C[0])
		return KV_OP_PLUS;
	else if (str[0] == KV_PREFIX_OP_MINUS_C[0])
		return KV_OP_MINUS;

	return KV_OP_ILLEGAL;
}

static sid_ucmd_kv_namespace_t _get_ns_from_key(const char *key)
{
	const char *str;
	size_t      len;

	/*            |<>|
	 * <op>:<dom>:<ns>:<ns_part>:<id>:<id_part>[:<key>]
	 */

	if (!(str = _get_key_part(key, KEY_PART_NS, &len)) || len > 1)
		return KV_NS_UNDEFINED;

	if (str[0] == KV_PREFIX_NS_UDEV_C[0])
		return KV_NS_UDEV;
	else if (str[0] == KV_PREFIX_NS_DEVICE_C[0])
		return KV_NS_DEVICE;
	else if (str[0] == KV_PREFIX_NS_MODULE_C[0])
		return KV_NS_MODULE;
	else if (str[0] == KV_PREFIX_NS_GLOBAL_C[0])
		return KV_NS_GLOBAL;
	else
		return KV_NS_UNDEFINED;
}

static const char *_buffer_copy_ns_part_from_key(struct buffer *buf, const char *key)
{
	const char *str;
	size_t      len;

	/*                 |<----->|
	   <op>:<dom>:<ns>:<ns_part><id>:<id_part>[:<key>]
	*/

	if (!(str = _get_key_part(key, KEY_PART_NS_PART, &len)))
		return NULL;

	return sid_buffer_fmt_add(buf, NULL, "%.*s", len, str);
}

static struct iovec *_get_value_vector(kv_store_value_flags_t flags, void *value, size_t value_size, struct iovec *iov)
{
	size_t           owner_size;
	struct kv_value *kv_value;

	if (!value)
		return NULL;

	if (flags & KV_STORE_VALUE_VECTOR)
		return value;

	kv_value   = value;
	owner_size = strlen(kv_value->data) + 1;

	KV_VALUE_PREPARE_HEADER(iov, kv_value->seqnum, kv_value->flags, kv_value->data);
	iov[KV_VALUE_IDX_DATA] = (struct iovec) {kv_value->data + owner_size, value_size - sizeof(*kv_value) - owner_size};

	return iov;
}

static const char *_get_iov_str(struct buffer *buf, bool unset, struct iovec *iov, size_t iov_size)
{
	size_t      i;
	const char *str;

	if (unset)
		return sid_buffer_fmt_add(buf, NULL, "NULL");

	str = sid_buffer_add(buf, "", 0, NULL);

	for (i = KV_VALUE_IDX_DATA; i < iov_size; i++) {
		if (!sid_buffer_add(buf, iov[i].iov_base, iov[i].iov_len - 1, NULL) || !sid_buffer_add(buf, " ", 1, NULL))
			goto fail;
	}

	sid_buffer_add(buf, "\0", 1, NULL);

	return str;
fail:
	if (str)
		sid_buffer_rewind_mem(buf, str);
	return NULL;
}

static int _write_kv_store_stats(struct sid_stats *stats, sid_resource_t *kv_store_res)
{
	kv_store_iter_t *      iter;
	const char *           key;
	size_t                 size;
	kv_store_value_flags_t flags;
	void *                 value;
	size_t                 hash_size, int_size, int_data_size, ext_size, ext_data_size;

	memset(stats, 0, sizeof(*stats));
	if (!(iter = kv_store_iter_create(kv_store_res))) {
		log_error(ID(kv_store_res), INTERNAL_ERROR "%s: failed to create record iterator", __func__);
		return -ENOMEM;
	}
	while ((value = kv_store_iter_next(iter, &size, &flags))) {
		stats->nr_kv_pairs++;
		key = kv_store_iter_current_key(iter);
		kv_store_iter_current_size(iter, &int_size, &int_data_size, &ext_size, &ext_data_size);
		stats->key_size += strlen(key) + 1;
		stats->value_int_size += int_size;
		stats->value_int_data_size += int_data_size;
		stats->value_ext_size += ext_size;
		stats->value_ext_data_size += ext_data_size;
	}
	kv_store_get_size(kv_store_res, &hash_size, &int_size);
	if (stats->value_int_size != int_size)
		log_error(ID(kv_store_res),
		          INTERNAL_ERROR "%s: kv-store size mismatch: %" PRIu64 " is not equal to %zu",
		          __func__,
		          stats->value_int_size,
		          int_size);
	stats->meta_size = hash_size;
	kv_store_iter_destroy(iter);
	return 0;
}

static void _dump_kv_store(const char *str, sid_resource_t *kv_store_res)
{
	kv_store_iter_t *      iter;
	size_t                 size;
	kv_store_value_flags_t flags;
	void *                 value;
	struct iovec           tmp_iov[KV_VALUE_IDX_DATA + 1];
	struct iovec *         iov;
	unsigned int           i = 0, j;

	if (!(iter = kv_store_iter_create(kv_store_res))) {
		log_error(ID(kv_store_res), INTERNAL_ERROR "%s: failed to create record iterator", __func__);
		return;
	}

	log_print(ID(kv_store_res), "\n======= KV STORE DUMP BEGIN %s =======", str);
	while ((value = kv_store_iter_next(iter, &size, &flags))) {
		iov = _get_value_vector(flags, value, size, tmp_iov);
		if (!strncmp(kv_store_iter_current_key(iter), "U:", 2))
			continue;
		log_print(ID(kv_store_res), "  --- RECORD %u", i);
		log_print(ID(kv_store_res), "      key: %s", kv_store_iter_current_key(iter));
		log_print(ID(kv_store_res),
		          "      seqnum: %" PRIu64 "  flags: %s%s%s%s  owner: %s",
		          KV_VALUE_SEQNUM(iov),
		          KV_VALUE_FLAGS(iov) & KV_PERSISTENT ? "KV_PERSISTENT " : "",
		          KV_VALUE_FLAGS(iov) & KV_MOD_PROTECTED ? "KV_MOD_PROTECTED " : "",
		          KV_VALUE_FLAGS(iov) & KV_MOD_PRIVATE ? "KV_MOD_PRIVATE " : "",
		          KV_VALUE_FLAGS(iov) & KV_MOD_RESERVED ? "KV_MOD_RESERVED " : "",
		          KV_VALUE_OWNER(iov));
		log_print(ID(kv_store_res),
		          "      value: %s",
		          flags & KV_STORE_VALUE_VECTOR ? "vector" : (const char *) KV_VALUE_DATA(iov));
		if (flags & KV_STORE_VALUE_VECTOR) {
			for (j = KV_VALUE_IDX_DATA; j < size; j++)
				log_print(ID(kv_store_res),
				          "        [%u] = %s",
				          j - KV_VALUE_IDX_DATA,
				          (const char *) iov[j].iov_base);
		}
		log_print(ID(kv_store_res), " ");
		i++;
	}
	log_print(ID(kv_store_res), "======= KV STORE DUMP END %s =========\n", str);

	kv_store_iter_destroy(iter);
}

static void _dump_kv_store_dev_stack_in_dot(const char *str, sid_resource_t *kv_store_res)
{
	static const char ID[] = "DOT";
	kv_store_iter_t * iter;
	void *            value;
	size_t            value_size, elem_count, dom_len, this_dev_len, ref_dev_len;
	const char *      full_key, *key, *dom, *this_dev, *ref_dev;

	kv_store_value_flags_t flags;
	struct iovec           tmp_iov[KV_VALUE_IDX_DATA + 1];
	struct iovec *         iov;
	int                    i;

	if (!(iter = kv_store_iter_create(kv_store_res))) {
		log_error(ID(kv_store_res), INTERNAL_ERROR "%s: failed to create record iterator", __func__);
		goto out;
	}

	log_print(ID, "digraph stack {");

	while ((value = kv_store_iter_next(iter, &value_size, &flags))) {
		full_key = kv_store_iter_current_key(iter);

		/* we're intested in KV_NS_DEVICE records only */
		if (_get_ns_from_key(full_key) != KV_NS_DEVICE)
			continue;

		key = _get_key_part(full_key, KEY_PART_CORE, NULL);

		/*
		 * We need to print:
		 *
		 *   '"this dev"' once
		 *     (we're using KV_KEY_DEV_READY key for that as that is set only once for each dev)
		 *
		 *   '"this dev" -> "ref_dev"' for each ref dev
		 *     (that's the KV_KEY_GEN_GROUP_IN + KV_KEY_DOM_LAYER key)
		 *
		 */

		if (!strcmp(key, KV_KEY_DEV_READY)) {
			this_dev = _get_key_part(full_key, KEY_PART_NS_PART, &this_dev_len);
			log_print(ID, "\"%.*s\"", (int) this_dev_len, this_dev);
			continue;
		}

		if (strcmp(key, KV_KEY_GEN_GROUP_IN) || (!(dom = _get_key_part(full_key, KEY_PART_DOM, &dom_len))) || !dom_len ||
		    strncmp(dom, KV_KEY_DOM_LAYER, dom_len))
			continue;

		this_dev = _get_key_part(full_key, KEY_PART_NS_PART, &this_dev_len);
		iov      = _get_value_vector(flags, value, value_size, tmp_iov);

		if (flags & KV_STORE_VALUE_VECTOR)
			elem_count = value_size;
		else
			elem_count = KV_VALUE_IDX_DATA + 1;

		for (i = KV_VALUE_IDX_DATA; i < elem_count; i++) {
			ref_dev = _get_key_part((const char *) iov[i].iov_base, KEY_PART_NS_PART, &ref_dev_len);
			log_print(ID, "\"%.*s\" -> \"%.*s\"", (int) this_dev_len, this_dev, (int) ref_dev_len, ref_dev);
		}
	}

	log_print(ID, "}");
out:
	if (iter)
		kv_store_iter_destroy(iter);
}

static int _kv_overwrite(const char *full_key, struct kv_store_update_spec *spec, void *arg)
{
	struct kv_update_arg *update_arg = arg;
	struct iovec          tmp_iov_old[KV_VALUE_IDX_DATA + 1];
	struct iovec          tmp_iov_new[KV_VALUE_IDX_DATA + 1];
	struct iovec *        iov_old, *iov_new;
	const char *          reason;

	if (!spec->old_data)
		return 1;

	iov_old = _get_value_vector(spec->old_flags, spec->old_data, spec->old_data_size, tmp_iov_old);
	iov_new = _get_value_vector(spec->new_flags, spec->new_data, spec->new_data_size, tmp_iov_new);

	if (KV_VALUE_FLAGS(iov_old) & KV_MOD_PRIVATE) {
		if (strcmp(KV_VALUE_OWNER(iov_old), KV_VALUE_OWNER(iov_new))) {
			reason               = "private";
			update_arg->ret_code = -EACCES;
			goto keep_old;
		}
	} else if (KV_VALUE_FLAGS(iov_old) & KV_MOD_PROTECTED) {
		if (strcmp(KV_VALUE_OWNER(iov_old), KV_VALUE_OWNER(iov_new))) {
			reason               = "protected";
			update_arg->ret_code = -EPERM;
			goto keep_old;
		}
	} else if (KV_VALUE_FLAGS(iov_old) & KV_MOD_RESERVED) {
		if (strcmp(KV_VALUE_OWNER(iov_old), KV_VALUE_OWNER(iov_new))) {
			reason               = "reserved";
			update_arg->ret_code = -EBUSY;
			goto keep_old;
		}
	}

	update_arg->ret_code = 0;
	return 1;
keep_old:
	log_debug(ID(update_arg->res),
	          "Module %s can't overwrite value with key %s which is %s and attached to %s module.",
	          KV_VALUE_OWNER(iov_new),
	          full_key,
	          reason,
	          KV_VALUE_OWNER(iov_old));
	return 0;
}

static int _flags_indicate_mod_owned(sid_ucmd_kv_flags_t flags)
{
	return flags & (KV_MOD_PROTECTED | KV_MOD_PRIVATE | KV_MOD_RESERVED);
}

static const char *_get_mod_name(struct module *mod)
{
	return mod ? module_get_full_name(mod) : MOD_NAME_CORE;
}

static size_t _kv_value_ext_data_offset(struct kv_value *kv_value)
{
	return strlen(kv_value->data) + 1;
}

bool _is_string_data(char *ptr, size_t len)
{
	int i;

	if (ptr[len - 1] != '\0')
		return false;
	for (i = 0; i < len - 1; i++)
		if (!isprint(ptr[i]))
			return false;
	return true;
}

static void _print_kv_value(struct iovec *iov, size_t size, output_format_t format, struct buffer *buf, bool vector, int level)
{
	int i;

	if (vector) {
		print_start_array("values", format, buf, level);
		for (i = KV_VALUE_IDX_DATA; i < size; i++) {
			if (iov[i].iov_len) {
				if (_is_string_data(iov[i].iov_base, iov[i].iov_len))
					print_str_array_elem(iov[i].iov_base, format, buf, i + 1 < size, level + 1);
				else
					print_binary_array_elem(iov[i].iov_base,
					                        iov[i].iov_len,
					                        format,
					                        buf,
					                        i + 1 < size,
					                        level + 1);
			} else
				print_str_array_elem("", format, buf, i + 1 < size, level + 1);
		}
		print_end_array(false, format, buf, 3);
	} else if (iov[KV_VALUE_IDX_DATA].iov_len) {
		if (_is_string_data(iov[KV_VALUE_IDX_DATA].iov_base, iov[KV_VALUE_IDX_DATA].iov_len))
			print_str_field("value", iov[KV_VALUE_IDX_DATA].iov_base, format, buf, false, level);
		else
			print_binary_field("value",
			                   iov[KV_VALUE_IDX_DATA].iov_base,
			                   iov[KV_VALUE_IDX_DATA].iov_len,
			                   format,
			                   buf,
			                   false,
			                   level);
	} else
		print_str_field("value", "", format, buf, false, level);
}

static int _build_kv_buffer(sid_resource_t *cmd_res, bool export_udev, bool export_sid, output_format_t format)
{
	struct sid_ucmd_ctx *  ucmd_ctx = sid_resource_get_data(cmd_res);
	struct kv_value *      kv_value;
	kv_store_iter_t *      iter;
	const char *           key;
	void *                 value;
	bool                   vector;
	size_t                 size, iov_size, key_size, data_offset;
	kv_store_value_flags_t flags;
	struct iovec *         iov;
	unsigned               i, records = 0;
	int                    r           = -1;
	struct buffer *        export_buf  = NULL;
	bool                   needs_comma = false;
	struct iovec           tmp_iov[KV_VALUE_IDX_DATA + 1];

	/*
	 * For udev namespace, we append key=value pairs to the output buffer.
	 *
	 * For other namespaces, we serialize the key-value records to export
	 * buffer which is backed by BUFFER_BACKEND_MEMFD/BUFFER_TYPE_LINEAR
	 * so we can send the FD where we want to.
	 *
	 * We only add key=value pairs to buffers which are marked with
	 * KV_PERSISTENT flag.
	 */

	if (!(iter = kv_store_iter_create(ucmd_ctx->ucmd_mod_ctx.kv_store_res))) {
		// TODO: Discard udev kv-store we've already appended to the output buffer!
		log_error(ID(cmd_res), "Failed to create iterator for temp key-value store.");
		goto fail;
	}

	if (!(export_buf = sid_buffer_create(&((struct buffer_spec) {.backend = BUFFER_BACKEND_MEMFD,
	                                                             .type    = BUFFER_TYPE_LINEAR,
	                                                             .mode    = BUFFER_MODE_SIZE_PREFIX}),
	                                     &((struct buffer_init) {.size = 0, .alloc_step = PATH_MAX, .limit = 0}),
	                                     &r))) {
		log_error(ID(cmd_res), "Failed to create export buffer.");
		goto fail;
	}

	/*
	 * For exporting the raw kv-store, format is set to NO_FORMAT
	 */
	if (format != NO_FORMAT) {
		print_start_document(format, export_buf, 0);
		print_start_array("siddb", format, export_buf, 1);
	}

	while ((value = kv_store_iter_next(iter, &size, &flags))) {
		vector = flags & KV_STORE_VALUE_VECTOR;

		if (vector) {
			iov      = value;
			iov_size = size;
			kv_value = NULL;

			if (format == NO_FORMAT) {
				if (!(KV_VALUE_FLAGS(iov) & KV_PERSISTENT))
					continue;

				KV_VALUE_FLAGS(iov) &= ~KV_PERSISTENT;
			}
		} else {
			iov      = NULL;
			iov_size = 0;
			kv_value = value;

			if (format == NO_FORMAT) {
				if (!(kv_value->flags & KV_PERSISTENT))
					continue;

				kv_value->flags &= ~KV_PERSISTENT;
			}
		}

		key      = kv_store_iter_current_key(iter);
		key_size = strlen(key) + 1;

		// TODO: Also deal with situation if the udev namespace values are defined as vectors by chance.
		if (_get_ns_from_key(key) == KV_NS_UDEV) {
			if (!export_udev) {
				log_debug(ID(cmd_res), "Ignoring request to export record with key %s to udev.", key);
				continue;
			}

			if (vector) {
				log_error(ID(cmd_res),
				          INTERNAL_ERROR "%s: Unsupported vector value for key %s in udev namespace.",
				          __func__,
				          key);
				r = -ENOTSUP;
				goto fail;
			}
			if (format == NO_FORMAT) {
				key = _get_key_part(key, KEY_PART_CORE, NULL);
				if (!sid_buffer_add(ucmd_ctx->res_buf, (void *) key, strlen(key), &r) ||
				    !sid_buffer_add(ucmd_ctx->res_buf, KV_PAIR_C, 1, &r))
					goto fail;
				data_offset = _kv_value_ext_data_offset(kv_value);
				if (!sid_buffer_add(ucmd_ctx->res_buf,
				                    kv_value->data + data_offset,
				                    strlen(kv_value->data + data_offset),
				                    &r) ||
				    !sid_buffer_add(ucmd_ctx->res_buf, KV_END_C, 1, &r))
					goto fail;
				log_debug(ID(ucmd_ctx->ucmd_mod_ctx.kv_store_res),
				          "Exported udev property %s=%s",
				          key,
				          kv_value->data + data_offset);
				continue;
			}
		} else if (!export_sid) {
			log_debug(ID(cmd_res), "Ignoring request to export record with key %s to SID main KV store.", key);
			continue;
		}

		if (format == NO_FORMAT) {
			/*
			 * Export keys with data to main process.
			 *
			 * Serialization format fields (message size is implicitly set
			 * when using BUFFER_MODE_SIZE_PREFIX):
			 *
			 *  1) message size         (MSG_SIGE_PREFIX_TYPE)
			 *  2) flags                (uint32_t)
			 *  3) key size             (size_t)
			 *  4) data size            (size_t)
			 *  5) key                  (key_size)
			 *  6) data                 (data_size)
			 *
			 * If "data" is a vector, then "data size" denotes vector
			 * item count and "data" is split into these fields repeated
			 * for each vector item:
			 *
			 *  6a) vector item size
			 *  6b) vector item data
			 *
			 * Repeat 2) - 7) as long as there are keys to send.
			 */

			if (!sid_buffer_add(export_buf, &flags, sizeof(flags), &r) ||
			    !sid_buffer_add(export_buf, &key_size, sizeof(key_size), &r) ||
			    !sid_buffer_add(export_buf, &size, sizeof(size), &r) ||
			    !sid_buffer_add(export_buf, (char *) key, strlen(key) + 1, &r)) {
				log_error_errno(ID(cmd_res), errno, "sid_buffer_add failed");
				goto fail;
			}

			if (vector) {
				for (i = 0, size = 0; i < iov_size; i++) {
					size += iov[i].iov_len;

					if (!sid_buffer_add(export_buf, &iov[i].iov_len, sizeof(iov->iov_len), &r) ||
					    !sid_buffer_add(export_buf, iov[i].iov_base, iov[i].iov_len, &r)) {
						log_error_errno(ID(cmd_res), errno, "sid_buffer_add failed");
						goto fail;
					}
				}
			} else if (!sid_buffer_add(export_buf, kv_value, size, &r)) {
				log_error_errno(ID(cmd_res), errno, "sid_buffer_add failed");
				goto fail;
			}
		} else {
			print_start_elem(needs_comma, format, export_buf, 2);
			print_uint_field("RECORD", records, format, export_buf, true, 3);
			print_str_field("key", key, format, export_buf, true, 3);
			iov = _get_value_vector(flags, value, size, tmp_iov);
			print_uint64_field("seqnum", KV_VALUE_SEQNUM(iov), format, export_buf, true, 3);
			print_start_array("flags", format, export_buf, 3);
			print_bool_array_elem("KV_PERSISTENT", KV_VALUE_FLAGS(iov) & KV_PERSISTENT, format, export_buf, true, 4);
			print_bool_array_elem("KV_MOD_PROTECTED",
			                      KV_VALUE_FLAGS(iov) & KV_MOD_PROTECTED,
			                      format,
			                      export_buf,
			                      true,
			                      4);
			print_bool_array_elem("KV_MOD_PRIVATE", KV_VALUE_FLAGS(iov) & KV_MOD_PRIVATE, format, export_buf, true, 4);
			print_bool_array_elem("KV_MOD_RESERVED",
			                      KV_VALUE_FLAGS(iov) & KV_MOD_RESERVED,
			                      format,
			                      export_buf,
			                      false,
			                      4);
			print_end_array(true, format, export_buf, 3);
			print_str_field("owner", KV_VALUE_OWNER(iov), format, export_buf, true, 3);
			_print_kv_value(iov, size, format, export_buf, vector, 3);
			print_end_elem(format, export_buf, 2);
			needs_comma = true;
		}
		records++;
	}

	if (format != NO_FORMAT) {
		print_end_array(false, format, export_buf, 1);
		print_end_document(format, export_buf, 0);
		print_null_byte(export_buf);
	}
	ucmd_ctx->exp_buf = export_buf;
	kv_store_iter_destroy(iter);
	return 0;

fail:
	if (iter)
		kv_store_iter_destroy(iter);
	if (export_buf)
		sid_buffer_destroy(export_buf);

	return r;
}

static int _passes_global_reservation_check(struct sid_ucmd_ctx *   ucmd_ctx,
                                            const char *            owner,
                                            sid_ucmd_kv_namespace_t ns,
                                            const char *            key)
{
	struct iovec           tmp_iov[KV_VALUE_IDX_DATA + 1];
	struct iovec *         iov;
	const char *           full_key = NULL;
	void *                 found;
	size_t                 value_size;
	kv_store_value_flags_t value_flags;
	struct kv_key_spec     key_spec =
		{.op = KV_OP_SET, .dom = ID_NULL, .ns = ns, .ns_part = ID_NULL, .id = ID_NULL, .id_part = ID_NULL, .key = key};
	int r = 1;

	if ((ns != KV_NS_UDEV) && (ns != KV_NS_DEVICE))
		goto out;

	if (!(full_key = _buffer_compose_key(ucmd_ctx->ucmd_mod_ctx.gen_buf, &key_spec))) {
		r = -ENOMEM;
		goto out;
	}

	if (!(found = kv_store_get_value(ucmd_ctx->ucmd_mod_ctx.kv_store_res, full_key, &value_size, &value_flags)))
		goto out;

	iov = _get_value_vector(value_flags, found, value_size, tmp_iov);

	if ((KV_VALUE_FLAGS(iov) & KV_MOD_RESERVED) && (!strcmp(KV_VALUE_OWNER(iov), owner)))
		goto out;

	log_debug(ID(ucmd_ctx->ucmd_mod_ctx.kv_store_res),
	          "Module %s can't overwrite value with key %s which is reserved and attached to %s module.",
	          owner,
	          full_key,
	          KV_VALUE_OWNER(iov));

	r = 0;
out:
	if (full_key)
		sid_buffer_rewind_mem(ucmd_ctx->ucmd_mod_ctx.gen_buf, full_key);
	return r;
}

static const char *_get_ns_part(struct module *mod, struct sid_ucmd_ctx *ucmd_ctx, sid_ucmd_kv_namespace_t ns)
{
	switch (ns) {
		case KV_NS_UDEV:
		case KV_NS_DEVICE:
			return ucmd_ctx->dev_id;
		case KV_NS_MODULE:
			return _get_mod_name(mod);
		case KV_NS_GLOBAL:
		case KV_NS_UNDEFINED:
			break;
	}

	return ID_NULL;
}

static void _destroy_delta(struct kv_delta *delta)
{
	if (delta->plus) {
		sid_buffer_destroy(delta->plus);
		delta->plus = NULL;
	}

	if (delta->minus) {
		sid_buffer_destroy(delta->minus);
		delta->minus = NULL;
	}

	if (delta->final) {
		sid_buffer_destroy(delta->final);
		delta->final = NULL;
	}
}

static void _destroy_unused_delta(struct kv_delta *delta)
{
	if (delta->plus) {
		if (sid_buffer_stat(delta->plus).usage.used <= KV_VALUE_IDX_DATA) {
			sid_buffer_destroy(delta->plus);
			delta->plus = NULL;
		}
	}

	if (delta->minus) {
		if (sid_buffer_stat(delta->minus).usage.used <= KV_VALUE_IDX_DATA) {
			sid_buffer_destroy(delta->minus);
			delta->minus = NULL;
		}
	}
}

static void *_do_sid_ucmd_set_kv(struct module *         mod,
                                 struct sid_ucmd_ctx *   ucmd_ctx,
                                 const char *            dom,
                                 sid_ucmd_kv_namespace_t ns,
                                 const char *            key,
                                 sid_ucmd_kv_flags_t     flags,
                                 const void *            value,
                                 size_t                  value_size)
{
	const char *         owner    = _get_mod_name(mod);
	const char *         full_key = NULL;
	struct iovec         iov[KV_VALUE_IDX_DATA + 1];
	struct kv_value *    kv_value;
	struct kv_update_arg update_arg;
	struct kv_key_spec   key_spec = {.op      = KV_OP_SET,
                                       .dom     = dom ?: ID_NULL,
                                       .ns      = ns,
                                       .ns_part = _get_ns_part(mod, ucmd_ctx, ns),
                                       .id      = ID_NULL,
                                       .id_part = ID_NULL,
                                       .key     = key};
	int                  r;
	void *               ret = NULL;

	/*
	 * First, we check if the KV is not reserved globally. This applies to reservations
	 * where the namespace stores records with finer granularity than module scope.
	 * This is the case of KV_NS_UDEV and KV_NS_DEVICE where the granularity is per-device
	 * and the global reservation applies to all devices, hence the global reservation
	 * record has 0:0 used instead of real major:minor.
	 *
	 * Also, check global reservation in KV_NS_UDEV only if KV is being set from a module.
	 * If we're not in a module, we're importing values from udev environment where
	 * we can't control any global reservation at the moment so it doesn't make sense
	 * to do the check here.
	 */
	if (!((ns == KV_NS_UDEV) && !strcmp(owner, OWNER_CORE))) {
		r = _passes_global_reservation_check(ucmd_ctx, owner, ns, key);
		if (r <= 0)
			goto out;
	}

	if (!(full_key = _buffer_compose_key(ucmd_ctx->ucmd_mod_ctx.gen_buf, &key_spec)))
		goto out;

	KV_VALUE_PREPARE_HEADER(iov, ucmd_ctx->udev_dev.seqnum, flags, (char *) owner);
	iov[KV_VALUE_IDX_DATA] = (struct iovec) {(void *) value, value ? value_size : 0};

	update_arg = (struct kv_update_arg) {.res      = ucmd_ctx->ucmd_mod_ctx.kv_store_res,
	                                     .owner    = owner,
	                                     .gen_buf  = ucmd_ctx->ucmd_mod_ctx.gen_buf,
	                                     .custom   = NULL,
	                                     .ret_code = -EREMOTEIO};

	if (!(kv_value = kv_store_set_value(ucmd_ctx->ucmd_mod_ctx.kv_store_res,
	                                    full_key,
	                                    iov,
	                                    KV_VALUE_IDX_DATA + 1,
	                                    KV_STORE_VALUE_VECTOR,
	                                    KV_STORE_VALUE_OP_MERGE,
	                                    _kv_overwrite,
	                                    &update_arg)) ||
	    !value_size)
		goto out;

	ret = kv_value->data + _kv_value_ext_data_offset(kv_value);
out:
	if (full_key)
		sid_buffer_rewind_mem(ucmd_ctx->ucmd_mod_ctx.gen_buf, full_key);
	return ret;
}

void *sid_ucmd_set_kv(struct module *         mod,
                      struct sid_ucmd_ctx *   ucmd_ctx,
                      sid_ucmd_kv_namespace_t ns,
                      const char *            key,
                      const void *            value,
                      size_t                  value_size,
                      sid_ucmd_kv_flags_t     flags)
{
	if (!mod || !ucmd_ctx || (ns == KV_NS_UNDEFINED) || !key || !*key || (key[0] == KEY_SYS_C[0]))
		return NULL;

	if (ns == KV_NS_UDEV)
		flags |= KV_PERSISTENT;

	return _do_sid_ucmd_set_kv(mod, ucmd_ctx, KV_KEY_DOM_USER, ns, key, flags, value, value_size);
}

static const void *_cmd_get_key_spec_value(struct module *      mod,
                                           struct sid_ucmd_ctx *ucmd_ctx,
                                           struct kv_key_spec * key_spec,
                                           size_t *             value_size,
                                           sid_ucmd_kv_flags_t *flags)
{
	const char *     owner    = _get_mod_name(mod);
	const char *     full_key = NULL;
	struct kv_value *kv_value;
	size_t           size, data_offset;
	void *           ret = NULL;

	if (!(full_key = _buffer_compose_key(ucmd_ctx->ucmd_mod_ctx.gen_buf, key_spec)))
		goto out;

	if (!(kv_value = kv_store_get_value(ucmd_ctx->ucmd_mod_ctx.kv_store_res, full_key, &size, NULL)))
		goto out;

	if (kv_value->flags & KV_MOD_PRIVATE) {
		if (strcmp(kv_value->data, owner))
			goto out;
	}

	if (flags)
		*flags = kv_value->flags;

	data_offset = _kv_value_ext_data_offset(kv_value);
	size -= (sizeof(*kv_value) + data_offset);

	if (value_size)
		*value_size = size;

	if (size)
		ret = kv_value->data + data_offset;
out:
	if (full_key)
		sid_buffer_rewind_mem(ucmd_ctx->ucmd_mod_ctx.gen_buf, full_key);
	return ret;
}

static const void *_do_sid_ucmd_get_kv(struct module *         mod,
                                       struct sid_ucmd_ctx *   ucmd_ctx,
                                       const char *            dom,
                                       sid_ucmd_kv_namespace_t ns,
                                       const char *            key,
                                       size_t *                value_size,
                                       sid_ucmd_kv_flags_t *   flags)
{
	struct kv_key_spec key_spec = {.op      = KV_OP_SET,
	                               .dom     = dom ?: ID_NULL,
	                               .ns      = ns,
	                               .ns_part = _get_ns_part(mod, ucmd_ctx, ns),
	                               .id      = ID_NULL,
	                               .id_part = ID_NULL,
	                               .key     = key};
	return _cmd_get_key_spec_value(mod, ucmd_ctx, &key_spec, value_size, flags);
}

const void *sid_ucmd_get_kv(struct module *         mod,
                            struct sid_ucmd_ctx *   ucmd_ctx,
                            sid_ucmd_kv_namespace_t ns,
                            const char *            key,
                            size_t *                value_size,
                            sid_ucmd_kv_flags_t *   flags)
{
	if (!mod || !ucmd_ctx || (ns == KV_NS_UNDEFINED) || !key || !*key || (key[0] == KEY_SYS_C[0]))
		return NULL;

	return _do_sid_ucmd_get_kv(mod, ucmd_ctx, KV_KEY_DOM_USER, ns, key, value_size, flags);
}

static int _kv_reserve(const char *full_key, struct kv_store_update_spec *spec, void *arg)
{
	struct kv_update_arg *update_arg = arg;
	struct iovec          tmp_iov_old[KV_VALUE_IDX_DATA + 1];
	struct iovec          tmp_iov_new[KV_VALUE_IDX_DATA + 1];
	struct iovec *        iov_old, *iov_new;

	if (!spec->old_data)
		return 1;

	iov_old = _get_value_vector(spec->old_flags, spec->old_data, spec->old_data_size, tmp_iov_old);
	iov_new = _get_value_vector(spec->new_flags, spec->new_data, spec->new_data_size, tmp_iov_new);

	if (strcmp(KV_VALUE_OWNER(iov_old), KV_VALUE_OWNER(iov_new))) {
		log_debug(ID(update_arg->res),
		          "Module %s can't reserve key %s which is already reserved by %s module.",
		          KV_VALUE_OWNER(iov_new),
		          full_key,
		          KV_VALUE_OWNER(iov_old));
		update_arg->ret_code = -EBUSY;
		return 0;
	}

	return 1;
}

static int _kv_unreserve(const char *full_key, struct kv_store_update_spec *spec, void *arg)
{
	struct kv_update_arg *update_arg = arg;
	struct iovec          tmp_iov_old[KV_VALUE_IDX_DATA + 1];
	struct iovec *        iov_old;

	if (!spec->old_data)
		return 1;

	iov_old = _get_value_vector(spec->old_flags, spec->old_data, spec->old_data_size, tmp_iov_old);

	if (strcmp(KV_VALUE_OWNER(iov_old), update_arg->owner)) {
		log_debug(ID(update_arg->res),
		          "Module %s can't unreserve key %s which is reserved by %s module.",
		          update_arg->owner,
		          full_key,
		          KV_VALUE_OWNER(iov_old));
		update_arg->ret_code = -EBUSY;
		return 0;
	}

	return 1;
}

int _do_sid_ucmd_mod_reserve_kv(struct module *          mod,
                                struct sid_ucmd_mod_ctx *ucmd_mod_ctx,
                                sid_ucmd_kv_namespace_t  ns,
                                const char *             key,
                                int                      unset)
{
	const char *         owner    = _get_mod_name(mod);
	const char *         full_key = NULL;
	struct iovec         iov[KV_VALUE_IDX_DATA]; /* without KV_VALUE_IDX_DATA */
	static uint64_t      null_int = 0;
	sid_ucmd_kv_flags_t  flags    = unset ? KV_FLAGS_UNSET : KV_MOD_RESERVED;
	struct kv_update_arg update_arg;
	int                  is_worker;
	struct kv_key_spec   key_spec =
		{.op = KV_OP_SET, .dom = ID_NULL, .ns = ns, .ns_part = ID_NULL, .id = ID_NULL, .id_part = ID_NULL, .key = key};
	int r = -1;

	if (!(full_key = _buffer_compose_key(ucmd_mod_ctx->gen_buf, &key_spec)))
		goto out;

	if (!(ucmd_mod_ctx->kv_store_res))
		goto out;

	update_arg = (struct kv_update_arg) {.res      = ucmd_mod_ctx->kv_store_res,
	                                     .gen_buf  = NULL,
	                                     .owner    = owner,
	                                     .custom   = NULL,
	                                     .ret_code = -EREMOTEIO};

	is_worker = worker_control_is_worker(ucmd_mod_ctx->kv_store_res);

	if (is_worker)
		flags |= KV_PERSISTENT;

	if (unset && !is_worker) {
		kv_store_unset_value(ucmd_mod_ctx->kv_store_res, full_key, _kv_unreserve, &update_arg);
		goto out;
	} else {
		KV_VALUE_PREPARE_HEADER(iov, null_int, flags, (char *) owner);
		if (!kv_store_set_value(ucmd_mod_ctx->kv_store_res,
		                        full_key,
		                        iov,
		                        KV_VALUE_IDX_DATA,
		                        KV_STORE_VALUE_VECTOR,
		                        KV_STORE_VALUE_OP_MERGE,
		                        _kv_reserve,
		                        &update_arg))
			goto out;
	}

	r = 0;
out:
	if (full_key)
		sid_buffer_rewind_mem(ucmd_mod_ctx->gen_buf, full_key);
	return r;
}

int sid_ucmd_mod_reserve_kv(struct module *mod, struct sid_ucmd_mod_ctx *ucmd_mod_ctx, sid_ucmd_kv_namespace_t ns, const char *key)
{
	if (!mod || !ucmd_mod_ctx || !key || !*key || (key[0] == KEY_SYS_C[0]))
		return -EINVAL;

	return _do_sid_ucmd_mod_reserve_kv(mod, ucmd_mod_ctx, ns, key, 0);
}

int sid_ucmd_mod_unreserve_kv(struct module *          mod,
                              struct sid_ucmd_mod_ctx *ucmd_mod_ctx,
                              sid_ucmd_kv_namespace_t  ns,
                              const char *             key)
{
	if (!mod || !ucmd_mod_ctx || !key || !*key || (key[0] == KEY_SYS_C[0]))
		return -EINVAL;

	return _do_sid_ucmd_mod_reserve_kv(mod, ucmd_mod_ctx, ns, key, 1);
}

int sid_ucmd_mod_add_mod_subregistry(struct module *mod, struct sid_ucmd_mod_ctx *ucmd_mod_ctx, sid_resource_t *mod_subregistry)
{
	sid_resource_t *res;
	char **         pathv, **name;

	if (!mod || !ucmd_mod_ctx || !mod_subregistry)
		return -EINVAL;

	if (!(pathv = util_str_comb_to_strv(NULL, NULL, module_get_full_name(mod), NULL, MODULE_NAME_DELIM, NULL)))
		return -ENOMEM;

	for (res = ucmd_mod_ctx->modules_res, name = pathv; *name; name++) {
		if (!(res = sid_resource_search(res, SID_RESOURCE_SEARCH_IMM_DESC, NULL, *name))) {
			free(pathv);
			return -ENOLINK;
		}
	}

	free(pathv);
	return module_registry_add_module_subregistry(res, mod_subregistry);
}

int sid_ucmd_dev_set_ready(struct module *mod, struct sid_ucmd_ctx *ucmd_ctx, dev_ready_t ready)
{
	if (!mod || !ucmd_ctx || (ready == DEV_NOT_RDY_UNDEFINED))
		return -EINVAL;

	if (!(_cmd_scan_phase_regs[ucmd_ctx->scan_phase].flags & CMD_SCAN_CAP_RDY))
		return -EPERM;

	if (ready == DEV_NOT_RDY_UNPROCESSED)
		return -EINVAL;

	_do_sid_ucmd_set_kv(NULL, ucmd_ctx, NULL, KV_NS_DEVICE, KV_KEY_DEV_READY, DEFAULT_KV_FLAGS_CORE, &ready, sizeof(ready));

	return 0;
}

dev_ready_t sid_ucmd_dev_get_ready(struct module *mod, struct sid_ucmd_ctx *ucmd_ctx)
{
	const dev_ready_t *p_ready;
	dev_ready_t        result;

	if (!mod || !ucmd_ctx)
		return DEV_NOT_RDY_UNDEFINED;

	if (!(p_ready = _do_sid_ucmd_get_kv(NULL, ucmd_ctx, NULL, KV_NS_DEVICE, KV_KEY_DEV_READY, NULL, NULL)))
		result = DEV_NOT_RDY_UNPROCESSED;
	else
		result = *p_ready;

	return result;
}

int sid_ucmd_dev_set_reserved(struct module *mod, struct sid_ucmd_ctx *ucmd_ctx, dev_reserved_t reserved)
{
	if (!mod || !ucmd_ctx || (reserved == DEV_RES_UNDEFINED))
		return -EINVAL;

	if (!(_cmd_scan_phase_regs[ucmd_ctx->scan_phase].flags & CMD_SCAN_CAP_RES))
		return -EPERM;

	_do_sid_ucmd_set_kv(NULL,
	                    ucmd_ctx,
	                    NULL,
	                    KV_NS_DEVICE,
	                    KV_KEY_DEV_RESERVED,
	                    DEFAULT_KV_FLAGS_CORE,
	                    &reserved,
	                    sizeof(reserved));

	return 0;
}

dev_reserved_t sid_ucmd_dev_get_reserved(struct module *mod, struct sid_ucmd_ctx *ucmd_ctx)
{
	const dev_reserved_t *p_reserved;
	dev_reserved_t        result;

	if (!mod || !ucmd_ctx)
		return DEV_RES_UNDEFINED;

	if (!(p_reserved = _do_sid_ucmd_get_kv(NULL, ucmd_ctx, NULL, KV_NS_DEVICE, KV_KEY_DEV_RESERVED, NULL, NULL)))
		result = DEV_RES_UNPROCESSED;
	else
		result = *p_reserved;

	return result;
}

static int _kv_write_new_only(const char *full_key, struct kv_store_update_spec *spec, void *arg)
{
	if (spec->old_data)
		return 0;

	return 1;
}

int sid_ucmd_group_create(struct module *         mod,
                          struct sid_ucmd_ctx *   ucmd_ctx,
                          sid_ucmd_kv_namespace_t group_ns,
                          const char *            group_id,
                          sid_ucmd_kv_flags_t     group_flags)
{
	const char * full_key = NULL;
	struct iovec iov[KV_VALUE_IDX_DATA];
	int          r = -1;

	if (!mod || !ucmd_ctx || (group_ns == KV_NS_UNDEFINED) || !group_id || !*group_id)
		return -EINVAL;

	struct kv_key_spec key_spec = {.op      = KV_OP_SET,
	                               .dom     = ID_NULL,
	                               .ns      = group_ns,
	                               .ns_part = _get_ns_part(mod, ucmd_ctx, group_ns),
	                               .id      = group_id,
	                               .id_part = ID_NULL,
	                               .key     = KV_KEY_GEN_GROUP_MEMBERS};

	struct kv_update_arg update_arg = {.res      = ucmd_ctx->ucmd_mod_ctx.kv_store_res,
	                                   .owner    = _get_mod_name(mod),
	                                   .gen_buf  = ucmd_ctx->ucmd_mod_ctx.gen_buf,
	                                   .custom   = NULL,
	                                   .ret_code = 0};

	if (!(full_key = _buffer_compose_key(ucmd_ctx->ucmd_mod_ctx.gen_buf, &key_spec)))
		goto out;
	KV_VALUE_PREPARE_HEADER(iov, ucmd_ctx->udev_dev.seqnum, kv_flags_persist, core_owner);

	if (!kv_store_set_value(ucmd_ctx->ucmd_mod_ctx.kv_store_res,
	                        full_key,
	                        iov,
	                        KV_VALUE_IDX_DATA,
	                        KV_STORE_VALUE_VECTOR,
	                        KV_STORE_VALUE_NO_OP,
	                        _kv_write_new_only,
	                        &update_arg))
		goto out;

	r = 0;
out:
	if (full_key)
		sid_buffer_rewind_mem(ucmd_ctx->ucmd_mod_ctx.gen_buf, full_key);
	return r;
}

int _handle_current_dev_for_group(struct module *         mod,
                                  struct sid_ucmd_ctx *   ucmd_ctx,
                                  sid_ucmd_kv_namespace_t group_ns,
                                  const char *            group_id,
                                  kv_op_t                 op)
{
	const char * tmp_mem_start = sid_buffer_add(ucmd_ctx->ucmd_mod_ctx.gen_buf, "", 0, NULL);
	const char * cur_full_key, *rel_key_prefix;
	struct iovec iov[KV_VALUE_IDX_DATA + 1];
	int          r = -1;

	struct kv_rel_spec rel_spec = {.delta = &((struct kv_delta) {.op    = op,
	                                                             .flags = DELTA_WITH_DIFF | DELTA_WITH_REL,
	                                                             .plus  = NULL,
	                                                             .minus = NULL,
	                                                             .final = NULL}),

	                               .cur_key_spec = &((struct kv_key_spec) {.op      = KV_OP_SET,
	                                                                       .dom     = KV_KEY_DOM_USER,
	                                                                       .ns      = group_ns,
	                                                                       .ns_part = _get_ns_part(mod, ucmd_ctx, group_ns),
	                                                                       .id      = group_id,
	                                                                       .id_part = ID_NULL,
	                                                                       .key     = KV_KEY_GEN_GROUP_MEMBERS}),

	                               .rel_key_spec = &((struct kv_key_spec) {.op      = KV_OP_SET,
	                                                                       .dom     = ID_NULL,
	                                                                       .ns      = KV_NS_DEVICE,
	                                                                       .ns_part = _get_ns_part(mod, ucmd_ctx, KV_NS_DEVICE),
	                                                                       .id      = ID_NULL,
	                                                                       .id_part = ID_NULL,
	                                                                       .key     = KV_KEY_GEN_GROUP_IN})};

	struct kv_update_arg update_arg = {.res     = ucmd_ctx->ucmd_mod_ctx.kv_store_res,
	                                   .owner   = OWNER_CORE,
	                                   .gen_buf = ucmd_ctx->ucmd_mod_ctx.gen_buf,
	                                   .custom  = &rel_spec};

	// TODO: check return values / maybe also pass flags / use proper owner

	KV_VALUE_PREPARE_HEADER(iov, ucmd_ctx->udev_dev.seqnum, kv_flags_no_persist, core_owner);
	rel_key_prefix = _buffer_compose_key_prefix(ucmd_ctx->ucmd_mod_ctx.gen_buf, rel_spec.rel_key_spec);
	if (!rel_key_prefix)
		goto out;
	iov[KV_VALUE_IDX_DATA] = (struct iovec) {(void *) rel_key_prefix, strlen(rel_key_prefix) + 1};

	cur_full_key = _buffer_compose_key(ucmd_ctx->ucmd_mod_ctx.gen_buf, rel_spec.cur_key_spec);
	if (!cur_full_key)
		goto out;
	if (kv_store_set_value(ucmd_ctx->ucmd_mod_ctx.kv_store_res,
	                       cur_full_key,
	                       iov,
	                       KV_VALUE_IDX_DATA + 1,
	                       KV_STORE_VALUE_VECTOR | KV_STORE_VALUE_REF,
	                       KV_STORE_VALUE_NO_OP,
	                       _kv_delta,
	                       &update_arg))
		r = 0;

	_destroy_delta(rel_spec.delta);
out:
	sid_buffer_rewind_mem(ucmd_ctx->ucmd_mod_ctx.gen_buf, tmp_mem_start);
	return r;
}

int sid_ucmd_group_add_current_dev(struct module *         mod,
                                   struct sid_ucmd_ctx *   ucmd_ctx,
                                   sid_ucmd_kv_namespace_t group_ns,
                                   const char *            group_id)
{
	if (!mod || !ucmd_ctx || (group_ns == KV_NS_UNDEFINED) || !group_id || !*group_id)
		return -EINVAL;

	return _handle_current_dev_for_group(mod, ucmd_ctx, group_ns, group_id, KV_OP_PLUS);
}

int sid_ucmd_group_remove_current_dev(struct module *         mod,
                                      struct sid_ucmd_ctx *   ucmd_ctx,
                                      sid_ucmd_kv_namespace_t group_ns,
                                      const char *            group_id)
{
	if (!mod || !ucmd_ctx || (group_ns == KV_NS_UNDEFINED) || !group_id || !*group_id)
		return -EINVAL;

	return _handle_current_dev_for_group(mod, ucmd_ctx, group_ns, group_id, KV_OP_MINUS);
}

int sid_ucmd_group_destroy(struct module *         mod,
                           struct sid_ucmd_ctx *   ucmd_ctx,
                           sid_ucmd_kv_namespace_t group_ns,
                           const char *            group_id,
                           int                     force)
{
	static sid_ucmd_kv_flags_t kv_flags_persist_no_reserved = (DEFAULT_KV_FLAGS_CORE) & ~KV_MOD_RESERVED;
	const char *               cur_full_key                 = NULL;
	size_t                     size;
	struct iovec               iov_blank[KV_VALUE_IDX_DATA];
	int                        r = -1;

	if (!mod || !ucmd_ctx || (group_ns == KV_NS_UNDEFINED) || !group_id || !*group_id)
		return -EINVAL;

	struct kv_rel_spec rel_spec = {.delta = &((struct kv_delta) {.op    = KV_OP_SET,
	                                                             .flags = DELTA_WITH_DIFF | DELTA_WITH_REL,
	                                                             .plus  = NULL,
	                                                             .minus = NULL,
	                                                             .final = NULL}),

	                               .cur_key_spec = &((struct kv_key_spec) {.op      = KV_OP_SET,
	                                                                       .dom     = ID_NULL,
	                                                                       .ns      = group_ns,
	                                                                       .ns_part = _get_ns_part(mod, ucmd_ctx, group_ns),
	                                                                       .id      = group_id,
	                                                                       .id_part = ID_NULL,
	                                                                       .key     = KV_KEY_GEN_GROUP_MEMBERS}),

	                               .rel_key_spec = &((struct kv_key_spec) {.op      = KV_OP_SET,
	                                                                       .dom     = ID_NULL,
	                                                                       .ns      = 0,
	                                                                       .ns_part = ID_NULL,
	                                                                       .id      = ID_NULL,
	                                                                       .id_part = ID_NULL,
	                                                                       .key     = KV_KEY_GEN_GROUP_IN})};

	struct kv_update_arg update_arg = {.res     = ucmd_ctx->ucmd_mod_ctx.kv_store_res,
	                                   .owner   = OWNER_CORE,
	                                   .gen_buf = ucmd_ctx->ucmd_mod_ctx.gen_buf,
	                                   .custom  = &rel_spec};

	// TODO: do not call kv_store_get_value, only kv_store_set_value and provide _kv_delta wrapper
	//       to do the "is empty?" check before the actual _kv_delta operation

	if (!(cur_full_key = _buffer_compose_key(ucmd_ctx->ucmd_mod_ctx.gen_buf, rel_spec.cur_key_spec)))
		goto out;

	if (!kv_store_get_value(ucmd_ctx->ucmd_mod_ctx.kv_store_res, cur_full_key, &size, NULL))
		goto out;

	if (size > KV_VALUE_IDX_DATA && !force) {
		r = -ENOTEMPTY;
		goto out;
	}

	KV_VALUE_PREPARE_HEADER(iov_blank, ucmd_ctx->udev_dev.seqnum, kv_flags_persist_no_reserved, core_owner);

	if (!kv_store_set_value(ucmd_ctx->ucmd_mod_ctx.kv_store_res,
	                        cur_full_key,
	                        iov_blank,
	                        KV_VALUE_IDX_DATA,
	                        KV_STORE_VALUE_VECTOR | KV_STORE_VALUE_REF,
	                        KV_STORE_VALUE_NO_OP,
	                        _kv_delta,
	                        &update_arg)) {
		r = update_arg.ret_code;
		goto out;
	}

	r = 0;
out:
	_destroy_delta(rel_spec.delta);
	if (cur_full_key)
		sid_buffer_rewind_mem(ucmd_ctx->ucmd_mod_ctx.gen_buf, cur_full_key);
	return r;
}

static int _device_add_field(struct sid_ucmd_ctx *ucmd_ctx, const char *start)
{
	const char *key;
	const char *value;
	int         r = -1;

	if (!(value = strchr(start, KV_PAIR_C[0])) || !*(++value))
		return -1;

	if (!(key = sid_buffer_fmt_add(ucmd_ctx->ucmd_mod_ctx.gen_buf, &r, "%.*s", value - start - 1, start)))
		return r;

	if (!(value = _do_sid_ucmd_set_kv(NULL, ucmd_ctx, NULL, KV_NS_UDEV, key, 0, value, strlen(value) + 1)))
		goto out;

	log_debug(ID(ucmd_ctx->ucmd_mod_ctx.kv_store_res), "Imported udev property %s=%s", key, value);

	/* Common key=value pairs are also directly in the ucmd_ctx->udev_dev structure. */
	if (!strcmp(key, UDEV_KEY_ACTION))
		ucmd_ctx->udev_dev.action = util_udev_str_to_udev_action(value);
	else if (!strcmp(key, UDEV_KEY_DEVPATH)) {
		ucmd_ctx->udev_dev.path = value;
		ucmd_ctx->udev_dev.name = util_str_rstr(value, "/");
		ucmd_ctx->udev_dev.name++;
	} else if (!strcmp(key, UDEV_KEY_DEVTYPE))
		ucmd_ctx->udev_dev.type = util_udev_str_to_udev_devtype(value);
	else if (!strcmp(key, UDEV_KEY_SEQNUM))
		ucmd_ctx->udev_dev.seqnum = strtoull(value, NULL, 10);
	else if (!strcmp(key, UDEV_KEY_SYNTH_UUID))
		ucmd_ctx->udev_dev.synth_uuid = value;

	r = 0;
out:
	sid_buffer_rewind_mem(ucmd_ctx->ucmd_mod_ctx.gen_buf, key);
	return r;
};

static int _parse_cmd_nullstr_udev_env(struct sid_ucmd_ctx *ucmd_ctx, const char *env, size_t env_size)
{
	dev_t       devno;
	const char *end;
	int         r = 0;

	if (env_size <= sizeof(devno)) {
		r = -EINVAL;
		goto out;
	}

	memcpy(&devno, env, sizeof(devno));
	ucmd_ctx->udev_dev.major = major(devno);
	ucmd_ctx->udev_dev.minor = minor(devno);

	if (asprintf(&ucmd_ctx->dev_id, "%d_%d", ucmd_ctx->udev_dev.major, ucmd_ctx->udev_dev.minor) < 0) {
		r = -ENOMEM;
		goto out;
	}

	/*
	 * We have this on input ('devno' prefix is already processed so skip it):
	 *
	 *   devnokey1=value1\0key2=value2\0...
	 */
	for (end = env + env_size, env += sizeof(devno); env < end; env += strlen(env) + 1) {
		if ((r = _device_add_field(ucmd_ctx, env) < 0))
			goto out;
	}
out:
	return r;
}

static void _canonicalize_module_name(char *name)
{
	char *p = name;

	while (*p) {
		if (*p == '-')
			*p = '_';
		p++;
	}
}

static void _canonicalize_kv_key(char *id)
{
	char *p = id;

	while (*p) {
		if (*p == ':')
			*p = '_';
		p++;
	}
}

/*
 *  Module name is equal to the name as exposed in SYSTEM_PROC_DEVICES_PATH.
 */
static const char *_lookup_module_name(sid_resource_t *cmd_res)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_resource_get_data(cmd_res);
	char                 buf[PATH_MAX];
	const char *         mod_name = NULL;
	FILE *               f        = NULL;
	char                 line[80];
	int                  in_block_section = 0;
	char *               p, *end, *found = NULL;
	int                  major;
	size_t               len;

	if ((mod_name = _do_sid_ucmd_get_kv(NULL, ucmd_ctx, NULL, KV_NS_DEVICE, KV_KEY_DEV_MOD, NULL, NULL)))
		goto out;

	if (!(f = fopen(SYSTEM_PROC_DEVICES_PATH, "r"))) {
		log_sys_error(ID(cmd_res), "fopen", SYSTEM_PROC_DEVICES_PATH);
		goto out;
	}

	while (fgets(line, sizeof(line), f) != NULL) {
		/* we need to be under "Block devices:" section */
		if (!in_block_section) {
			if (line[0] == 'B')
				in_block_section = 1;
			continue;
		}

		p = line;

		/* skip space prefix in line */
		while (isspace(*p))
			p++;

		/* skip whole line if there's no number */
		if (!isdigit(*p))
			continue;

		/* find where the number ends */
		end = p;
		while (isdigit(*end))
			end++;

		/* place '\0' at the end so only that number is a string */
		end[0] = '\0';

		/* try to convert the string */
		if ((major = atoi(p)) == 0)
			continue;

		/* is it the major we're looking for? */
		if (major == ucmd_ctx->udev_dev.major) {
			found = end + 1;
			break;
		}
	}

	if (!found) {
		log_error(ID(cmd_res),
		          "Unable to find major number %d for device %s in %s.",
		          ucmd_ctx->udev_dev.major,
		          ucmd_ctx->udev_dev.name,
		          SYSTEM_PROC_DEVICES_PATH);
		goto out;
	}

	p = found;
	while (isprint(*p))
		p++;
	p[0] = '\0';

	len = p - found;

	if (len >= sizeof(buf)) {
		log_error(ID(cmd_res),
		          "Insufficient result buffer for device lookup in %s, "
		          "found string \"%s\", buffer size is only %zu.",
		          SYSTEM_PROC_DEVICES_PATH,
		          found,
		          sizeof(buf));
		goto out;
	}

	memcpy(buf, found, len);
	buf[len] = '\0';
	_canonicalize_module_name(buf);

	if (!(mod_name = _do_sid_ucmd_set_kv(NULL,
	                                     ucmd_ctx,
	                                     NULL,
	                                     KV_NS_DEVICE,
	                                     KV_KEY_DEV_MOD,
	                                     DEFAULT_KV_FLAGS_CORE,
	                                     buf,
	                                     strlen(buf) + 1)))
		log_error_errno(ID(cmd_res), errno, "Failed to store device " CMD_DEV_ID_FMT " module name", CMD_DEV_ID(ucmd_ctx));
out:
	if (f)
		fclose(f);
	return mod_name;
}

static int _connection_cleanup(sid_resource_t *conn_res)
{
	sid_resource_t *worker_res = sid_resource_search(conn_res, SID_RESOURCE_SEARCH_IMM_ANC, NULL, NULL);

	sid_resource_destroy(conn_res);

	// TODO: If there are more connections per worker used,
	// 	 then check if this is the last connection.
	// 	 If it's not the last one, then do not yield the worker.

	(void) worker_control_worker_yield(worker_res);

	return 0;
}

static output_format_t flags_to_format(uint16_t flags)
{
	switch (flags & SID_CMD_FLAGS_FMT_MASK) {
		case SID_CMD_FLAGS_FMT_TABLE:
			return TABLE;
		case SID_CMD_FLAGS_FMT_JSON:
			return JSON;
		case SID_CMD_FLAGS_FMT_ENV:
			return ENV;
	}
	return TABLE; /* default to TABLE on invalid format */
}

static int _cmd_exec_version(struct cmd_exec_arg *exec_arg)
{
	int                  r;
	struct sid_ucmd_ctx *ucmd_ctx = sid_resource_get_data(exec_arg->cmd_res);
	char *               version_data;
	size_t               size;
	output_format_t      format = flags_to_format(ucmd_ctx->request_header.flags);

	print_start_document(format, ucmd_ctx->ucmd_mod_ctx.gen_buf, 0);
	print_uint_field("SID_PROTOCOL", SID_PROTOCOL, format, ucmd_ctx->ucmd_mod_ctx.gen_buf, true, 1);
	print_uint_field("SID_MAJOR", SID_VERSION_MAJOR, format, ucmd_ctx->ucmd_mod_ctx.gen_buf, true, 1);
	print_uint_field("SID_MINOR", SID_VERSION_MINOR, format, ucmd_ctx->ucmd_mod_ctx.gen_buf, true, 1);
	print_uint_field("SID_RELEASE", SID_VERSION_RELEASE, format, ucmd_ctx->ucmd_mod_ctx.gen_buf, false, 1);
	print_end_document(format, ucmd_ctx->ucmd_mod_ctx.gen_buf, 0);
	print_null_byte(ucmd_ctx->ucmd_mod_ctx.gen_buf);
	sid_buffer_get_data(ucmd_ctx->ucmd_mod_ctx.gen_buf, (const void **) &version_data, &size);
	sid_buffer_add(ucmd_ctx->res_buf, version_data, size, &r);
	return r;
}

static int _cmd_exec_tree(struct cmd_exec_arg *exec_arg)
{
	int                  r;
	struct sid_ucmd_ctx *ucmd_ctx = sid_resource_get_data(exec_arg->cmd_res);
	char *               resource_tree_data;
	size_t               size;
	output_format_t      format = flags_to_format(ucmd_ctx->request_header.flags);

	if ((r = sid_resource_write_tree_recursively(sid_resource_search(exec_arg->cmd_res, SID_RESOURCE_SEARCH_TOP, NULL, NULL),
	                                             format,
	                                             false,
	                                             ucmd_ctx->ucmd_mod_ctx.gen_buf,
	                                             0)) == 0) {
		sid_buffer_fmt_add(ucmd_ctx->ucmd_mod_ctx.gen_buf, NULL, "%s", "\n");
		print_null_byte(ucmd_ctx->ucmd_mod_ctx.gen_buf);
		sid_buffer_get_data(ucmd_ctx->ucmd_mod_ctx.gen_buf, (const void **) &resource_tree_data, &size);
		sid_buffer_add(ucmd_ctx->res_buf, resource_tree_data, size, &r);
	}
	return r;
}

static int _cmd_exec_stats(struct cmd_exec_arg *exec_arg)
{
	int                  r;
	struct sid_ucmd_ctx *ucmd_ctx = sid_resource_get_data(exec_arg->cmd_res);
	struct sid_stats     stats;
	char *               stats_data;
	size_t               size;
	output_format_t      format = flags_to_format(ucmd_ctx->request_header.flags);

	if ((r = _write_kv_store_stats(&stats, ucmd_ctx->ucmd_mod_ctx.kv_store_res)) == 0) {
		print_start_document(format, ucmd_ctx->ucmd_mod_ctx.gen_buf, 0);
		print_uint64_field("KEYS_SIZE", stats.key_size, format, ucmd_ctx->ucmd_mod_ctx.gen_buf, true, 1);
		print_uint64_field("VALUES_INTERNAL_SIZE", stats.value_int_size, format, ucmd_ctx->ucmd_mod_ctx.gen_buf, true, 1);
		print_uint64_field("VALUES_INTERNAL_DATA_SIZE",
		                   stats.value_int_data_size,
		                   format,
		                   ucmd_ctx->ucmd_mod_ctx.gen_buf,
		                   true,
		                   1);
		print_uint64_field("VALUES_EXTERNAL_SIZE", stats.value_ext_size, format, ucmd_ctx->ucmd_mod_ctx.gen_buf, true, 1);
		print_uint64_field("VALUES_EXTERNAL_DATA_SIZE",
		                   stats.value_ext_data_size,
		                   format,
		                   ucmd_ctx->ucmd_mod_ctx.gen_buf,
		                   true,
		                   1);
		print_uint64_field("METADATA_SIZE", stats.meta_size, format, ucmd_ctx->ucmd_mod_ctx.gen_buf, true, 1);
		print_uint_field("NR_KEY_VALUE_PAIRS", stats.nr_kv_pairs, format, ucmd_ctx->ucmd_mod_ctx.gen_buf, true, 1);
		print_end_document(format, ucmd_ctx->ucmd_mod_ctx.gen_buf, 0);
		print_null_byte(ucmd_ctx->ucmd_mod_ctx.gen_buf);
		sid_buffer_get_data(ucmd_ctx->ucmd_mod_ctx.gen_buf, (const void **) &stats_data, &size);
		sid_buffer_add(ucmd_ctx->res_buf, stats_data, size, &r);
	}
	return r;
}

static int _get_sysfs_value(struct module *mod, const char *path, char *buf, size_t buf_size)
{
	FILE * fp;
	size_t len;
	int    r = -1;

	if (!(fp = fopen(path, "r"))) {
		log_sys_error(_get_mod_name(mod), "fopen", path);
		goto out;
	}

	if (!(fgets(buf, buf_size, fp))) {
		log_sys_error(_get_mod_name(mod), "fgets", path);
		goto out;
	}

	if ((len = strlen(buf)) && buf[len - 1] == '\n')
		buf[--len] = '\0';

	if (!len)
		log_error(_get_mod_name(mod), "No value found in %s.", path);
	else
		r = 0;
out:
	if (fp)
		fclose(fp);

	return r;
}

int _part_get_whole_disk(struct module *mod, struct sid_ucmd_ctx *ucmd_ctx, char *devno, size_t size)
{
	const char *s;
	int         r;

	if (!ucmd_ctx || !mod || !devno || !size)
		return -EINVAL;

	if (!(s = sid_buffer_fmt_add(ucmd_ctx->ucmd_mod_ctx.gen_buf,
	                             &r,
	                             "%s%s/../dev",
	                             SYSTEM_SYSFS_PATH,
	                             ucmd_ctx->udev_dev.path))) {
		log_error_errno(_get_mod_name(mod),
		                r,
		                "Failed to compose sysfs path for whole device of partition device " CMD_DEV_ID_FMT,
		                CMD_DEV_ID(ucmd_ctx));
		return r;
	}
	r = _get_sysfs_value(mod, s, devno, size);
	sid_buffer_rewind_mem(ucmd_ctx->ucmd_mod_ctx.gen_buf, s);
	if (r < 0)
		return r;

	_canonicalize_kv_key(devno);
	return 0;
}

const void *sid_ucmd_part_get_disk_kv(struct module *      mod,
                                      struct sid_ucmd_ctx *ucmd_ctx,
                                      const char *         key,
                                      size_t *             value_size,
                                      sid_ucmd_kv_flags_t *flags)
{
	char               devno_buf[16];
	struct kv_key_spec key_spec = {.op      = KV_OP_SET,
	                               .dom     = KV_KEY_DOM_USER,
	                               .ns      = KV_NS_DEVICE,
	                               .ns_part = ID_NULL, /* will be calculated later */
	                               .id      = ID_NULL,
	                               .id_part = ID_NULL,
	                               .key     = key};

	if (!ucmd_ctx || !key || !*key || (key[0] == KEY_SYS_C[0]))
		return NULL;

	if (_part_get_whole_disk(mod, ucmd_ctx, devno_buf, sizeof(devno_buf)) < 0)
		return NULL;

	key_spec.ns_part = devno_buf;

	return _cmd_get_key_spec_value(mod, ucmd_ctx, &key_spec, value_size, flags);
}

static int _init_delta_buffer(struct buffer **delta_buf, size_t size, struct iovec *header, size_t header_size)
{
	struct buffer *buf = NULL;
	size_t         i;
	int            r = 0;

	if (!size)
		return 0;

	if (size < header_size) {
		r = -EINVAL;
		goto out;
	}

	if (!(buf = sid_buffer_create(&((struct buffer_spec) {.backend = BUFFER_BACKEND_MALLOC,
	                                                      .type    = BUFFER_TYPE_VECTOR,
	                                                      .mode    = BUFFER_MODE_PLAIN}),
	                              &((struct buffer_init) {.size = size, .alloc_step = 0, .limit = 0}),
	                              &r)))
		goto out;

	for (i = 0; i < header_size; i++) {
		if (!sid_buffer_add(buf, header[i].iov_base, header[i].iov_len, &r))
			goto out;
	}
out:
	if (r < 0)
		free(buf);
	else
		*delta_buf = buf;
	return r;
}

static int _init_delta_struct(struct kv_delta *delta,
                              size_t           minus_size,
                              size_t           plus_size,
                              size_t           final_size,
                              struct iovec *   header,
                              size_t           header_size)
{
	if (_init_delta_buffer(&delta->plus, plus_size, header, header_size) < 0 ||
	    _init_delta_buffer(&delta->minus, minus_size, header, header_size) < 0 ||
	    _init_delta_buffer(&delta->final, final_size, header, header_size) < 0) {
		_destroy_delta(delta);
		return -1;
	}

	return 0;
}

static int _iov_str_item_cmp(const void *a, const void *b)
{
	const struct iovec *iovec_item_a = (struct iovec *) a;
	const struct iovec *iovec_item_b = (struct iovec *) b;

	return strcmp((const char *) iovec_item_a->iov_base, (const char *) iovec_item_b->iov_base);
}

static int _delta_step_calculate(struct kv_store_update_spec *spec, struct kv_update_arg *update_arg)
{
	struct kv_delta *delta     = ((struct kv_rel_spec *) update_arg->custom)->delta;
	struct iovec *   old_value = spec->old_data;
	size_t           old_size  = spec->old_data_size;
	struct iovec *   new_value = spec->new_data;
	size_t           new_size  = spec->new_data_size;
	size_t           i_old, i_new;
	int              cmp_result;
	int              r = -1;

	if (_init_delta_struct(delta, old_size, new_size, old_size + new_size, new_value, KV_VALUE_IDX_DATA) < 0)
		goto out;

	if (!old_size)
		old_size = KV_VALUE_IDX_DATA;

	if (!new_size)
		new_size = KV_VALUE_IDX_DATA;

	/* start right beyond the header */
	i_old = i_new = KV_VALUE_IDX_DATA;

	/* look for differences between old_value and new_value vector */
	while (1) {
		if ((i_old < old_size) && (i_new < new_size)) {
			/* both vectors still still have items to handle */
			cmp_result = strcmp(old_value[i_old].iov_base, new_value[i_new].iov_base);
			if (cmp_result < 0) {
				/* the old vector has item the new one doesn't have */
				switch (delta->op) {
					case KV_OP_SET:
						/* we have detected removed item: add it to delta->minus */
						if (!sid_buffer_add(delta->minus,
						                    old_value[i_old].iov_base,
						                    old_value[i_old].iov_len,
						                    &r))
							goto out;
						break;
					case KV_OP_PLUS:
					/* we're keeping old item: add it to delta->final */
					/* no break here intentionally! */
					case KV_OP_MINUS:
						/* we're keeping old item: add it to delta->final */
						if (!sid_buffer_add(delta->final,
						                    old_value[i_old].iov_base,
						                    old_value[i_old].iov_len,
						                    &r))
							goto out;
						break;
					case KV_OP_ILLEGAL:
						goto out;
				}
				i_old++;
			} else if (cmp_result > 0) {
				/* the new vector has item the old one doesn't have */
				switch (delta->op) {
					case KV_OP_SET:
					/* we have detected new item: add it to delta->plus and delta->final */
					/* no break here intentionally! */
					case KV_OP_PLUS:
						/* we're adding new item: add it to delta->plus and delta->final */
						if (!sid_buffer_add(delta->plus,
						                    new_value[i_new].iov_base,
						                    new_value[i_new].iov_len,
						                    &r) ||
						    !sid_buffer_add(delta->final,
						                    new_value[i_new].iov_base,
						                    new_value[i_new].iov_len,
						                    &r))
							goto out;
						break;
					case KV_OP_MINUS:
						/* we're trying to remove non-existing item: ignore it */
						break;
					case KV_OP_ILLEGAL:
						goto out;
				}
				i_new++;
			} else {
				/* both old and new has the item */
				switch (delta->op) {
					case KV_OP_SET:
					/* we have detected no change for this item: add it to delta->final */
					/* no break here intentionally! */
					case KV_OP_PLUS:
						/* we're trying to add already existing item: add it to delta->final but not
						 * delta->plus */
						if (!sid_buffer_add(delta->final,
						                    new_value[i_new].iov_base,
						                    new_value[i_new].iov_len,
						                    &r))
							goto out;
						break;
					case KV_OP_MINUS:
						/* we're removing item: add it to delta->minus */
						if (!sid_buffer_add(delta->minus,
						                    new_value[i_new].iov_base,
						                    new_value[i_new].iov_len,
						                    &r))
							goto out;
						break;
					case KV_OP_ILLEGAL:
						goto out;
				}
				i_old++;
				i_new++;
			}
			continue;
		} else if (i_old == old_size) {
			/* only new vector still has items to handle */
			while (i_new < new_size) {
				switch (delta->op) {
					case KV_OP_SET:
					/* we have detected new item: add it to delta->final */
					/* no break here intentionally! */
					case KV_OP_PLUS:
						/* we're adding new item: add it to delta->plus and delta->final */
						if (!sid_buffer_add(delta->plus,
						                    new_value[i_new].iov_base,
						                    new_value[i_new].iov_len,
						                    &r) ||
						    !sid_buffer_add(delta->final,
						                    new_value[i_new].iov_base,
						                    new_value[i_new].iov_len,
						                    &r))
							goto out;
						break;
					case KV_OP_MINUS:
						/* we're removing non-existing item: don't add to delta->minus */
						break;
					case KV_OP_ILLEGAL:
						goto out;
				}
				i_new++;
			}
		} else if (i_new == new_size) {
			/* only old vector still has items to handle */
			while (i_old < old_size) {
				switch (delta->op) {
					case KV_OP_SET:
						/* we have detected removed item: add it to delta->minus */
						if (!sid_buffer_add(delta->minus,
						                    old_value[i_old].iov_base,
						                    old_value[i_old].iov_len,
						                    &r))
							goto out;
						break;
					case KV_OP_PLUS:
					/* we're keeping old item: add it to delta->final */
					/* no break here intentionally! */
					case KV_OP_MINUS:
						/* we're not changing the old item so add it to delta->final */
						if (!sid_buffer_add(delta->final,
						                    old_value[i_old].iov_base,
						                    old_value[i_old].iov_len,
						                    &r))
							goto out;
						break;
					case KV_OP_ILLEGAL:
						goto out;
				}
				i_old++;
			}
		}
		/* no more items to process in both old and new vector: exit */
		break;
	}

	r = 0;
out:
	if (r < 0)
		_destroy_delta(delta);
	else
		_destroy_unused_delta(delta);

	return r;
}

static void _delta_cross_bitmap_calculate(struct cross_bitmap_calc_arg *cross)
{
	size_t old_size, new_size;
	size_t i_old, i_new;
	int    cmp_result;

	if ((old_size = cross->old_size) < KV_VALUE_IDX_DATA)
		old_size = KV_VALUE_IDX_DATA;

	if ((new_size = cross->new_size) < KV_VALUE_IDX_DATA)
		new_size = KV_VALUE_IDX_DATA;

	i_old = i_new = KV_VALUE_IDX_DATA;

	while (1) {
		if ((i_old < old_size) && (i_new < new_size)) {
			/* both vectors still have items to handle */
			cmp_result = strcmp(cross->old_value[i_old].iov_base, cross->new_value[i_new].iov_base);
			if (cmp_result < 0) {
				/* the old vector has item the new one doesn't have: OK */
				i_old++;
			} else if (cmp_result > 0) {
				/* the new vector has item the old one doesn't have: OK */
				i_new++;
			} else {
				/* both old and new has the item: we have found contradiction! */
				bitmap_bit_unset(cross->old_bmp, i_old);
				bitmap_bit_unset(cross->new_bmp, i_new);
				i_old++;
				i_new++;
			}
		} else if (i_old == old_size) {
			/* only new vector still has items to handle: nothing else to compare */
			break;
		} else if (i_new == new_size) {
			/* only old vector still has items to handle: nothing else to compare */
			break;
		}
	}
}

static int _delta_abs_calculate(struct kv_store_update_spec *spec, struct kv_update_arg *update_arg, struct kv_delta *abs_delta)
{
	struct cross_bitmap_calc_arg cross1   = {0};
	struct cross_bitmap_calc_arg cross2   = {0};
	struct kv_rel_spec *         rel_spec = update_arg->custom;
	kv_op_t                      orig_op  = rel_spec->cur_key_spec->op;
	const char *                 delta_full_key;
	struct iovec *               abs_plus, *abs_minus;
	size_t                       i, abs_plus_size, abs_minus_size;
	int                          r = -1;

	if (!rel_spec->delta->plus && !rel_spec->delta->minus)
		return 0;

	rel_spec->cur_key_spec->op = KV_OP_PLUS;
	delta_full_key             = _buffer_compose_key(update_arg->gen_buf, rel_spec->cur_key_spec);
	if (!delta_full_key)
		goto out;
	cross1.old_value = kv_store_get_value(update_arg->res, delta_full_key, &cross1.old_size, NULL);
	sid_buffer_rewind_mem(update_arg->gen_buf, delta_full_key);
	if (cross1.old_value) {
		if (!(cross1.old_bmp = bitmap_create(cross1.old_size, true, NULL)))
			goto out;
	}

	rel_spec->cur_key_spec->op = KV_OP_MINUS;
	delta_full_key             = _buffer_compose_key(update_arg->gen_buf, rel_spec->cur_key_spec);
	if (!delta_full_key)
		goto out;
	cross2.old_value = kv_store_get_value(update_arg->res, delta_full_key, &cross2.old_size, NULL);
	sid_buffer_rewind_mem(update_arg->gen_buf, delta_full_key);
	if (cross2.old_value) {
		if (!(cross2.old_bmp = bitmap_create(cross2.old_size, true, NULL)))
			goto out;
	}

	/*
	 * set up cross1 - old plus vs. new minus
	 *
	 * OLD              NEW
	 *
	 * plus  <----|     plus
	 * minus      |---> minus
	 */
	if (rel_spec->delta->minus) {
		sid_buffer_get_data(rel_spec->delta->minus, (const void **) &cross1.new_value, &cross1.new_size);

		if (!(cross1.new_bmp = bitmap_create(cross1.new_size, true, NULL)))
			goto out;

		/* cross-compare old_plus with new_minus and unset bitmap positions where we find contradiction */
		_delta_cross_bitmap_calculate(&cross1);
	}

	/*
	 * setup cross2 - old minus vs. new plus
	 *
	 * OLD             NEW
	 *
	 * plus      |---> plus
	 * minus <---|     minus
	 */
	if (rel_spec->delta->plus) {
		sid_buffer_get_data(rel_spec->delta->plus, (const void **) &cross2.new_value, &cross2.new_size);

		if (!(cross2.new_bmp = bitmap_create(cross2.new_size, true, NULL)))
			goto out;

		/* cross-compare old_minus with new_plus and unset bitmap positions where we find contradiction */
		_delta_cross_bitmap_calculate(&cross2);
	}

	/*
	 * count overall size for both plus and minus taking only non-contradicting items
	 *
	 * OLD             NEW
	 *
	 * plus  <---+---> plus
	 * minus <---+---> minus
	 */
	abs_minus_size = ((cross2.old_bmp ? bitmap_get_bit_set_count(cross2.old_bmp) : 0) +
	                  (cross1.new_bmp ? bitmap_get_bit_set_count(cross1.new_bmp) : 0));
	if (cross2.old_bmp && cross1.new_bmp)
		abs_minus_size -= KV_VALUE_IDX_DATA;

	abs_plus_size = ((cross1.old_bmp ? bitmap_get_bit_set_count(cross1.old_bmp) : 0) +
	                 (cross2.new_bmp ? bitmap_get_bit_set_count(cross2.new_bmp) : 0));
	if (cross1.old_bmp && cross2.new_bmp)
		abs_plus_size -= KV_VALUE_IDX_DATA;

	/* go through the old and new plus and minus vectors and merge non-contradicting items */
	if (_init_delta_struct(abs_delta, abs_minus_size, abs_plus_size, 0, spec->new_data, KV_VALUE_IDX_DATA) < 0)
		goto out;

	if (rel_spec->delta->flags & DELTA_WITH_REL)
		abs_delta->flags |= DELTA_WITH_REL;

	if (cross1.old_value) {
		for (i = KV_VALUE_IDX_DATA; i < cross1.old_size; i++) {
			if (bitmap_bit_is_set(cross1.old_bmp, i, NULL) &&
			    !sid_buffer_add(abs_delta->plus, cross1.old_value[i].iov_base, cross1.old_value[i].iov_len, &r))
				goto out;
		}
	}

	if (cross1.new_value) {
		for (i = KV_VALUE_IDX_DATA; i < cross1.new_size; i++) {
			if (bitmap_bit_is_set(cross1.new_bmp, i, NULL) &&
			    !sid_buffer_add(abs_delta->minus, cross1.new_value[i].iov_base, cross1.new_value[i].iov_len, &r))
				goto out;
		}
	}

	if (cross2.old_value) {
		for (i = KV_VALUE_IDX_DATA; i < cross2.old_size; i++) {
			if (bitmap_bit_is_set(cross2.old_bmp, i, NULL) &&
			    !sid_buffer_add(abs_delta->minus, cross2.old_value[i].iov_base, cross2.old_value[i].iov_len, &r))
				goto out;
		}
	}

	if (cross2.new_value) {
		for (i = KV_VALUE_IDX_DATA; i < cross2.new_size; i++) {
			if (bitmap_bit_is_set(cross2.new_bmp, i, NULL) &&
			    !sid_buffer_add(abs_delta->plus, cross2.new_value[i].iov_base, cross2.new_value[i].iov_len, &r))
				goto out;
		}
	}

	if (abs_delta->plus) {
		sid_buffer_get_data(abs_delta->plus, (const void **) &abs_plus, &abs_plus_size);
		qsort(abs_plus + KV_VALUE_IDX_DATA, abs_plus_size - KV_VALUE_IDX_DATA, sizeof(struct iovec), _iov_str_item_cmp);
	}

	if (abs_delta->minus) {
		sid_buffer_get_data(abs_delta->minus, (const void **) &abs_minus, &abs_minus_size);
		qsort(abs_minus + KV_VALUE_IDX_DATA, abs_minus_size - KV_VALUE_IDX_DATA, sizeof(struct iovec), _iov_str_item_cmp);
	}

	r = 0;
out:
	if (cross1.old_bmp)
		bitmap_destroy(cross1.old_bmp);
	if (cross1.new_bmp)
		bitmap_destroy(cross1.new_bmp);
	if (cross2.old_bmp)
		bitmap_destroy(cross2.old_bmp);
	if (cross2.new_bmp)
		bitmap_destroy(cross2.new_bmp);

	rel_spec->cur_key_spec->op = orig_op;

	if (r < 0)
		_destroy_delta(abs_delta);

	return r;
}

// TODO: Make it possible to set all flags at once or change selected flag bits.
static void _value_vector_mark_persist(struct iovec *iov, int persist)
{
	if (persist)
		iov[KV_VALUE_IDX_FLAGS] = (struct iovec) {&kv_flags_persist, sizeof(kv_flags_persist)};
	else
		iov[KV_VALUE_IDX_FLAGS] = (struct iovec) {&kv_flags_no_persist, sizeof(kv_flags_no_persist)};
}

static void _flip_key_specs(struct kv_rel_spec *rel_spec)
{
	struct kv_key_spec *tmp_key_spec;

	tmp_key_spec           = rel_spec->cur_key_spec;
	rel_spec->cur_key_spec = rel_spec->rel_key_spec;
	rel_spec->rel_key_spec = tmp_key_spec;
}

static int
	_delta_update(struct kv_store_update_spec *spec, struct kv_update_arg *update_arg, struct kv_delta *abs_delta, kv_op_t op)
{
	uint64_t            seqnum        = KV_VALUE_SEQNUM(spec->new_data);
	struct kv_rel_spec *rel_spec      = update_arg->custom;
	kv_op_t             orig_op       = rel_spec->cur_key_spec->op;
	const char *        tmp_mem_start = sid_buffer_add(update_arg->gen_buf, "", 0, NULL);
	struct kv_delta *   orig_delta;
	struct iovec *      delta_iov, *abs_delta_iov;
	size_t              delta_iov_cnt, abs_delta_iov_cnt, i;
	const char *        key_prefix, *ns_part, *full_key;
	struct iovec        rel_iov[KV_VALUE_IDX_DATA + 1];
	int                 r = 0;

	if (op == KV_OP_PLUS) {
		if (!abs_delta->plus)
			return 0;
		sid_buffer_get_data(abs_delta->plus, (const void **) &abs_delta_iov, &abs_delta_iov_cnt);
		sid_buffer_get_data(rel_spec->delta->plus, (const void **) &delta_iov, &delta_iov_cnt);
	} else if (op == KV_OP_MINUS) {
		if (!abs_delta->minus)
			return 0;
		sid_buffer_get_data(abs_delta->minus, (const void **) &abs_delta_iov, &abs_delta_iov_cnt);
		sid_buffer_get_data(rel_spec->delta->minus, (const void **) &delta_iov, &delta_iov_cnt);
	} else {
		log_error(ID(update_arg->res), INTERNAL_ERROR "%s: incorrect delta operation requested.", __func__);
		return -1;
	}

	/* store absolute delta for current item - persistent */
	rel_spec->cur_key_spec->op = op;
	full_key                   = _buffer_compose_key(update_arg->gen_buf, rel_spec->cur_key_spec);
	rel_spec->cur_key_spec->op = orig_op;
	if (!full_key)
		return -1;

	_value_vector_mark_persist(abs_delta_iov, 1);

	kv_store_set_value(update_arg->res,
	                   full_key,
	                   abs_delta_iov,
	                   abs_delta_iov_cnt,
	                   KV_STORE_VALUE_VECTOR,
	                   KV_STORE_VALUE_NO_OP,
	                   _kv_overwrite,
	                   update_arg);

	_value_vector_mark_persist(abs_delta_iov, 0);

	sid_buffer_rewind_mem(update_arg->gen_buf, full_key);

	/* the other way round now - store final and absolute delta for each relative */
	if (delta_iov_cnt && rel_spec->delta->flags & DELTA_WITH_REL) {
		_flip_key_specs(rel_spec);
		orig_delta = rel_spec->delta;

		rel_spec->delta     = &((struct kv_delta) {0});
		rel_spec->delta->op = op;
		/*
		 * WARNING: Be careful here - never call with DELTA_WITH_REL flag otherwise
		 *          we'd get into infinite loop. Mind that we are using _kv_delta
		 *          here for the kv_store_set_value BUT we're already inside _kv_delta
		 *          here. We just need to store the final and absolute vectors for
		 *          relatives, nothing else.
		 */
		rel_spec->delta->flags = DELTA_WITH_DIFF;

		key_prefix = _buffer_compose_key_prefix(update_arg->gen_buf, rel_spec->rel_key_spec);
		if (!key_prefix) {
			r = -1;
			goto fail;
		}
		KV_VALUE_PREPARE_HEADER(rel_iov, seqnum, kv_flags_no_persist, (char *) update_arg->owner);
		rel_iov[KV_VALUE_IDX_DATA] = (struct iovec) {.iov_base = (void *) key_prefix, .iov_len = strlen(key_prefix) + 1};

		for (i = KV_VALUE_IDX_DATA; i < delta_iov_cnt; i++) {
			ns_part                         = _buffer_copy_ns_part_from_key(update_arg->gen_buf, delta_iov[i].iov_base);
			rel_spec->cur_key_spec->ns_part = ns_part;
			full_key                        = _buffer_compose_key(update_arg->gen_buf, rel_spec->cur_key_spec);
			if (!full_key) {
				r = -1;
				goto fail;
			}
			kv_store_set_value(update_arg->res,
			                   full_key,
			                   rel_iov,
			                   KV_VALUE_IDX_DATA + 1,
			                   KV_STORE_VALUE_VECTOR | KV_STORE_VALUE_REF,
			                   KV_STORE_VALUE_NO_OP,
			                   _kv_delta,
			                   update_arg);

			_destroy_delta(rel_spec->delta);
		}
fail:
		rel_spec->delta = orig_delta;
		_flip_key_specs(rel_spec);
	}

	rel_spec->cur_key_spec->op = orig_op;
	sid_buffer_rewind_mem(update_arg->gen_buf, tmp_mem_start);
	return r;
}

/*
 * The _kv_delta function is a helper responsible for calculating changes
 * between old and new vector values and then updating the database accordingly.
 * It is supposed to be called as update callback in kv_store_set_value.
 *
 * The sequence of steps taken is this:
 *
 *   1) kv_store_set_value is called with _kv_delta update callback.
 *
 *   2) kv_store_set_value checks database content and fills in
 *      the 'spec' with old vector (the one already written in database)
 *      and new vector (the one with which we are trying to update
 *      the database in certain way). How the database is actually
 *      updated depends on combination of defined operation and flags
 *      (described later).
 *
 *   3) kv_store_set_value calls _kv_delta to resolve the update.
 *
 *   4) _kv_delta casts 'arg' to the proper 'struct kv_update_arg'
 *      instance, called 'update_arg' here.
 *
 *   5) _kv_delta casts 'update_arg->custom' to proper
 *      'struct kv_rel_spec' instance, called 'rel_spec' here.
 *
 *   6) _kv_delta takes the 'spec' arg with old and new value and
 *      calculates changes between the two, depending on which
 *      'rel_spec->delta->op' operation is used (this is done
 *      in _delta_step_calculate helper function that _kv_delta
 *      calls):
 *
 *        - 'KV_OP_SET' overwrites old vector with new vector
 *
 *        - 'KV_OP_PLUS' merges items from old and new vector
 *
 *        - 'KV_OP_MINUS' removes items from new vector from old vector
 *
 *      The results are stored in 'rel_spec->delta' instance:
 *
 *        - 'rel_spec->delta->plus' vector containing items that are being added
 *
 *        - 'rel_spec->delta->minus' vector containing items that are being removed
 *
 *        - 'rel_spec->delta->final' vector containing resulting vector
 *
 *      The 'rel_spec->delta->{plus,minus} are called DELTA STEP VECTORS
 *      because we calculate only the difference between immediate old
 *      and new value.
 *
 *      If we don't need any transactions or reciprocal updates,
 *      we stop here. We take the resulting 'rel_spec->delta->final'
 *      vector and we return that one up to the caller so it can write
 *      it to the database as new value (overwriting the old value).
 *
 *   === THE STEPS BELOW APPLY FOR TRANSACTIONS AND/OR RECIPROCAL UPDATES ===
 *
 *   Here, by TRANSACTIONS we mean:
 *
 *     - several possible updates done to snapshot database
 *       before we do final synchronization of this snapshot database
 *       with main database.
 *
 *   Here, by RECIPROCAL UPDATES we mean:
 *
 *     - for each item of vector A, also update all the vectors with key
 *       that is derived from the item of vector A. For example:
 *
 *         - adding X and Y to vector with key A: A = +{X, Y}
 *
 *        and so we do reciprocal update:
 *
 *         - adding A to vector with derived key X: X = +{A}
 *         - adding A to vector with derived key Y: Y = +{A}
 *
 *   We use rel_spec->delta->flags to define transactional and/or reciprocal updates:
 *
 *        - 'DELTA_WITH_DIFF' causes calculation of DELTA ABSOLUTE VECTORS
 *          besides delta step vectors. The delta absolute vectors
 *          contain overall change within a transaction up to current point in time.
 *
 *        - 'DELTA_WITH_REL' also causes calculation of DELTA ABSOLUTE VECTORS.
 *          In addition to that, it does the reciprocal updates for each
 *          delta step as defined by step vectors.
 *
 *   7) _kv_delta calculates DELTA ABSOLUTE VECTORS and it stores them
 *      in internal 'abs_delta' variable for both DELTA_WITH_DIFF and DELTA_WITH_REL case
 *      (this is done in _delta_step_calculate helper function that _kv_delta calls).
 *
 *   8) _kv_delta updates database (this is done in _delta_update helper function that
 *      _kv_delta calls):
 *
 *        8_1 delta plus vectors are processed:
 *
 *          8_1_1) absolute delta plus vector is stored in database with
 *                _kv_overwrite database callback (so simply overwriting any existing value)
 *
 *          8_1_2) if we want reciprocal updates, then for each item as defined
 *	           by rel_spec->delta->plus vector, we store the reciprocal
 *                 relation in database with _kv_delta database callback (because
 *                 we need to trigger the the same kind of update just like we
 *                 do for current update.)
 *
 *                 !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 *                 WARNING: Here we use _kv_delta inside _kv_delta, so that's a
 *                          recursive call!!! We have to be very careful here and
 *                          we have to call this internal _kv_delta only with
 *                          DELTA_WITH_DIFF flag, never with DELTA_WITH_REL!!!
 *                          Otherwise, we'd get into infinite loop updating,
 *                          for example:
 *
 *                          A = +{X} then X = +{A} then A = +{X} then X = +{A} ...
 *                 !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 *
 *        8_2 delta minus vectors are processed:
 *	      (the same as 8_1, just for the minus vectors instead of plus vectors)
 *
 */
static int _kv_delta(const char *full_key __attribute__((unused)), struct kv_store_update_spec *spec, void *arg)
{
	struct kv_update_arg *update_arg = arg;
	struct kv_rel_spec *  rel_spec   = update_arg->custom;
	struct kv_delta       abs_delta  = {0};
	int                   r          = 0; /* no change by default */

	/* FIXME: propagate error out of this function so it can be reported by caller. */

	/*
	 * Take previous and current vector and calculate differential "plus" and "minus" vectors.
	 * These are "step vectors".
	 */
	if (_delta_step_calculate(spec, update_arg) < 0)
		goto out;

	/*
	 * Take the "step vectors" we've just calculated and account for any not yet
	 * committed "absolute vectors" and calculate new absolute vectors ruling
	 * out any contradictions.
	 *
	 * A contradiction happens when (previous) "absolute plus vector" contains an item that
	 * is also present in just calculated "step minus vector" and vice versa.
	 *
	 * This way we support application of more than one delta within one transaction
	 * before we do a final commit.
	 *
	 */
	if (rel_spec->delta->flags & (DELTA_WITH_DIFF | DELTA_WITH_REL)) {
		if (_delta_abs_calculate(spec, update_arg, &abs_delta) < 0)
			goto out;

		if (_delta_update(spec, update_arg, &abs_delta, KV_OP_PLUS) < 0)
			goto out;

		if (_delta_update(spec, update_arg, &abs_delta, KV_OP_MINUS) < 0)
			goto out;
	}

	/*
	 * Get the actual vector out of rel_spec->delta->final and rewrite spec->new_data
	 * with this one. Also, make the vector to be copied instead of referenced only
	 * because we will destroy the delta buffer completely.
	 */
	if (rel_spec->delta->final) {
		sid_buffer_get_data(rel_spec->delta->final, (const void **) &spec->new_data, &spec->new_data_size);

		spec->new_flags &= ~KV_STORE_VALUE_REF;

		r = 1;
	}
out:
	_destroy_delta(&abs_delta);

	return r;
}

static int _refresh_device_disk_hierarchy_from_sysfs(sid_resource_t *cmd_res)
{
	/* FIXME: ...fail completely here, discarding any changes made to DB so far if any of the steps below fail? */
	struct sid_ucmd_ctx *ucmd_ctx      = sid_resource_get_data(cmd_res);
	const char *         tmp_mem_start = sid_buffer_add(ucmd_ctx->ucmd_mod_ctx.gen_buf, "", 0, NULL);
	const char *         s;
	struct dirent **     dirent  = NULL;
	struct buffer *      vec_buf = NULL;
	char                 devno_buf[16];
	struct iovec *       iov;
	size_t               iov_cnt;
	int                  count = 0, i;
	int                  r     = -1;

	struct kv_rel_spec rel_spec = {.delta = &((struct kv_delta) {.op    = KV_OP_SET,
	                                                             .flags = DELTA_WITH_DIFF | DELTA_WITH_REL,
	                                                             .plus  = NULL,
	                                                             .minus = NULL,
	                                                             .final = NULL}),

	                               .cur_key_spec =
	                                       &((struct kv_key_spec) {.op      = KV_OP_SET,
	                                                               .dom     = KV_KEY_DOM_LAYER,
	                                                               .ns      = KV_NS_DEVICE,
	                                                               .ns_part = _get_ns_part(NULL, ucmd_ctx, KV_NS_DEVICE),
	                                                               .id      = ID_NULL,
	                                                               .id_part = ID_NULL,
	                                                               .key     = KV_KEY_GEN_GROUP_MEMBERS}),

	                               .rel_key_spec = &((struct kv_key_spec) {.op      = KV_OP_SET,
	                                                                       .dom     = KV_KEY_DOM_LAYER,
	                                                                       .ns      = KV_NS_DEVICE,
	                                                                       .ns_part = ID_NULL, /* will be calculated later */
	                                                                       .id      = ID_NULL,
	                                                                       .id_part = ID_NULL,
	                                                                       .key     = KV_KEY_GEN_GROUP_IN})};

	struct kv_update_arg update_arg = {.res     = ucmd_ctx->ucmd_mod_ctx.kv_store_res,
	                                   .owner   = OWNER_CORE,
	                                   .gen_buf = ucmd_ctx->ucmd_mod_ctx.gen_buf,
	                                   .custom  = &rel_spec};

	if (ucmd_ctx->udev_dev.action != UDEV_ACTION_REMOVE) {
		if (!(s = sid_buffer_fmt_add(ucmd_ctx->ucmd_mod_ctx.gen_buf,
		                             &r,
		                             "%s%s/%s",
		                             SYSTEM_SYSFS_PATH,
		                             ucmd_ctx->udev_dev.path,
		                             SYSTEM_SYSFS_SLAVES))) {
			log_error_errno(ID(cmd_res),
			                r,
			                "Failed to compose sysfs %s path for device " CMD_DEV_ID_FMT,
			                SYSTEM_SYSFS_SLAVES,
			                CMD_DEV_ID(ucmd_ctx));
			goto out;
		}

		if ((count = scandir(s, &dirent, NULL, NULL)) < 0) {
			/*
			 * FIXME: Add code to deal with/warn about: (errno == ENOENT) && (ucmd_ctx->udev_dev.action !=
			 * UDEV_ACTION_REMOVE). That means we don't have REMOVE uevent, but at the same time, we don't have sysfs
			 * content, e.g. because we're processing this uevent too late: the device has already been removed right
			 * after this uevent was triggered. For now, error out even in this case.
			 */
			log_sys_error(ID(cmd_res), "scandir", s);
			goto out;
		}

		sid_buffer_rewind_mem(ucmd_ctx->ucmd_mod_ctx.gen_buf, s);
	}

	/*
	 * Create vec_buf used to set up database records.
	 * (count - 2 + 3) == (count + 1)
	 * -2 to subtract "." and ".." directory which we're not interested in
	 * +3 for "seqnum|flags|owner" header
	 */
	if (!(vec_buf = sid_buffer_create(&((struct buffer_spec) {.backend = BUFFER_BACKEND_MALLOC,
	                                                          .type    = BUFFER_TYPE_VECTOR,
	                                                          .mode    = BUFFER_MODE_PLAIN}),
	                                  &((struct buffer_init) {.size = count + 1, .alloc_step = 1, .limit = 0}),
	                                  &r))) {
		log_error_errno(ID(cmd_res),
		                r,
		                "Failed to create buffer to record hierarchy for device " CMD_DEV_ID_FMT,
		                CMD_DEV_ID(ucmd_ctx));
		goto out;
	}

	/* Add record header to vec_buf: seqnum | flags | owner. */
	if (!sid_buffer_add(vec_buf, &ucmd_ctx->udev_dev.seqnum, sizeof(ucmd_ctx->udev_dev.seqnum), &r) ||
	    !sid_buffer_add(vec_buf, &kv_flags_no_persist, sizeof(kv_flags_no_persist), &r) ||
	    !sid_buffer_add(vec_buf, core_owner, strlen(core_owner) + 1, &r))
		goto out;

	/* Read relatives from sysfs into vec_buf. */
	if (ucmd_ctx->udev_dev.action != UDEV_ACTION_REMOVE) {
		for (i = 0; i < count; i++) {
			if (dirent[i]->d_name[0] == '.') {
				free(dirent[i]);
				continue;
			}

			if ((s = sid_buffer_fmt_add(ucmd_ctx->ucmd_mod_ctx.gen_buf,
			                            &r,
			                            "%s%s/%s/%s/dev",
			                            SYSTEM_SYSFS_PATH,
			                            ucmd_ctx->udev_dev.path,
			                            SYSTEM_SYSFS_SLAVES,
			                            dirent[i]->d_name))) {
				if (_get_sysfs_value(NULL, s, devno_buf, sizeof(devno_buf)) < 0) {
					sid_buffer_rewind_mem(ucmd_ctx->ucmd_mod_ctx.gen_buf, s);
					continue;
				}
				sid_buffer_rewind_mem(ucmd_ctx->ucmd_mod_ctx.gen_buf, s);

				_canonicalize_kv_key(devno_buf);
				rel_spec.rel_key_spec->ns_part = devno_buf;

				s = _buffer_compose_key_prefix(ucmd_ctx->ucmd_mod_ctx.gen_buf, rel_spec.rel_key_spec);
				if (!s || !sid_buffer_add(vec_buf, (void *) s, strlen(s) + 1, &r))
					goto out;
			} else
				log_error_errno(
					ID(cmd_res),
					r,
					"Failed to compose sysfs path for device %s which is relative of device " CMD_DEV_ID_FMT,
					dirent[i]->d_name,
					CMD_DEV_ID(ucmd_ctx));

			free(dirent[i]);
		}
		free(dirent);
		rel_spec.rel_key_spec->ns_part = ID_NULL;
	}

	/* Get the actual vector with relatives and sort it. */
	sid_buffer_get_data(vec_buf, (const void **) (&iov), &iov_cnt);
	qsort(iov + 3, iov_cnt - 3, sizeof(struct iovec), _iov_str_item_cmp);

	if (!(s = _buffer_compose_key(ucmd_ctx->ucmd_mod_ctx.gen_buf, rel_spec.cur_key_spec))) {
		log_error(ID(cmd_res),
		          _key_prefix_err_msg,
		          ucmd_ctx->udev_dev.name,
		          ucmd_ctx->udev_dev.major,
		          ucmd_ctx->udev_dev.minor);
		goto out;
	}

	/*
	 * Handle delta.final vector for this device.
	 * The delta.final is computed inside _kv_delta out of vec_buf.
	 * The _kv_delta also sets delta.plus and delta.minus vectors with info about changes when compared to previous record.
	 */
	iov = kv_store_set_value(ucmd_ctx->ucmd_mod_ctx.kv_store_res,
	                         s,
	                         iov,
	                         iov_cnt,
	                         KV_STORE_VALUE_VECTOR | KV_STORE_VALUE_REF,
	                         KV_STORE_VALUE_NO_OP,
	                         _kv_delta,
	                         &update_arg);

	r = 0;
out:
	_destroy_delta(rel_spec.delta);
	if (vec_buf)
		sid_buffer_destroy(vec_buf);
	sid_buffer_rewind_mem(ucmd_ctx->ucmd_mod_ctx.gen_buf, tmp_mem_start);
	return r;
}

static int _refresh_device_partition_hierarchy_from_sysfs(sid_resource_t *cmd_res)
{
	struct sid_ucmd_ctx *ucmd_ctx      = sid_resource_get_data(cmd_res);
	const char *         tmp_mem_start = sid_buffer_add(ucmd_ctx->ucmd_mod_ctx.gen_buf, "", 0, NULL);
	struct iovec         iov_to_store[KV_VALUE_IDX_DATA + 1];
	char                 devno_buf[16];
	const char *         s;
	int                  r = -1;

	struct kv_rel_spec rel_spec = {.delta = &((struct kv_delta) {.op    = KV_OP_SET,
	                                                             .flags = DELTA_WITH_DIFF | DELTA_WITH_REL,
	                                                             .plus  = NULL,
	                                                             .minus = NULL,
	                                                             .final = NULL}),

	                               .cur_key_spec =
	                                       &((struct kv_key_spec) {.op      = KV_OP_SET,
	                                                               .dom     = KV_KEY_DOM_LAYER,
	                                                               .ns      = KV_NS_DEVICE,
	                                                               .ns_part = _get_ns_part(NULL, ucmd_ctx, KV_NS_DEVICE),
	                                                               .id      = ID_NULL,
	                                                               .id_part = ID_NULL,
	                                                               .key     = KV_KEY_GEN_GROUP_MEMBERS}),

	                               .rel_key_spec = &((struct kv_key_spec) {.op      = KV_OP_SET,
	                                                                       .dom     = KV_KEY_DOM_LAYER,
	                                                                       .ns      = KV_NS_DEVICE,
	                                                                       .ns_part = ID_NULL, /* will be calculated later */
	                                                                       .id      = ID_NULL,
	                                                                       .id_part = ID_NULL,
	                                                                       .key     = KV_KEY_GEN_GROUP_IN})};

	struct kv_update_arg update_arg = {.res     = ucmd_ctx->ucmd_mod_ctx.kv_store_res,
	                                   .owner   = OWNER_CORE,
	                                   .gen_buf = ucmd_ctx->ucmd_mod_ctx.gen_buf,
	                                   .custom  = &rel_spec};

	KV_VALUE_PREPARE_HEADER(iov_to_store, ucmd_ctx->udev_dev.seqnum, kv_flags_no_persist, core_owner);
	if (_part_get_whole_disk(NULL, ucmd_ctx, devno_buf, sizeof(devno_buf)) < 0)
		goto out;

	rel_spec.rel_key_spec->ns_part = devno_buf;

	s = _buffer_compose_key_prefix(ucmd_ctx->ucmd_mod_ctx.gen_buf, rel_spec.rel_key_spec);
	if (!s)
		goto out;
	iov_to_store[KV_VALUE_IDX_DATA] = (struct iovec) {(void *) s, strlen(s) + 1};

	rel_spec.rel_key_spec->ns_part = ID_NULL;

	if (!(s = _buffer_compose_key(ucmd_ctx->ucmd_mod_ctx.gen_buf, rel_spec.cur_key_spec))) {
		log_error(ID(cmd_res),
		          _key_prefix_err_msg,
		          ucmd_ctx->udev_dev.name,
		          ucmd_ctx->udev_dev.major,
		          ucmd_ctx->udev_dev.minor);
		goto out;
	}

	/*
	 * Handle delta.final vector for this device.
	 * The delta.final is computed inside _kv_delta out of vec_buf.
	 * The _kv_delta also sets delta.plus and delta.minus vectors with info about changes when compared to previous record.
	 */
	kv_store_set_value(ucmd_ctx->ucmd_mod_ctx.kv_store_res,
	                   s,
	                   iov_to_store,
	                   KV_VALUE_IDX_DATA + 1,
	                   KV_STORE_VALUE_VECTOR | KV_STORE_VALUE_REF,
	                   KV_STORE_VALUE_NO_OP,
	                   _kv_delta,
	                   &update_arg);

	r = 0;
out:
	_destroy_delta(rel_spec.delta);
	sid_buffer_rewind_mem(ucmd_ctx->ucmd_mod_ctx.gen_buf, tmp_mem_start);
	return r;
}

static int _refresh_device_hierarchy_from_sysfs(sid_resource_t *cmd_res)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_resource_get_data(cmd_res);

	switch (ucmd_ctx->udev_dev.type) {
		case UDEV_DEVTYPE_DISK:
			if ((_refresh_device_disk_hierarchy_from_sysfs(cmd_res) < 0))
				return -1;
			break;
		case UDEV_DEVTYPE_PARTITION:
			if ((_refresh_device_partition_hierarchy_from_sysfs(cmd_res) < 0))
				return -1;
			break;
		case UDEV_DEVTYPE_UNKNOWN:
			break;
	}

	return 0;
}

static int _execute_block_modules(struct cmd_exec_arg *exec_arg, cmd_scan_phase_t phase)
{
	struct sid_ucmd_ctx *     ucmd_ctx = sid_resource_get_data(exec_arg->cmd_res);
	sid_resource_t *          block_mod_res;
	struct module *           block_mod;
	const struct cmd_mod_fns *block_mod_fns;
	int                       r = -1;

	sid_resource_iter_reset(exec_arg->block_mod_iter);

	while ((block_mod_res = sid_resource_iter_next(exec_arg->block_mod_iter))) {
		if (module_registry_get_module_symbols(block_mod_res, (const void ***) &block_mod_fns) < 0) {
			log_error(ID(exec_arg->cmd_res), "Failed to retrieve module symbols from module %s.", ID(block_mod_res));
			goto out;
		}

		block_mod = sid_resource_get_data(block_mod_res);

		switch (phase) {
			case CMD_SCAN_PHASE_A_IDENT:
				if (block_mod_fns->ident && block_mod_fns->ident(block_mod, ucmd_ctx) < 0)
					goto out;
				break;
			case CMD_SCAN_PHASE_A_SCAN_PRE:
				if (block_mod_fns->scan_pre && block_mod_fns->scan_pre(block_mod, ucmd_ctx) < 0)
					goto out;
				break;
			case CMD_SCAN_PHASE_A_SCAN_CURRENT:
				if (block_mod_fns->scan_current && block_mod_fns->scan_current(block_mod, ucmd_ctx) < 0)
					goto out;
				break;
			case CMD_SCAN_PHASE_A_SCAN_NEXT:
				if (block_mod_fns->scan_next && block_mod_fns->scan_next(block_mod, ucmd_ctx) < 0)
					goto out;
				break;
			case CMD_SCAN_PHASE_A_SCAN_POST_CURRENT:
				if (block_mod_fns->scan_post_current && block_mod_fns->scan_post_current(block_mod, ucmd_ctx) < 0)
					goto out;
				break;
			case CMD_SCAN_PHASE_A_SCAN_POST_NEXT:
				if (block_mod_fns->scan_post_next && block_mod_fns->scan_post_next(block_mod, ucmd_ctx) < 0)
					goto out;
				break;
			case CMD_SCAN_PHASE_B_TRIGGER_ACTION_CURRENT:
				if (block_mod_fns->trigger_action_current &&
				    block_mod_fns->trigger_action_current(block_mod, ucmd_ctx) < 0)
					goto out;
				break;
			case CMD_SCAN_PHASE_B_TRIGGER_ACTION_NEXT:
				if (block_mod_fns->trigger_action_next &&
				    block_mod_fns->trigger_action_next(block_mod, ucmd_ctx) < 0)
					goto out;
				break;
			case CMD_SCAN_PHASE_ERROR:
				if (block_mod_fns->error && block_mod_fns->error(block_mod, ucmd_ctx) < 0)
					goto out;
				break;
			default:
				log_error(ID(exec_arg->cmd_res),
				          INTERNAL_ERROR "%s: Trying illegal execution of block modules in %s state.",
				          __func__,
				          _cmd_scan_phase_regs[phase].name);
				break;
		}
	}

	r = 0;
out:
	return r;
}

static int _set_device_kv_records(sid_resource_t *cmd_res)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_resource_get_data(cmd_res);
	dev_ready_t          ready;
	dev_reserved_t       reserved;

	if (!_do_sid_ucmd_get_kv(NULL, ucmd_ctx, NULL, KV_NS_DEVICE, KV_KEY_DEV_READY, NULL, NULL)) {
		ready    = DEV_NOT_RDY_UNPROCESSED;
		reserved = DEV_RES_UNPROCESSED;

		_do_sid_ucmd_set_kv(NULL,
		                    ucmd_ctx,
		                    NULL,
		                    KV_NS_DEVICE,
		                    KV_KEY_DEV_READY,
		                    DEFAULT_KV_FLAGS_CORE,
		                    &ready,
		                    sizeof(ready));
		_do_sid_ucmd_set_kv(NULL,
		                    ucmd_ctx,
		                    NULL,
		                    KV_NS_DEVICE,
		                    KV_KEY_DEV_RESERVED,
		                    DEFAULT_KV_FLAGS_CORE,
		                    &reserved,
		                    sizeof(reserved));
	}

	_refresh_device_hierarchy_from_sysfs(cmd_res);

	return 0;
}

static int _cmd_exec_scan_init(struct cmd_exec_arg *exec_arg)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_resource_get_data(exec_arg->cmd_res);
	sid_resource_t *     block_mod_registry_res;

	if (!(block_mod_registry_res = sid_resource_search(ucmd_ctx->ucmd_mod_ctx.modules_res,
	                                                   SID_RESOURCE_SEARCH_IMM_DESC,
	                                                   &sid_resource_type_module_registry,
	                                                   MODULES_BLOCK_ID))) {
		log_error(ID(exec_arg->cmd_res), INTERNAL_ERROR "%s: Failed to find block module registry resource.", __func__);
		goto fail;
	}

	if (!(exec_arg->block_mod_iter = sid_resource_iter_create(block_mod_registry_res))) {
		log_error(ID(exec_arg->cmd_res), "Failed to create block module iterator.");
		goto fail;
	}

	if (!(exec_arg->type_mod_registry_res = sid_resource_search(ucmd_ctx->ucmd_mod_ctx.modules_res,
	                                                            SID_RESOURCE_SEARCH_IMM_DESC,
	                                                            &sid_resource_type_module_registry,
	                                                            MODULES_TYPE_ID))) {
		log_error(ID(exec_arg->cmd_res), INTERNAL_ERROR "%s: Failed to find type module registry resource.", __func__);
		goto fail;
	}

	if (_set_device_kv_records(exec_arg->cmd_res) < 0) {
		log_error(ID(exec_arg->cmd_res), "Failed to set device hierarchy.");
		goto fail;
	}

	return 0;
fail:
	if (exec_arg->block_mod_iter) {
		sid_resource_iter_destroy(exec_arg->block_mod_iter);
		exec_arg->block_mod_iter = NULL;
	}

	return -1;
}

static int _cmd_exec_scan_ident(struct cmd_exec_arg *exec_arg)
{
	struct sid_ucmd_ctx *     ucmd_ctx = sid_resource_get_data(exec_arg->cmd_res);
	const struct cmd_mod_fns *mod_fns;
	const char *              mod_name;

	if ((mod_name = _lookup_module_name(exec_arg->cmd_res)) &&
	    !(exec_arg->type_mod_res_current = module_registry_get_module(exec_arg->type_mod_registry_res, mod_name)))
		log_debug(ID(exec_arg->cmd_res), "Module %s not loaded.", mod_name);

	_execute_block_modules(exec_arg, CMD_SCAN_PHASE_A_IDENT);

	if (!exec_arg->type_mod_res_current)
		return 0;

	module_registry_get_module_symbols(exec_arg->type_mod_res_current, (const void ***) &mod_fns);
	if (mod_fns && mod_fns->ident)
		return mod_fns->ident(sid_resource_get_data(exec_arg->type_mod_res_current), ucmd_ctx);

	return 0;
}

static int _cmd_exec_scan_pre(struct cmd_exec_arg *exec_arg)
{
	struct sid_ucmd_ctx *     ucmd_ctx = sid_resource_get_data(exec_arg->cmd_res);
	const struct cmd_mod_fns *mod_fns;

	_execute_block_modules(exec_arg, CMD_SCAN_PHASE_A_SCAN_PRE);

	if (!exec_arg->type_mod_res_current)
		return 0;

	module_registry_get_module_symbols(exec_arg->type_mod_res_current, (const void ***) &mod_fns);
	if (mod_fns && mod_fns->scan_pre)
		return mod_fns->scan_pre(sid_resource_get_data(exec_arg->type_mod_res_current), ucmd_ctx);

	return 0;
}

static int _cmd_exec_scan_current(struct cmd_exec_arg *exec_arg)
{
	struct sid_ucmd_ctx *     ucmd_ctx = sid_resource_get_data(exec_arg->cmd_res);
	const struct cmd_mod_fns *mod_fns;

	_execute_block_modules(exec_arg, CMD_SCAN_PHASE_A_SCAN_CURRENT);

	if (!exec_arg->type_mod_res_current)
		return 0;

	module_registry_get_module_symbols(exec_arg->type_mod_res_current, (const void ***) &mod_fns);
	if (mod_fns && mod_fns->scan_current)
		if (mod_fns->scan_current(sid_resource_get_data(exec_arg->type_mod_res_current), ucmd_ctx))
			return -1;

	return 0;
}

static int _cmd_exec_scan_next(struct cmd_exec_arg *exec_arg)
{
	struct sid_ucmd_ctx *     ucmd_ctx = sid_resource_get_data(exec_arg->cmd_res);
	const struct cmd_mod_fns *mod_fns;
	const char *              next_mod_name;

	_execute_block_modules(exec_arg, CMD_SCAN_PHASE_A_SCAN_NEXT);

	if ((next_mod_name = _do_sid_ucmd_get_kv(NULL, ucmd_ctx, NULL, KV_NS_DEVICE, SID_UCMD_KEY_DEVICE_NEXT_MOD, NULL, NULL))) {
		if (!(exec_arg->type_mod_res_next = module_registry_get_module(exec_arg->type_mod_registry_res, next_mod_name)))
			log_debug(ID(exec_arg->cmd_res), "Module %s not loaded.", next_mod_name);
	} else
		exec_arg->type_mod_res_next = NULL;

	if (!exec_arg->type_mod_res_next)
		return 0;

	module_registry_get_module_symbols(exec_arg->type_mod_res_next, (const void ***) &mod_fns);
	if (mod_fns && mod_fns->scan_next)
		return mod_fns->scan_next(sid_resource_get_data(exec_arg->type_mod_res_next), ucmd_ctx);

	return 0;
}

static int _cmd_exec_scan_post_current(struct cmd_exec_arg *exec_arg)
{
	struct sid_ucmd_ctx *     ucmd_ctx = sid_resource_get_data(exec_arg->cmd_res);
	const struct cmd_mod_fns *mod_fns;

	_execute_block_modules(exec_arg, CMD_SCAN_PHASE_A_SCAN_POST_CURRENT);

	if (!exec_arg->type_mod_res_current)
		return 0;

	module_registry_get_module_symbols(exec_arg->type_mod_res_current, (const void ***) &mod_fns);
	if (mod_fns && mod_fns->scan_post_current)
		return mod_fns->scan_post_current(sid_resource_get_data(exec_arg->type_mod_res_current), ucmd_ctx);

	return 0;
}

static int _cmd_exec_scan_post_next(struct cmd_exec_arg *exec_arg)
{
	struct sid_ucmd_ctx *     ucmd_ctx = sid_resource_get_data(exec_arg->cmd_res);
	const struct cmd_mod_fns *mod_fns;

	_execute_block_modules(exec_arg, CMD_SCAN_PHASE_A_SCAN_POST_NEXT);

	if (!exec_arg->type_mod_res_next)
		return 0;

	module_registry_get_module_symbols(exec_arg->type_mod_res_next, (const void ***) &mod_fns);
	if (mod_fns && mod_fns->scan_post_next)
		return mod_fns->scan_post_next(sid_resource_get_data(exec_arg->type_mod_res_next), ucmd_ctx);

	return 0;
}

static int _cmd_exec_scan_wait(struct cmd_exec_arg *exec_arg)
{
	return 0;
}

static int _cmd_exec_scan_exit(struct cmd_exec_arg *exec_arg)
{
	if (exec_arg->block_mod_iter) {
		sid_resource_iter_destroy(exec_arg->block_mod_iter);
		exec_arg->block_mod_iter = NULL;
	}

	return 0;
}

static int _cmd_exec_trigger_action_current(struct cmd_exec_arg *exec_arg)
{
	return 0;
}

static int _cmd_exec_trigger_action_next(struct cmd_exec_arg *exec_arg)
{
	return 0;
}

static int _cmd_exec_scan_error(struct cmd_exec_arg *exec_arg)
{
	struct sid_ucmd_ctx *     ucmd_ctx = sid_resource_get_data(exec_arg->cmd_res);
	const struct cmd_mod_fns *mod_fns;
	int                       r = 0;

	_execute_block_modules(exec_arg, CMD_SCAN_PHASE_ERROR);

	if (exec_arg->type_mod_res_current) {
		module_registry_get_module_symbols(exec_arg->type_mod_res_current, (const void ***) &mod_fns);
		if (mod_fns && mod_fns->error)
			r |= mod_fns->error(sid_resource_get_data(exec_arg->type_mod_res_current), ucmd_ctx);
	}

	if (exec_arg->type_mod_res_next) {
		module_registry_get_module_symbols(exec_arg->type_mod_res_next, (const void ***) &mod_fns);
		if (mod_fns && mod_fns->error)
			r |= mod_fns->error(sid_resource_get_data(exec_arg->type_mod_res_next), ucmd_ctx);
	}

	return r;
}

static struct cmd_reg _cmd_scan_phase_regs[] = {
	[CMD_SCAN_PHASE_A_INIT] = {.name = "init", .flags = CMD_SCAN_CAP_ALL, .exec = _cmd_exec_scan_init},

	[CMD_SCAN_PHASE_A_IDENT] = {.name = "ident", .flags = 0, .exec = _cmd_exec_scan_ident},

	[CMD_SCAN_PHASE_A_SCAN_PRE] = {.name = "scan-pre", .flags = CMD_SCAN_CAP_RDY, .exec = _cmd_exec_scan_pre},

	[CMD_SCAN_PHASE_A_SCAN_CURRENT] = {.name = "scan-current", .flags = CMD_SCAN_CAP_RDY, .exec = _cmd_exec_scan_current},

	[CMD_SCAN_PHASE_A_SCAN_NEXT] = {.name = "scan-next", .flags = CMD_SCAN_CAP_RES, .exec = _cmd_exec_scan_next},

	[CMD_SCAN_PHASE_A_SCAN_POST_CURRENT] = {.name = "scan-post-current", .flags = 0, .exec = _cmd_exec_scan_post_current},

	[CMD_SCAN_PHASE_A_SCAN_POST_NEXT] = {.name = "scan-post-next", .flags = 0, .exec = _cmd_exec_scan_post_next},

	[CMD_SCAN_PHASE_A_WAITING] = {.name = "waiting", .flags = 0, .exec = _cmd_exec_scan_wait},

	[CMD_SCAN_PHASE_A_EXIT] = {.name = "exit", .flags = CMD_SCAN_CAP_ALL, .exec = _cmd_exec_scan_exit},

	[CMD_SCAN_PHASE_B_TRIGGER_ACTION_CURRENT] = {.name  = "trigger-action-current",
                                                     .flags = 0,
                                                     .exec  = _cmd_exec_trigger_action_current},

	[CMD_SCAN_PHASE_B_TRIGGER_ACTION_NEXT] = {.name = "trigger-action-next", .flags = 0, .exec = _cmd_exec_trigger_action_next},

	[CMD_SCAN_PHASE_ERROR] = {.name = "error", .flags = 0, .exec = _cmd_exec_scan_error},
};

static int _cmd_exec_scan(struct cmd_exec_arg *exec_arg)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_resource_get_data(exec_arg->cmd_res);
	cmd_scan_phase_t     phase;

	for (phase = CMD_SCAN_PHASE_A_INIT; phase <= CMD_SCAN_PHASE_A_EXIT; phase++) {
		log_debug(ID(exec_arg->cmd_res), "Executing %s phase.", _cmd_scan_phase_regs[phase].name);
		ucmd_ctx->scan_phase = phase;

		if (_cmd_scan_phase_regs[phase].exec(exec_arg) < 0) {
			log_error(ID(exec_arg->cmd_res), "%s phase failed.", _cmd_scan_phase_regs[phase].name);

			/* if init or exit phase fails, there's nothing else we can do */
			if (phase == CMD_SCAN_PHASE_A_INIT || phase == CMD_SCAN_PHASE_A_EXIT)
				return -1;

			/* otherwise, call out modules to handle the error case */
			if (_cmd_scan_phase_regs[CMD_SCAN_PHASE_ERROR].exec(exec_arg) < 0)
				log_error(ID(exec_arg->cmd_res), "error phase failed.");
		}
	}

	return 0;
}

static struct cmd_reg _cmd_regs[] = {
	[SID_CMD_UNKNOWN]    = {.name = NULL, .flags = 0, .exec = NULL},
	[SID_CMD_ACTIVE]     = {.name = NULL, .flags = 0, .exec = NULL},
	[SID_CMD_CHECKPOINT] = {.name = NULL, .flags = CMD_KV_IMPORT_UDEV, .exec = NULL},
	[SID_CMD_REPLY]      = {.name = NULL, .flags = 0, .exec = NULL},
	[SID_CMD_SCAN]       = {.name  = NULL,
                          .flags = CMD_KV_IMPORT_UDEV | CMD_KV_EXPORT_UDEV | CMD_KV_EXPORT_SID | CMD_SESSION_ID,
                          .exec  = _cmd_exec_scan},
	[SID_CMD_VERSION]    = {.name = NULL, .flags = 0, .exec = _cmd_exec_version},
	[SID_CMD_DUMP]       = {.name = NULL, .flags = CMD_KV_EXPORT_UDEV | CMD_KV_EXPORT_SID | CMD_KV_EXPORT_CLIENT, .exec = NULL},
	[SID_CMD_STATS]      = {.name = NULL, .flags = 0, .exec = _cmd_exec_stats},
	[SID_CMD_TREE]       = {.name = NULL, .flags = 0, .exec = _cmd_exec_tree},
};

static ssize_t _send_fd_over_unix_comms(int fd, int unix_comms_fd)
{
	static unsigned char byte = 0xFF;
	ssize_t              n;

	for (;;) {
		n = sid_comms_unix_send(unix_comms_fd, &byte, sizeof(byte), fd);
		if (n >= 0)
			break;
		if (n == -EAGAIN || n == -EINTR)
			continue;
		break;
	}

	return n;
}

static int _cmd_handler(sid_resource_event_source_t *es, void *data)
{
	sid_resource_t *        cmd_res         = data;
	struct sid_ucmd_ctx *   ucmd_ctx        = sid_resource_get_data(cmd_res);
	sid_resource_t *        conn_res        = sid_resource_search(cmd_res, SID_RESOURCE_SEARCH_IMM_ANC, NULL, NULL);
	struct connection *     conn            = sid_resource_get_data(conn_res);
	struct sid_msg_header   response_header = {.status = SID_CMD_STATUS_SUCCESS, .prot = SID_PROTOCOL, .cmd = SID_CMD_REPLY};
	struct cmd_exec_arg     exec_arg        = {0};
	int                     r               = -1;
	struct worker_data_spec data_spec;
	struct cmd_reg *        cmd_reg;

	if (!sid_buffer_add(ucmd_ctx->res_buf, &response_header, sizeof(response_header), &r))
		goto out;

	if (ucmd_ctx->request_header.prot < 2) {
		log_error(ID(cmd_res), "Client protocol version unsupported: %u", ucmd_ctx->request_header.prot);
		(void) _connection_cleanup(conn_res);
		return -1;
	} else if (ucmd_ctx->request_header.prot <= SID_PROTOCOL) {
		/* If client speaks older protocol, reply using this protocol, if possible. */
		response_header.prot  = ucmd_ctx->request_header.prot;
		response_header.flags = ucmd_ctx->request_header.flags;

		cmd_reg          = &_cmd_regs[ucmd_ctx->request_header.cmd];
		exec_arg.cmd_res = cmd_res;

		if (cmd_reg->exec && ((r = cmd_reg->exec(&exec_arg)) < 0)) {
			log_error(ID(cmd_res), "Failed to execute command");
			goto out;
		}
	} else {
		log_error(ID(cmd_res), "Client protocol unknown version: %u > %u ", ucmd_ctx->request_header.prot, SID_PROTOCOL);
		(void) _connection_cleanup(conn_res);
		return -1;
	}

	if (cmd_reg->flags & CMD_KV_EXPORT_UDEV || cmd_reg->flags & CMD_KV_EXPORT_SID) {
		if ((r = _build_kv_buffer(cmd_res,
		                          cmd_reg->flags & CMD_KV_EXPORT_UDEV,
		                          cmd_reg->flags & CMD_KV_EXPORT_SID,
		                          cmd_reg->flags & CMD_KV_EXPORT_CLIENT ? flags_to_format(ucmd_ctx->request_header.flags)
		                                                                : NO_FORMAT)) < 0) {
			log_error(ID(cmd_res), "Failed to export KV store.");
			goto out;
		}
	}
out:
	if (r < 0)
		response_header.status |= SID_CMD_STATUS_FAILURE;

	if (sid_buffer_write_all(ucmd_ctx->res_buf, conn->fd) < 0) {
		(void) _connection_cleanup(conn_res);
		log_error(ID(cmd_res), "Failed to send command response.");
		r = -1;
	}

	if (ucmd_ctx->exp_buf && r >= 0) {
		if (cmd_reg->flags & CMD_KV_EXPORT_CLIENT) {
			if ((r = _send_fd_over_unix_comms(sid_buffer_get_fd(ucmd_ctx->exp_buf), conn->fd)) < 0)
				log_error_errno(ID(cmd_res), r, "Failed to send command exports to client.");
		} else {
			if (sid_buffer_stat(ucmd_ctx->exp_buf).usage.used > BUFFER_SIZE_PREFIX_LEN) {
				data_spec.data               = NULL;
				data_spec.data_size          = 0;
				data_spec.ext.used           = true;
				data_spec.ext.socket.fd_pass = sid_buffer_get_fd(ucmd_ctx->exp_buf);

				if ((r = worker_control_channel_send(cmd_res, MAIN_WORKER_CHANNEL_ID, &data_spec)) < 0)
					log_error_errno(ID(cmd_res), r, "Failed to send command exports to main SID process.");
			}
		}
	}

	return r;
}

static int _reply_failure(sid_resource_t *conn_res)
{
	struct connection *   conn = sid_resource_get_data(conn_res);
	struct sid_msg        msg;
	uint8_t               prot;
	struct sid_msg_header response_header = {
		.status = SID_CMD_STATUS_FAILURE,
	};
	int r = -1;

	(void) sid_buffer_get_data(conn->buf, (const void **) &msg.header, &msg.size);
	prot = msg.header->prot;
	(void) sid_buffer_rewind(conn->buf, BUFFER_SIZE_PREFIX_LEN, BUFFER_POS_ABS);
	if (prot <= SID_PROTOCOL) {
		response_header.prot = prot;
		if (sid_buffer_add(conn->buf, &response_header, sizeof(response_header), &r))
			r = sid_buffer_write_all(conn->buf, conn->fd);
	}

	return r;
}

static int _on_connection_event(sid_resource_event_source_t *es, int fd, uint32_t revents, void *data)
{
	sid_resource_t *   conn_res = data;
	struct connection *conn     = sid_resource_get_data(conn_res);
	struct sid_msg     msg;
	char               id[32];
	ssize_t            n;
	int                r = 0;

	if (revents & EPOLLERR) {
		if (revents & EPOLLHUP)
			log_error(ID(conn_res), "Peer connection closed prematurely.");
		else
			log_error(ID(conn_res), "Connection error.");
		(void) _connection_cleanup(conn_res);
		return -1;
	}

	n = sid_buffer_read(conn->buf, fd);
	if (n > 0) {
		if (sid_buffer_is_complete(conn->buf, NULL)) {
			(void) sid_buffer_get_data(conn->buf, (const void **) &msg.header, &msg.size);

			if (msg.size < sizeof(struct sid_msg_header)) {
				(void) _connection_cleanup(conn_res);
				return -1;
			}
			/* Sanitize command number - map all out of range command numbers to CMD_UNKNOWN. */
			if (msg.header->cmd < _SID_CMD_START || msg.header->cmd > _SID_CMD_END)
				msg.header->cmd = SID_CMD_UNKNOWN;

			snprintf(id, sizeof(id), "%d/%s", getpid(), sid_cmd_names[msg.header->cmd]);

			if (!sid_resource_create(conn_res,
			                         &sid_resource_type_ubridge_command,
			                         SID_RESOURCE_NO_FLAGS,
			                         id,
			                         &msg,
			                         SID_RESOURCE_PRIO_NORMAL,
			                         SID_RESOURCE_NO_SERVICE_LINKS)) {
				log_error(ID(conn_res), "Failed to register command for processing.");
				if (_reply_failure(conn_res) < 0) {
					(void) _connection_cleanup(conn_res);
					return -1;
				}
			}
			(void) sid_buffer_reset(conn->buf);
		}
	} else if (n < 0) {
		if (n == -EAGAIN || n == -EINTR)
			return 0;
		log_error_errno(ID(conn_res), n, "buffer_read_msg");
		r = -1;
	} else {
		if (_connection_cleanup(conn_res) < 0)
			r = -1;
	}

	return r;
}

static int _init_connection(sid_resource_t *res, const void *kickstart_data, void **data)
{
	const struct worker_data_spec *data_spec = kickstart_data;
	struct connection *            conn;
	int                            r;

	if (!(conn = mem_zalloc(sizeof(*conn)))) {
		log_error(ID(res), "Failed to allocate new connection structure.");
		goto fail;
	}

	conn->fd = data_spec->ext.socket.fd_pass;

	if (sid_resource_create_io_event_source(res, NULL, conn->fd, _on_connection_event, 0, "client connection", res) < 0) {
		log_error(ID(res), "Failed to register connection event handler.");
		goto fail;
	}

	if (!(conn->buf = sid_buffer_create(&((struct buffer_spec) {.backend = BUFFER_BACKEND_MALLOC,
	                                                            .type    = BUFFER_TYPE_LINEAR,
	                                                            .mode    = BUFFER_MODE_SIZE_PREFIX}),
	                                    &((struct buffer_init) {.size = 0, .alloc_step = 1, .limit = 0}),
	                                    &r))) {
		log_error_errno(ID(res), r, "Failed to create connection buffer");
		goto fail;
	}

	*data = conn;
	return 0;
fail:
	if (conn) {
		if (conn->buf)
			sid_buffer_destroy(conn->buf);
		free(conn);
	}
	return -1;
}

static int _destroy_connection(sid_resource_t *res)
{
	struct connection *conn = sid_resource_get_data(res);

	if (conn->fd != -1)
		close(conn->fd);

	if (conn->buf)
		sid_buffer_destroy(conn->buf);

	free(conn);
	return 0;
}

static bool _socket_client_is_capable(int fd, sid_cmd_t cmd)
{
	socklen_t    len = 0;
	struct ucred uc;

	len = sizeof(struct ucred);
	/* root can run any command */
	if ((fd >= 0) && (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &uc, &len) == 0) && (uc.uid == 0))
		return true;
	return !_cmd_root_only[cmd];
}

static int _init_command(sid_resource_t *res, const void *kickstart_data, void **data)
{
	const struct sid_msg *msg      = kickstart_data;
	struct sid_ucmd_ctx * ucmd_ctx = NULL;
	struct connection *   conn     = sid_resource_get_data(sid_resource_search(res, SID_RESOURCE_SEARCH_IMM_ANC, NULL, NULL));
	const char *          worker_id;
	int                   r;

	if (!conn || !_socket_client_is_capable(conn->fd, msg->header->cmd)) {
		log_error(ID(res), "client does not have permission to run %s", sid_cmd_names[msg->header->cmd]);
		return -1;
	}

	if (!(ucmd_ctx = mem_zalloc(sizeof(*ucmd_ctx)))) {
		log_error(ID(res), "Failed to allocate new command structure.");
		return -1;
	}

	if (!(ucmd_ctx->res_buf = sid_buffer_create(&((struct buffer_spec) {.backend = BUFFER_BACKEND_MALLOC,
	                                                                    .type    = BUFFER_TYPE_VECTOR,
	                                                                    .mode    = BUFFER_MODE_SIZE_PREFIX}),
	                                            &((struct buffer_init) {.size = 1, .alloc_step = 1, .limit = 0}),
	                                            &r))) {
		log_error_errno(ID(res), r, "Failed to create response buffer");
		goto fail;
	}

	ucmd_ctx->request_header = *msg->header;

	if (!(ucmd_ctx->ucmd_mod_ctx.gen_buf =
	              sid_buffer_create(&((struct buffer_spec) {.backend = BUFFER_BACKEND_MALLOC,
	                                                        .type    = BUFFER_TYPE_LINEAR,
	                                                        .mode    = BUFFER_MODE_PLAIN}),
	                                &((struct buffer_init) {.size = 0, .alloc_step = PATH_MAX, .limit = 0}),
	                                &r))) {
		log_error_errno(ID(res), r, "Failed to create generic buffer");
		goto fail;
	}

	if (!(ucmd_ctx->ucmd_mod_ctx.modules_res =
	              sid_resource_search(res, SID_RESOURCE_SEARCH_GENUS, &sid_resource_type_aggregate, MODULES_AGGREGATE_ID))) {
		log_error(ID(res), INTERNAL_ERROR "%s: Failed to find module registry aggregator.", __func__);
		goto fail;
	}

	if (!(ucmd_ctx->ucmd_mod_ctx.kv_store_res =
	              sid_resource_search(res, SID_RESOURCE_SEARCH_GENUS, &sid_resource_type_kv_store, MAIN_KV_STORE_NAME))) {
		log_error(ID(res), INTERNAL_ERROR "%s: Failed to find key-value store.", __func__);
		goto fail;
	}

	if (_cmd_regs[msg->header->cmd].flags & CMD_KV_IMPORT_UDEV) {
		/* currently, we only parse udev environment for the SCAN command */
		if ((r = _parse_cmd_nullstr_udev_env(ucmd_ctx, msg->header->data, msg->size - sizeof(*msg->header))) < 0) {
			log_error_errno(ID(res), r, "Failed to parse udev environment variables");
			goto fail;
		}
	}

	if (_cmd_regs[msg->header->cmd].flags & CMD_SESSION_ID) {
		if (!(worker_id = worker_control_get_worker_id(res))) {
			log_error(ID(res), "Failed to get worker ID to set %s udev variable.", KV_KEY_UDEV_SID_SESSION_ID);
			goto fail;
		}

		if (!_do_sid_ucmd_set_kv(NULL,
		                         ucmd_ctx,
		                         NULL,
		                         KV_NS_UDEV,
		                         KV_KEY_UDEV_SID_SESSION_ID,
		                         KV_PERSISTENT,
		                         worker_id,
		                         strlen(worker_id) + 1)) {
			log_error(ID(res), "Failed to set %s udev variable.", KV_KEY_UDEV_SID_SESSION_ID);
			goto fail;
		}
	}

	if (sid_resource_create_deferred_event_source(res, NULL, _cmd_handler, 0, "command handler", res) < 0) {
		log_error(ID(res), "Failed to register command handler.");
		goto fail;
	}

	*data = ucmd_ctx;
	return 0;
fail:
	if (ucmd_ctx) {
		if (ucmd_ctx->ucmd_mod_ctx.gen_buf)
			sid_buffer_destroy(ucmd_ctx->ucmd_mod_ctx.gen_buf);
		if (ucmd_ctx->res_buf)
			sid_buffer_destroy(ucmd_ctx->res_buf);
		if (ucmd_ctx->dev_id)
			free(ucmd_ctx->dev_id);
		free(ucmd_ctx);
	}
	return -1;
}

static int _destroy_command(sid_resource_t *res)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_resource_get_data(res);

	sid_buffer_destroy(ucmd_ctx->ucmd_mod_ctx.gen_buf);
	sid_buffer_destroy(ucmd_ctx->res_buf);
	if (ucmd_ctx->exp_buf)
		sid_buffer_destroy(ucmd_ctx->exp_buf);
	free(ucmd_ctx->dev_id);
	free(ucmd_ctx);

	return 0;
}

static int _main_kv_store_unset(const char *full_key, struct kv_store_update_spec *spec, void *arg)
{
	struct kv_update_arg *update_arg = arg;
	struct iovec          tmp_iov_old[KV_VALUE_IDX_DATA + 1];
	struct iovec *        iov_old;

	if (!spec->old_data)
		return 1;

	iov_old = _get_value_vector(spec->old_flags, spec->old_data, spec->old_data_size, tmp_iov_old);

	if (_flags_indicate_mod_owned(KV_VALUE_FLAGS(iov_old)) && strcmp(KV_VALUE_OWNER(iov_old), update_arg->owner)) {
		log_debug(ID(update_arg->res),
		          "Refusing request from module %s to unset existing value for key %s (seqnum %" PRIu64
		          "which belongs to module %s.",
		          update_arg->owner,
		          full_key,
		          KV_VALUE_SEQNUM(iov_old),
		          KV_VALUE_OWNER(iov_old));
		update_arg->ret_code = EBUSY;
		return 0;
	}

	return 1;
}

static int _main_kv_store_update(const char *full_key, struct kv_store_update_spec *spec, void *arg)
{
	struct kv_update_arg *update_arg = arg;
	struct kv_rel_spec *  rel_spec   = update_arg->custom;
	struct iovec          tmp_iov_old[KV_VALUE_IDX_DATA + 1];
	struct iovec          tmp_iov_new[KV_VALUE_IDX_DATA + 1];
	struct iovec *        iov_old, *iov_new;
	int                   r;

	iov_old = _get_value_vector(spec->old_flags, spec->old_data, spec->old_data_size, tmp_iov_old);
	iov_new = _get_value_vector(spec->new_flags, spec->new_data, spec->new_data_size, tmp_iov_new);

	if (rel_spec->delta->op == KV_OP_SET)
		/* overwrite whole value */
		r = (!iov_old ||
		     ((KV_VALUE_SEQNUM(iov_new) >= KV_VALUE_SEQNUM(iov_old)) && _kv_overwrite(full_key, spec, update_arg)));
	else {
		/* resolve delta */
		r = _kv_delta(full_key, spec, update_arg);
		/* resolving delta might have changed new_data so get it afresh for the log_debug below */
		iov_new = _get_value_vector(spec->new_flags, spec->new_data, spec->new_data_size, tmp_iov_new);
	}

	if (r)
		log_debug(ID(update_arg->res),
		          "Updating value for key %s (new seqnum %" PRIu64 " >= old seqnum %" PRIu64 ")",
		          full_key,
		          KV_VALUE_SEQNUM(iov_new),
		          iov_old ? KV_VALUE_SEQNUM(iov_old) : 0);
	else
		log_debug(ID(update_arg->res),
		          "Keeping old value for key %s (new seqnum %" PRIu64 " < old seqnum %" PRIu64 ")",
		          full_key,
		          KV_VALUE_SEQNUM(iov_new),
		          iov_old ? KV_VALUE_SEQNUM(iov_old) : 0);

	return r;
}

static int _sync_main_kv_store(sid_resource_t *worker_proxy_res, sid_resource_t *internal_ubridge_res, int fd)
{
	static const char       syncing_msg[] = "Syncing main key-value store:  %s = %s (seqnum %" PRIu64 ")";
	struct ubridge *        ubridge       = sid_resource_get_data(internal_ubridge_res);
	sid_resource_t *        kv_store_res;
	kv_store_value_flags_t  flags;
	BUFFER_SIZE_PREFIX_TYPE msg_size;
	size_t                  full_key_size, data_size, data_offset, i;
	char *                  full_key, *shm = MAP_FAILED, *p, *end;
	struct kv_value *       value = NULL;
	struct iovec *          iov   = NULL;
	const char *            iov_str;
	void *                  data_to_store;
	struct kv_rel_spec      rel_spec   = {.delta = &((struct kv_delta) {0})};
	struct kv_update_arg    update_arg = {.gen_buf = ubridge->ucmd_mod_ctx.gen_buf, .custom = &rel_spec};
	bool                    unset;
	int                     r = -1;

	if (!(kv_store_res = sid_resource_search(internal_ubridge_res,
	                                         SID_RESOURCE_SEARCH_IMM_DESC,
	                                         &sid_resource_type_kv_store,
	                                         MAIN_KV_STORE_NAME)))
		return -ENOMEDIUM;

	ubridge = sid_resource_get_data(internal_ubridge_res);

	if (read(fd, &msg_size, BUFFER_SIZE_PREFIX_LEN) != BUFFER_SIZE_PREFIX_LEN) {
		log_error_errno(ID(worker_proxy_res), errno, "Failed to read shared memory size");
		goto out;
	}

	if (msg_size <= BUFFER_SIZE_PREFIX_LEN) { /* nothing to sync */
		r = 0;
		goto out;
	}

	if ((p = shm = mmap(NULL, msg_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED) {
		log_error_errno(ID(worker_proxy_res), errno, "Failed to map memory with key-value store");
		goto out;
	}

	end = p + msg_size;
	p += sizeof(msg_size);

	while (p < end) {
		flags = *((kv_store_value_flags_t *) p);
		p += sizeof(flags);

		full_key_size = *((size_t *) p);
		p += sizeof(full_key_size);

		data_size = *((size_t *) p);
		p += sizeof(data_size);

		full_key = p;
		p += full_key_size;

		/*
		 * Note: if we're reserving a value, then we keep it even if it's NULL.
		 * This prevents others to use the same key. To unset the value,
		 * one needs to drop the flag explicitly.
		 */

		if (flags & KV_STORE_VALUE_VECTOR) {
			if (data_size < KV_VALUE_IDX_DATA) {
				log_error(ID(worker_proxy_res),
				          "Received incorrect vector of size %zu to sync with main key-value store.",
				          data_size);
				goto out;
			}

			if (!(iov = malloc(data_size * sizeof(struct iovec)))) {
				log_error(ID(worker_proxy_res), "Failed to allocate vector to sync main key-value store.");
				goto out;
			}

			for (i = 0; i < data_size; i++) {
				iov[i].iov_len = *((size_t *) p);
				p += sizeof(size_t);
				iov[i].iov_base = p;
				p += iov[i].iov_len;
			}

			unset = !(KV_VALUE_FLAGS(iov) & KV_MOD_RESERVED) && (data_size == KV_VALUE_IDX_DATA);

			update_arg.owner    = KV_VALUE_OWNER(iov);
			update_arg.res      = kv_store_res;
			update_arg.ret_code = -EREMOTEIO;

			iov_str = _get_iov_str(ubridge->ucmd_mod_ctx.gen_buf, unset, iov, data_size);
			log_debug(ID(worker_proxy_res), syncing_msg, full_key, iov_str, KV_VALUE_SEQNUM(iov));
			if (iov_str)
				sid_buffer_rewind_mem(ubridge->ucmd_mod_ctx.gen_buf, iov_str);

			switch (rel_spec.delta->op = _get_op_from_key(full_key)) {
				case KV_OP_PLUS:
					full_key += sizeof(KV_PREFIX_OP_PLUS_C) - 1;
					break;
				case KV_OP_MINUS:
					full_key += sizeof(KV_PREFIX_OP_MINUS_C) - 1;
					break;
				case KV_OP_SET:
					break;
				case KV_OP_ILLEGAL:
					log_error(ID(worker_proxy_res),
					          INTERNAL_ERROR
					          "Illegal operator found for key %s while trying to sync main key-value store.",
					          full_key);
					goto out;
			}

			data_to_store = iov;
		} else {
			if (data_size <= sizeof(struct kv_value)) {
				log_error(ID(worker_proxy_res),
				          "Received incorrect value of size %zu to sync with main key-value store.",
				          data_size);
				goto out;
			}

			value = (struct kv_value *) p;
			p += data_size;

			data_offset = _kv_value_ext_data_offset(value);
			unset       = ((value->flags != KV_MOD_RESERVED) && (data_size == (sizeof(struct kv_value) + data_offset)));

			update_arg.owner    = value->data;
			update_arg.res      = kv_store_res;
			update_arg.ret_code = -EREMOTEIO;

			log_debug(ID(worker_proxy_res),
			          syncing_msg,
			          full_key,
			          unset         ? "NULL"
			          : data_offset ? value->data + data_offset
			                        : value->data,
			          value->seqnum);

			rel_spec.delta->op = KV_OP_SET;

			data_to_store = value;
		}

		if (unset)
			kv_store_unset_value(kv_store_res, full_key, _main_kv_store_unset, &update_arg);
		else
			kv_store_set_value(kv_store_res,
			                   full_key,
			                   data_to_store,
			                   data_size,
			                   flags,
			                   KV_STORE_VALUE_NO_OP,
			                   _main_kv_store_update,
			                   &update_arg);

		_destroy_delta(rel_spec.delta);
		iov = mem_freen(iov);
	}

	r = 0;

	//_dump_kv_store(__func__, kv_store_res);
	//_dump_kv_store_dev_stack_in_dot(__func__, kv_store_res);
out:
	free(iov);

	if (shm != MAP_FAILED && munmap(shm, msg_size) < 0) {
		log_error_errno(ID(worker_proxy_res), errno, "Failed to unmap memory with key-value store");
		r = -1;
	}

	return r;
}

static int _worker_proxy_recv_fn(sid_resource_t *         worker_proxy_res,
                                 struct worker_channel *  chan,
                                 struct worker_data_spec *data_spec,
                                 void *                   arg)
{
	sid_resource_t *internal_ubridge_res = arg;
	int             r;

	if (data_spec->ext.used) {
		r = _sync_main_kv_store(worker_proxy_res, internal_ubridge_res, data_spec->ext.socket.fd_pass);
		close(data_spec->ext.socket.fd_pass);
	} else {
		log_error(ID(worker_proxy_res), "Received response from worker, but database synchronization handle missing.");
		r = -1;
	}

	return r;
}

static int _worker_recv_fn(sid_resource_t *worker_res, struct worker_channel *chan, struct worker_data_spec *data_spec, void *arg)
{
	if (data_spec->ext.used) {
		if (!sid_resource_create(worker_res,
		                         &sid_resource_type_ubridge_connection,
		                         SID_RESOURCE_NO_FLAGS,
		                         SID_RESOURCE_NO_CUSTOM_ID,
		                         data_spec,
		                         SID_RESOURCE_PRIO_NORMAL,
		                         SID_RESOURCE_NO_SERVICE_LINKS)) {
			log_error(ID(worker_res), "Failed to create connection resource.");
			return -1;
		}
	} else {
		log_error(ID(worker_res), "Received command from worker proxy, but connection handle missing.");
		return -1;
	}

	return 0;
}

static int _worker_init_fn(sid_resource_t *worker_res, void *arg)
{
	sid_resource_t *ubridge_internal_res = arg;
	sid_resource_t *modules_res, *kv_store_res;

	if (!(modules_res = sid_resource_search(ubridge_internal_res,
	                                        SID_RESOURCE_SEARCH_IMM_DESC,
	                                        &sid_resource_type_aggregate,
	                                        MODULES_AGGREGATE_ID)))
		return -ENOMEDIUM;

	if (!(kv_store_res = sid_resource_search(ubridge_internal_res,
	                                         SID_RESOURCE_SEARCH_IMM_DESC,
	                                         &sid_resource_type_kv_store,
	                                         MAIN_KV_STORE_NAME)))
		return -ENOMEDIUM;

	/* we take only inherited modules and kv_store for the worker */
	(void) sid_resource_isolate_with_children(modules_res);
	(void) sid_resource_isolate_with_children(kv_store_res);

	(void) sid_resource_add_child(worker_res, modules_res, SID_RESOURCE_NO_FLAGS);
	(void) sid_resource_add_child(worker_res, kv_store_res, SID_RESOURCE_RESTRICT_WALK_UP);

	/* destroy the rest */
	(void) sid_resource_unref(sid_resource_search(ubridge_internal_res, SID_RESOURCE_SEARCH_TOP, NULL, NULL));

	return 0;
}

static int _on_ubridge_interface_event(sid_resource_event_source_t *es, int fd, uint32_t revents, void *data)
{
	char                    uuid[UTIL_UUID_STR_SIZE];
	util_mem_t              mem                  = {.base = uuid, .size = sizeof(uuid)};
	sid_resource_t *        internal_ubridge_res = data;
	sid_resource_t *        worker_control_res, *worker_proxy_res;
	struct ubridge *        ubridge = sid_resource_get_data(internal_ubridge_res);
	struct worker_data_spec data_spec;
	int                     r;

	log_debug(ID(internal_ubridge_res), "Received an event.");

	if (!(worker_control_res = sid_resource_search(internal_ubridge_res,
	                                               SID_RESOURCE_SEARCH_IMM_DESC,
	                                               &sid_resource_type_worker_control,
	                                               NULL))) {
		log_error(ID(internal_ubridge_res), INTERNAL_ERROR "%s: Failed to find worker control resource.", __func__);
		return -1;
	}

	if (!(worker_proxy_res = worker_control_get_idle_worker(worker_control_res))) {
		log_debug(ID(internal_ubridge_res), "Idle worker not found, creating a new one.");

		if (!util_uuid_gen_str(&mem)) {
			log_error(ID(internal_ubridge_res), "Failed to generate UUID for new worker.");
			return -1;
		}

		if (!(worker_proxy_res = worker_control_get_new_worker(worker_control_res, &((struct worker_params) {.id = uuid}))))
			return -1;
	}

	/* worker never reaches this point, only worker-proxy does */

	data_spec.data      = NULL;
	data_spec.data_size = 0;
	data_spec.ext.used  = true;

	if ((data_spec.ext.socket.fd_pass = accept4(ubridge->socket_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC)) < 0) {
		log_sys_error(ID(internal_ubridge_res), "accept", "");
		return -1;
	}

	if ((r = worker_control_channel_send(worker_proxy_res, MAIN_WORKER_CHANNEL_ID, &data_spec)) < 0) {
		log_error_errno(ID(internal_ubridge_res), r, "worker_control_channel_send");
		(void) close(data_spec.ext.socket.fd_pass);
		return -1;
	}

	(void) close(data_spec.ext.socket.fd_pass);
	return 0;
}

static int _on_ubridge_udev_monitor_event(sid_resource_event_source_t *es, int fd, uint32_t revents, void *data)
{
	sid_resource_t *    internal_ubridge_res = data;
	struct ubridge *    ubridge              = sid_resource_get_data(internal_ubridge_res);
	sid_resource_t *    worker_control_res;
	struct udev_device *udev_dev;
	const char *        worker_id;
	int                 r = -1;

	if (!(udev_dev = udev_monitor_receive_device(ubridge->umonitor.mon)))
		goto out;

	if (!(worker_id = udev_device_get_property_value(udev_dev, KV_KEY_UDEV_SID_SESSION_ID)))
		goto out;

	if (!(worker_control_res = sid_resource_search(internal_ubridge_res,
	                                               SID_RESOURCE_SEARCH_IMM_DESC,
	                                               &sid_resource_type_worker_control,
	                                               NULL)))
		goto out;

	if (!worker_control_find_worker(worker_control_res, worker_id))
		goto out;

	r = 0;
out:
	if (udev_dev)
		udev_device_unref(udev_dev);
	return r;
}

static void _destroy_udev_monitor(sid_resource_t *ubridge_res, struct umonitor *umonitor)
{
	if (!umonitor->udev)
		return;

	if (umonitor->mon) {
		udev_monitor_unref(umonitor->mon);
		umonitor->mon = NULL;
	}

	udev_unref(umonitor->udev);
	umonitor->udev = NULL;
}

static int _set_up_ubridge_socket(sid_resource_t *ubridge_res, int *ubridge_socket_fd)
{
	char *val;
	int   fd;

	if (service_fd_activation_present(1)) {
		if (!(val = getenv(SERVICE_KEY_ACTIVATION_TYPE))) {
			log_error(ID(ubridge_res), "Missing %s key in environment.", SERVICE_KEY_ACTIVATION_TYPE);
			return -ENOKEY;
		}

		if (strcmp(val, SERVICE_VALUE_ACTIVATION_FD)) {
			log_error(ID(ubridge_res), "Incorrect value for key %s: %s.", SERVICE_VALUE_ACTIVATION_FD, val);
			return -EINVAL;
		}

		/* The very first FD passed in is the one we are interested in. */
		fd = SERVICE_FD_ACTIVATION_FDS_START;

		if (!(service_fd_is_socket_unix(fd, SOCK_STREAM, 1, SID_SOCKET_PATH, SID_SOCKET_PATH_LEN))) {
			log_error(ID(ubridge_res), "Passed file descriptor is of incorrect type.");
			return -EINVAL;
		}
	} else {
		/* No systemd autoactivation - create new socket FD. */
		if ((fd = sid_comms_unix_create(SID_SOCKET_PATH, SID_SOCKET_PATH_LEN, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC)) <
		    0) {
			log_error_errno(ID(ubridge_res), fd, "Failed to create local server socket");
			return fd;
		}
	}

	*ubridge_socket_fd = fd;
	return 0;
}

static int _set_up_udev_monitor(sid_resource_t *ubridge_res, sid_resource_t *internal_ubridge_res, struct umonitor *umonitor)
{
	int umonitor_fd = -1;

	if (!(umonitor->udev = udev_new())) {
		log_error(ID(ubridge_res), "Failed to create udev handle.");
		goto fail;
	}

	if (!(umonitor->mon = udev_monitor_new_from_netlink(umonitor->udev, "udev"))) {
		log_error(ID(ubridge_res), "Failed to create udev monitor.");
		goto fail;
	}

	if (udev_monitor_filter_add_match_tag(umonitor->mon, UDEV_TAG_SID) < 0) {
		log_error(ID(ubridge_res), "Failed to create tag filter.");
		goto fail;
	}

	umonitor_fd = udev_monitor_get_fd(umonitor->mon);

	if (sid_resource_create_io_event_source(ubridge_res,
	                                        NULL,
	                                        umonitor_fd,
	                                        _on_ubridge_udev_monitor_event,
	                                        0,
	                                        "udev monitor",
	                                        internal_ubridge_res) < 0) {
		log_error(ID(ubridge_res), "Failed to register udev monitoring.");
		goto fail;
	}

	if (udev_monitor_enable_receiving(umonitor->mon) < 0) {
		log_error(ID(ubridge_res), "Failed to enable udev monitoring.");
		goto fail;
	}

	return 0;
fail:
	_destroy_udev_monitor(ubridge_res, umonitor);
	return -1;
}

static struct module_symbol_params block_symbol_params[] = {{
								    SID_UCMD_MOD_FN_NAME_IDENT,
								    MODULE_SYMBOL_INDIRECT,
							    },
                                                            {
								    SID_UCMD_MOD_FN_NAME_SCAN_PRE,
								    MODULE_SYMBOL_INDIRECT,
							    },
                                                            {
								    SID_UCMD_MOD_FN_NAME_SCAN_CURRENT,
								    MODULE_SYMBOL_INDIRECT,
							    },
                                                            {
								    SID_UCMD_MOD_FN_NAME_SCAN_NEXT,
								    MODULE_SYMBOL_INDIRECT,
							    },
                                                            {
								    SID_UCMD_MOD_FN_NAME_SCAN_POST_CURRENT,
								    MODULE_SYMBOL_INDIRECT,
							    },
                                                            {
								    SID_UCMD_MOD_FN_NAME_SCAN_POST_NEXT,
								    MODULE_SYMBOL_INDIRECT,
							    },
                                                            {
								    SID_UCMD_MOD_FN_NAME_TRIGGER_ACTION_CURRENT,
								    MODULE_SYMBOL_INDIRECT,
							    },
                                                            {
								    SID_UCMD_MOD_FN_NAME_TRIGGER_ACTION_NEXT,
								    MODULE_SYMBOL_INDIRECT,
							    },
                                                            {
								    SID_UCMD_MOD_FN_NAME_ERROR,
								    MODULE_SYMBOL_FAIL_ON_MISSING | MODULE_SYMBOL_INDIRECT,
							    },
                                                            NULL_MODULE_SYMBOL_PARAMS};

static struct module_symbol_params type_symbol_params[] = {{
								   SID_UCMD_MOD_FN_NAME_IDENT,
								   MODULE_SYMBOL_FAIL_ON_MISSING | MODULE_SYMBOL_INDIRECT,
							   },
                                                           {
								   SID_UCMD_MOD_FN_NAME_SCAN_PRE,
								   MODULE_SYMBOL_INDIRECT,
							   },
                                                           {
								   SID_UCMD_MOD_FN_NAME_SCAN_CURRENT,
								   MODULE_SYMBOL_INDIRECT,
							   },
                                                           {
								   SID_UCMD_MOD_FN_NAME_SCAN_NEXT,
								   MODULE_SYMBOL_INDIRECT,
							   },
                                                           {
								   SID_UCMD_MOD_FN_NAME_SCAN_POST_CURRENT,
								   MODULE_SYMBOL_INDIRECT,
							   },
                                                           {
								   SID_UCMD_MOD_FN_NAME_SCAN_POST_NEXT,
								   MODULE_SYMBOL_INDIRECT,
							   },
                                                           {
								   SID_UCMD_MOD_FN_NAME_TRIGGER_ACTION_CURRENT,
								   MODULE_SYMBOL_INDIRECT,
							   },
                                                           {
								   SID_UCMD_MOD_FN_NAME_TRIGGER_ACTION_NEXT,
								   MODULE_SYMBOL_INDIRECT,
							   },
                                                           {
								   SID_UCMD_MOD_FN_NAME_ERROR,
								   MODULE_SYMBOL_FAIL_ON_MISSING | MODULE_SYMBOL_INDIRECT,
							   },
                                                           NULL_MODULE_SYMBOL_PARAMS};

static const struct sid_kv_store_resource_params main_kv_store_res_params = {.backend           = KV_STORE_BACKEND_HASH,
                                                                             .hash.initial_size = 32};

static int _init_ubridge(sid_resource_t *res, const void *kickstart_data, void **data)
{
	struct ubridge *ubridge = NULL;
	sid_resource_t *internal_res, *kv_store_res, *modules_res;
	struct buffer * buf;
	int             r;

	if (!(ubridge = mem_zalloc(sizeof(struct ubridge)))) {
		log_error(ID(res), "Failed to allocate memory for ubridge structure.");
		goto fail;
	}
	ubridge->socket_fd = -1;

	if (!(internal_res = sid_resource_create(res,
	                                         &sid_resource_type_aggregate,
	                                         SID_RESOURCE_RESTRICT_WALK_DOWN | SID_RESOURCE_DISALLOW_ISOLATION,
	                                         INTERNAL_AGGREGATE_ID,
	                                         ubridge,
	                                         SID_RESOURCE_PRIO_NORMAL,
	                                         SID_RESOURCE_NO_SERVICE_LINKS))) {
		log_error(ID(res), "Failed to create internal ubridge resource.");
		goto fail;
	}

	if (!(kv_store_res = sid_resource_create(internal_res,
	                                         &sid_resource_type_kv_store,
	                                         SID_RESOURCE_RESTRICT_WALK_UP,
	                                         MAIN_KV_STORE_NAME,
	                                         &main_kv_store_res_params,
	                                         SID_RESOURCE_PRIO_NORMAL,
	                                         SID_RESOURCE_NO_SERVICE_LINKS))) {
		log_error(ID(res), "Failed to create main key-value store.");
		goto fail;
	}

	struct worker_channel_spec channel_specs[] = {
		{
			.id = MAIN_WORKER_CHANNEL_ID,

			.wire =
				(struct worker_wire_spec) {
					.type = WORKER_WIRE_SOCKET,
				},

			.worker_tx_cb = NULL_WORKER_CHANNEL_CB_SPEC,
			.worker_rx_cb =
				(struct worker_channel_cb_spec) {
					.cb  = _worker_recv_fn,
					.arg = NULL,
				},

			.proxy_tx_cb = NULL_WORKER_CHANNEL_CB_SPEC,
			.proxy_rx_cb =
				(struct worker_channel_cb_spec) {
					.cb  = _worker_proxy_recv_fn,
					.arg = internal_res,
				},
		},
		NULL_WORKER_CHANNEL_SPEC,
	};

	struct worker_control_resource_params worker_control_res_params = {
		.worker_type = WORKER_TYPE_INTERNAL,

		.init_cb_spec =
			(struct worker_init_cb_spec) {
				.cb  = _worker_init_fn,
				.arg = internal_res,
			},

		.channel_specs = channel_specs,
	};

	if (!sid_resource_create(internal_res,
	                         &sid_resource_type_worker_control,
	                         SID_RESOURCE_NO_FLAGS,
	                         SID_RESOURCE_NO_CUSTOM_ID,
	                         &worker_control_res_params,
	                         SID_RESOURCE_PRIO_NORMAL,
	                         SID_RESOURCE_NO_SERVICE_LINKS)) {
		log_error(ID(res), "Failed to create worker control.");
		goto fail;
	}

	if (!(buf = sid_buffer_create(&((struct buffer_spec) {.backend = BUFFER_BACKEND_MALLOC,
	                                                      .type    = BUFFER_TYPE_LINEAR,
	                                                      .mode    = BUFFER_MODE_PLAIN}),
	                              &((struct buffer_init) {.size = 0, .alloc_step = PATH_MAX, .limit = 0}),
	                              &r))) {
		log_error_errno(ID(res), r, "Failed to create generic buffer");
		goto fail;
	}

	if (!(modules_res = sid_resource_create(internal_res,
	                                        &sid_resource_type_aggregate,
	                                        SID_RESOURCE_NO_FLAGS,
	                                        MODULES_AGGREGATE_ID,
	                                        SID_RESOURCE_NO_PARAMS,
	                                        SID_RESOURCE_PRIO_NORMAL,
	                                        SID_RESOURCE_NO_SERVICE_LINKS))) {
		log_error(ID(res), "Failed to create aggreagete resource for module handlers.");
		goto fail;
	}

	ubridge->ucmd_mod_ctx = (struct sid_ucmd_mod_ctx) {
		.kv_store_res = kv_store_res,
		.modules_res  = modules_res,
		.gen_buf      = buf,
	};

	struct module_registry_resource_params block_res_mod_params = {
		.directory     = SID_UCMD_BLOCK_MOD_DIR,
		.module_prefix = NULL,
		.module_suffix = ".so",
		.flags         = MODULE_REGISTRY_PRELOAD,
		.symbol_params = block_symbol_params,
		.cb_arg        = &ubridge->ucmd_mod_ctx,
	};

	struct module_registry_resource_params type_res_mod_params = {
		.directory     = SID_UCMD_TYPE_MOD_DIR,
		.module_prefix = NULL,
		.module_suffix = ".so",
		.flags         = MODULE_REGISTRY_PRELOAD,
		.symbol_params = type_symbol_params,
		.cb_arg        = &ubridge->ucmd_mod_ctx,
	};

	if (!(sid_resource_create(modules_res,
	                          &sid_resource_type_module_registry,
	                          SID_RESOURCE_DISALLOW_ISOLATION,
	                          MODULES_BLOCK_ID,
	                          &block_res_mod_params,
	                          SID_RESOURCE_PRIO_NORMAL,
	                          SID_RESOURCE_NO_SERVICE_LINKS)) ||
	    !(sid_resource_create(modules_res,
	                          &sid_resource_type_module_registry,
	                          SID_RESOURCE_DISALLOW_ISOLATION,
	                          MODULES_TYPE_ID,
	                          &type_res_mod_params,
	                          SID_RESOURCE_PRIO_NORMAL,
	                          SID_RESOURCE_NO_SERVICE_LINKS))) {
		log_error(ID(res), "Failed to create module handler.");
		goto fail;
	}

	if (_set_up_ubridge_socket(res, &ubridge->socket_fd) < 0) {
		log_error(ID(res), "Failed to set up local server socket.");
		goto fail;
	}

	if (sid_resource_create_io_event_source(res,
	                                        NULL,
	                                        ubridge->socket_fd,
	                                        _on_ubridge_interface_event,
	                                        0,
	                                        UBRIDGE_NAME,
	                                        internal_res) < 0) {
		log_error(ID(res), "Failed to register interface with event loop.");
		goto fail;
	}

	if (_set_up_udev_monitor(res, internal_res, &ubridge->umonitor) < 0) {
		log_error(ID(res), "Failed to set up udev monitor.");
		goto fail;
	}

	/*
	 * Call util_cmdline_get_arg here to only read the kernel command line
	 * so we already have that preloaded for any possible workers.
	 */
	(void) util_cmdline_get_arg("root", NULL, NULL);

	*data = ubridge;
	return 0;
fail:
	if (ubridge) {
		if (ubridge->ucmd_mod_ctx.gen_buf)
			sid_buffer_destroy(ubridge->ucmd_mod_ctx.gen_buf);
		if (ubridge->socket_fd >= 0)
			(void) close(ubridge->socket_fd);
		free(ubridge);
	}
	return -1;
}

static int _destroy_ubridge(sid_resource_t *res)
{
	struct ubridge *ubridge = sid_resource_get_data(res);

	_destroy_udev_monitor(res, &ubridge->umonitor);

	if (ubridge->ucmd_mod_ctx.gen_buf)
		sid_buffer_destroy(ubridge->ucmd_mod_ctx.gen_buf);

	if (ubridge->socket_fd != -1)
		(void) close(ubridge->socket_fd);

	free(ubridge);
	return 0;
}

const sid_resource_type_t sid_resource_type_ubridge_command = {
	.name    = COMMAND_NAME,
	.init    = _init_command,
	.destroy = _destroy_command,
};

const sid_resource_type_t sid_resource_type_ubridge_connection = {
	.name    = CONNECTION_NAME,
	.init    = _init_connection,
	.destroy = _destroy_connection,
};

const sid_resource_type_t sid_resource_type_ubridge = {
	.name    = UBRIDGE_NAME,
	.init    = _init_ubridge,
	.destroy = _destroy_ubridge,
};
