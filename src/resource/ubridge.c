/*
 * This file is part of SID.
 *
 * Copyright (C) 2017-2019 Red Hat, Inc. All rights reserved.
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
#include "configure.h"
#include "bitmap.h"
#include "buffer.h"
#include "comms.h"
#include "kv-store.h"
#include "log.h"
#include "macros.h"
#include "mem.h"
#include "module-registry.h"
#include "resource.h"
#include "ubridge-cmd-module.h"
#include "usid-iface.h"
#include "util.h"
#include "worker-control.h"

#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <libudev.h>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>


#define UBRIDGE_NAME                 "ubridge"
#define CONNECTION_NAME              "connection"
#define COMMAND_NAME                 "command"

#define INTERNAL_AGGREGATE_ID        "ubridge-internal"
#define MODULES_AGGREGATE_ID         "modules"
#define MODULES_BLOCK_ID             "block"
#define MODULES_TYPE_ID              "type"

#define UDEV_TAG_SID                 "sid"
#define KV_KEY_UDEV_SID_SESSION_ID   "SID_SESSION_ID"

#define COMMAND_STATUS_MASK_OVERALL  UINT64_C(0x0000000000000001)
#define COMMAND_STATUS_SUCCESS       UINT64_C(0x0000000000000000)
#define COMMAND_STATUS_FAILURE       UINT64_C(0x0000000000000001)

#define UBRIDGE_CMD_BLOCK_MODULE_DIRECTORY LIBDIR "/" PACKAGE "/modules/ubridge-cmd/block"
#define UBRIDGE_CMD_TYPE_MODULE_DIRECTORY  LIBDIR "/" PACKAGE "/modules/ubridge-cmd/type"

#define UBRIDGE_CMD_MODULE_FN_NAME_IDENT                  "sid_ubridge_cmd_ident"
#define UBRIDGE_CMD_MODULE_FN_NAME_SCAN_PRE               "sid_ubridge_cmd_scan_pre"
#define UBRIDGE_CMD_MODULE_FN_NAME_SCAN_CURRENT           "sid_ubridge_cmd_scan_current"
#define UBRIDGE_CMD_MODULE_FN_NAME_SCAN_NEXT              "sid_ubridge_cmd_scan_next"
#define UBRIDGE_CMD_MODULE_FN_NAME_SCAN_POST_CURRENT      "sid_ubridge_cmd_scan_post_current"
#define UBRIDGE_CMD_MODULE_FN_NAME_SCAN_POST_NEXT         "sid_ubridge_cmd_scan_post_next"

#define UBRIDGE_CMD_MODULE_FN_NAME_ERROR                  "sid_ubridge_cmd_error"
#define UBRIDGE_CMD_MODULE_FN_NAME_TRIGGER_ACTION_CURRENT "sid_ubridge_cmd_trigger_action_current"
#define UBRIDGE_CMD_MODULE_FN_NAME_TRIGGER_ACTION_NEXT    "sid_ubridge_cmd_trigger_action_next"

#define MAIN_KV_STORE_NAME  "main"

#define KV_PAIR_C           "="
#define KV_END_C            ""

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

#define KEY_SYS_C                "#"

#define KV_KEY_DEV_READY         KEY_SYS_C "RDY"
#define KV_KEY_DEV_RESERVED      KEY_SYS_C "RES"
#define KV_KEY_DEV_MOD           KEY_SYS_C "MOD"
#define KV_KEY_DEV_NEXT_MOD      SID_UBRIDGE_CMD_KEY_DEVICE_NEXT_MOD

#define KV_KEY_DOM_LAYER         "LYR"
#define KV_KEY_DOM_USER          "USR"

#define KV_KEY_GEN_GROUP_MEMBERS KEY_SYS_C "GMB"
#define KV_KEY_GEN_GROUP_IN      KEY_SYS_C "GIN"

#define MOD_NAME_CORE         "core"
#define OWNER_CORE             MOD_NAME_CORE
#define DEFAULT_KV_FLAGS_CORE  KV_PERSISTENT | KV_MOD_RESERVED | KV_MOD_PRIVATE

#define UDEV_KEY_ACTION     "ACTION"
#define UDEV_KEY_DEVPATH    "DEVPATH"
#define UDEV_KEY_DEVTYPE    "DEVTYPE"
#define UDEV_KEY_MAJOR      "MAJOR"
#define UDEV_KEY_MINOR      "MINOR"
#define UDEV_KEY_SEQNUM     "SEQNUM"
#define UDEV_KEY_SYNTH_UUID "SYNTH_UUID"

#define UDEV_VALUE_DEVTYPE_DISK      "disk"
#define UDEV_VALUE_DEVTYPE_PARTITION "partition"

#define CMD_DEV_ID_FMT  "%s (%d:%d)"
#define CMD_DEV_ID(cmd) cmd->udev_dev.name, cmd->udev_dev.major, cmd->udev_dev.minor

/* internal resources */
const sid_resource_type_t sid_resource_type_ubridge_connection;
const sid_resource_type_t sid_resource_type_ubridge_command;

struct sid_ubridge_cmd_mod_context {
	sid_resource_t *kv_store_res;
	struct buffer *gen_buf;
};

struct umonitor {
	struct udev *udev;
	struct udev_monitor *mon;
};

struct ubridge {
	int socket_fd;
	sid_resource_t *internal_res;
	sid_resource_t *modules_res;
	sid_resource_t *main_kv_store_res;
	sid_resource_t *worker_control_res;
	struct sid_ubridge_cmd_mod_context cmd_mod;
	struct umonitor umonitor;
};

typedef enum {
	CMD_SCAN_PHASE_A_INIT = 0,                                     /* initializing phase "A" */

	__CMD_SCAN_PHASE_A_START = 1,                                  /* phase "A" module processing starts */
	CMD_SCAN_PHASE_A_IDENT = __CMD_SCAN_PHASE_A_START,             /* module */
	CMD_SCAN_PHASE_A_SCAN_PRE,                                     /* module */
	CMD_SCAN_PHASE_A_SCAN_CURRENT,                                 /* module */
	CMD_SCAN_PHASE_A_SCAN_NEXT,                                    /* module */
	CMD_SCAN_PHASE_A_SCAN_POST_CURRENT,                            /* module */
	CMD_SCAN_PHASE_A_SCAN_POST_NEXT,                               /* module */
	__CMD_SCAN_PHASE_A_END = CMD_SCAN_PHASE_A_SCAN_POST_NEXT,     /* phase "A" module processing ends */

	CMD_SCAN_PHASE_A_WAITING,                                      /* phase "A" waiting for confirmation */

	CMD_SCAN_PHASE_A_EXIT,                                         /* exiting phase "A" */

	CMD_SCAN_PHASE_B_TRIGGER_ACTION_CURRENT,
	__CMD_SCAN_PHASE_B_TRIGGER_ACTION_START = CMD_SCAN_PHASE_B_TRIGGER_ACTION_CURRENT,
	CMD_SCAN_PHASE_B_TRIGGER_ACTION_NEXT,
	__CMD_SCAN_PHASE_B_TRIGGER_ACTION_END = CMD_SCAN_PHASE_B_TRIGGER_ACTION_NEXT,

	CMD_SCAN_PHASE_ERROR,
} cmd_scan_phase_t;

struct udevice {
	udev_action_t action;
	udev_devtype_t type;
	const char *path;
	const char *name; /* just a pointer to devpath's last element */
	int major;
	int minor;
	uint64_t seqnum;
	const char *synth_uuid;
};

struct connection {
	int fd;
	struct buffer *buf;
};

struct sid_ubridge_cmd_context {
	struct usid_msg_header request_header;
	union {
		cmd_scan_phase_t scan_phase;
	};
	char *dev_id;
	struct udevice udev_dev;
	sid_resource_t *kv_store_res;
	sid_resource_t *mod_res; /* the module that is processed at the moment */
	struct buffer *gen_buf;
	struct buffer *res_buf;

};

struct cmd_mod_fns {
	sid_ubridge_cmd_fn_t *ident;
	sid_ubridge_cmd_fn_t *scan_pre;
	sid_ubridge_cmd_fn_t *scan_current;
	sid_ubridge_cmd_fn_t *scan_next;
	sid_ubridge_cmd_fn_t *scan_post_current;
	sid_ubridge_cmd_fn_t *scan_post_next;
	sid_ubridge_cmd_fn_t *trigger_action_current;
	sid_ubridge_cmd_fn_t *trigger_action_next;
	sid_ubridge_cmd_fn_t *error;
} __attribute__((packed));

struct cmd_exec_arg {
	sid_resource_t *cmd_res;
	sid_resource_t *type_mod_registry_res;
	sid_resource_iter_t *block_mod_iter;  /* all block modules to execute */
	sid_resource_t *type_mod_res_current; /* one type module for current layer to execute */
	sid_resource_t *type_mod_res_next;    /* one type module for next layer to execute */
};

struct cmd_reg {
	const char *name;
	uint32_t flags;
	int (*exec) (struct cmd_exec_arg *exec_arg);
};

struct kv_value {
	uint64_t seqnum;
	sid_ubridge_kv_flags_t flags;
	char data[0]; /* contains both internal and external data */
} __attribute__((packed));

enum {
	KV_VALUE_IDX_SEQNUM,
	KV_VALUE_IDX_FLAGS,
	KV_VALUE_IDX_OWNER,
	KV_VALUE_IDX_DATA,
	_KV_VALUE_IDX_COUNT,
};

#define KV_VALUE_PREPARE_HEADER(iov, seqnum, flags, owner) \
		iov[KV_VALUE_IDX_SEQNUM] = (struct iovec) {&(seqnum), sizeof(seqnum)}; \
		iov[KV_VALUE_IDX_FLAGS] = (struct iovec) {&(flags), sizeof(flags)}; \
		iov[KV_VALUE_IDX_OWNER] = (struct iovec) {owner, strlen(owner) + 1};

#define KV_VALUE_SEQNUM(iov) (*((uint64_t *) ((struct iovec *) iov)[KV_VALUE_IDX_SEQNUM].iov_base))
#define KV_VALUE_FLAGS(iov) (*((sid_ubridge_kv_flags_t *) ((struct iovec *) iov)[KV_VALUE_IDX_FLAGS].iov_base))
#define KV_VALUE_OWNER(iov) ((char *) ((struct iovec *) iov)[KV_VALUE_IDX_OWNER].iov_base)
#define KV_VALUE_DATA(iov) (((struct iovec *) iov)[KV_VALUE_IDX_DATA].iov_base)

struct kv_update_arg {
	sid_resource_t *res;
	struct buffer *gen_buf;
	const char *owner; /* in */
	void *custom;	      /* in/out */
	int ret_code;	      /* out */
};

typedef enum {
	KV_OP_ILLEGAL, /* illegal operation */
	KV_OP_SET,     /* set value for kv */
	KV_OP_PLUS,    /* add value to vector kv */
	KV_OP_MINUS,   /* remove value fomr vector kv */
} kv_op_t;

typedef enum {
	DELTA_NO_FLAGS  = 0x0,
	DELTA_WITH_DIFF = 0x1,
	DELTA_WITH_REL  = 0x2,
} delta_flags_t;

struct kv_delta {
	kv_op_t op;
	delta_flags_t flags;
	struct buffer *plus;
	struct buffer *minus;
	struct buffer *final;
};

typedef enum {
	__KEY_PART_START = 0x0,
	KEY_PART_OP      = 0x0,
	KEY_PART_NS      = 0x1,
	KEY_PART_NS_PART = 0x2,
	KEY_PART_DOM     = 0x3,
	KEY_PART_ID      = 0x4,
	KEY_PART_ID_PART = 0x5,
	KEY_PART_CORE    = 0x6,
	__KEY_PART_COUNT,
} key_part_t;

struct kv_key_spec {
	kv_op_t op;
	sid_ubridge_cmd_kv_namespace_t ns;
	const char *ns_part;
	const char *dom;
	const char *id;
	const char *id_part;
	const char *key;
};

struct kv_rel_spec {
	struct kv_delta *delta;
	struct kv_key_spec *cur_key_spec;
	struct kv_key_spec *rel_key_spec;
};

struct kv_key_res_def {
	sid_ubridge_cmd_kv_namespace_t ns;
	const char *key;
};

struct cross_bitmap_calc_arg {
	struct iovec *old_value;
	size_t old_size;
	struct bitmap *old_bmp;
	struct iovec *new_value;
	size_t new_size;
	struct bitmap *new_bmp;
};

#define CMD_SCAN_CAP_RDY UINT32_C(0x000000001) /* can set ready state */
#define CMD_SCAN_CAP_RES UINT32_C(0x000000002) /* can set reserved state */

static struct cmd_reg _cmd_scan_phase_regs[];
static sid_ubridge_kv_flags_t kv_flags_no_persist = (DEFAULT_KV_FLAGS_CORE) & ~KV_PERSISTENT;
static sid_ubridge_kv_flags_t kv_flags_persist = DEFAULT_KV_FLAGS_CORE;
static char *core_owner = OWNER_CORE;

static int _kv_delta(const char *full_key, struct kv_store_update_spec *spec, void *garg);
static const char _key_prefix_err_msg[] = "Failed to get key prefix to store hierarchy records for device " CMD_DEV_ID_FMT ".";

udev_action_t sid_ubridge_cmd_dev_get_action(struct sid_ubridge_cmd_context *cmd)
{
	return cmd->udev_dev.action;
}

int sid_ubridge_cmd_cmd_dev_get_major(struct sid_ubridge_cmd_context *cmd)
{
	return cmd->udev_dev.major;
}

int sid_ubridge_cmd_cmd_dev_get_minor(struct sid_ubridge_cmd_context *cmd)
{
	return cmd->udev_dev.minor;
}

const char *sid_ubridge_cmd_dev_get_name(struct sid_ubridge_cmd_context *cmd)
{
	return cmd->udev_dev.name;
}

udev_devtype_t sid_ubridge_cmd_dev_get_type(struct sid_ubridge_cmd_context *cmd)
{
	return cmd->udev_dev.type;
}

uint64_t sid_ubridge_cmd_dev_get_seqnum(struct sid_ubridge_cmd_context *cmd)
{
	return cmd->udev_dev.seqnum;
}

const char *sid_ubridge_cmd_dev_get_synth_uuid(struct sid_ubridge_cmd_context *cmd)
{
	return cmd->udev_dev.synth_uuid;
}

static const char *_do_buffer_compose_key(struct buffer *buf, struct kv_key_spec *spec, int prefix_only)
{
	static const char *op_to_key_prefix_map[] = {[KV_OP_ILLEGAL]   = KV_PREFIX_OP_ILLEGAL_C,
	                                             [KV_OP_SET]       = KV_PREFIX_OP_SET_C,
	                                             [KV_OP_PLUS]      = KV_PREFIX_OP_PLUS_C,
	                                             [KV_OP_MINUS]     = KV_PREFIX_OP_MINUS_C
	                                            };

	static const char *ns_to_key_prefix_map[] = {[KV_NS_UNDEFINED] = KV_PREFIX_NS_UNDEFINED_C,
	                                             [KV_NS_UDEV]      = KV_PREFIX_NS_UDEV_C,
	                                             [KV_NS_DEVICE]    = KV_PREFIX_NS_DEVICE_C,
	                                             [KV_NS_MODULE]    = KV_PREFIX_NS_MODULE_C,
	                                             [KV_NS_GLOBAL]    = KV_PREFIX_NS_GLOBAL_C
	                                            };

	/* <op>:<ns>:<ns_part>:<id>:<id_part>[:<key>] */

	return buffer_fmt_add(buf, "%s" KV_STORE_KEY_JOIN /* op */
	                      "%s" KV_STORE_KEY_JOIN /* ns */
	                      "%s" KV_STORE_KEY_JOIN /* ns_part */
	                      "%s" KV_STORE_KEY_JOIN /* dom */
	                      "%s" KV_STORE_KEY_JOIN /* id */
	                      "%s" "%s"              /* id_part */
	                      "%s",
	                      op_to_key_prefix_map[spec->op],
	                      ns_to_key_prefix_map[spec->ns],
	                      spec->ns_part,
	                      spec->dom,
	                      spec->id,
	                      spec->id_part,
	                      prefix_only ? KEY_NULL : KV_STORE_KEY_JOIN,
	                      prefix_only ? KEY_NULL : spec->key);
}

static const char *_buffer_compose_key(struct buffer *buf, struct kv_key_spec *spec)
{
	/* <op>:<ns>:<ns_part>:<dom>:<id>:<id_part>:<key> */
	return _do_buffer_compose_key(buf, spec, 0);
}

static const char *_buffer_compose_key_prefix(struct buffer *buf, struct kv_key_spec *spec)
{
	/* <op>:<ns>:<ns_part>:<dom>:<id>:<id_part> */
	return _do_buffer_compose_key(buf, spec, 1);
}

static const char *_get_key_part(const char *key, key_part_t req_part, size_t *len)
{
	key_part_t part;
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
	size_t len;

	/* |<>|
	 * <op>:<ns>:<ns_part>:<dom>:<id>:<id_part>[:<key>]
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

static sid_ubridge_cmd_kv_namespace_t _get_ns_from_key(const char *key)
{
	const char *str;
	size_t len;

	/*      |<>|
	 * <op>:<ns>:<ns_part>:<dom>:<id>:<id_part>[:<key>]
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
	size_t len;

	/*           |<----->|
	   <op>:<ns>:<ns_part>:<dom>:<id>:<id_part>[:<key>]
	*/

	if (!(str = _get_key_part(key, KEY_PART_NS_PART, &len)))
		return NULL;

	return buffer_fmt_add(buf, "%.*s", len, str);
}

static struct iovec *_get_value_vector(kv_store_value_flags_t flags, void *value, size_t value_size, struct iovec *iov)
{
	size_t owner_size;
	struct kv_value *kv_value;

	if (!value)
		return NULL;

	if (flags & KV_STORE_VALUE_VECTOR)
		return value;

	kv_value = value;
	owner_size = strlen(kv_value->data) + 1;

	KV_VALUE_PREPARE_HEADER(iov, kv_value->seqnum, kv_value->flags, kv_value->data)
	iov[KV_VALUE_IDX_DATA] = (struct iovec) {
		kv_value->data + owner_size, value_size - sizeof(*kv_value) - owner_size
	};

	return iov;
}

static void _dump_kv_store(const char *str, sid_resource_t *kv_store_res)
{
	kv_store_iter_t *iter;
	size_t size;
	kv_store_value_flags_t flags;
	void *value;
	struct iovec tmp_iov[_KV_VALUE_IDX_COUNT];
	struct iovec *iov;
	unsigned int i = 0, j;

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
		log_print(ID(kv_store_res), "      seqnum: %" PRIu64 "  flags: %s%s%s%s  owner: %s",
		          KV_VALUE_SEQNUM(iov),
		          KV_VALUE_FLAGS(iov) & KV_PERSISTENT ? "KV_PERSISTENT " : "",
		          KV_VALUE_FLAGS(iov) & KV_MOD_PROTECTED ? "KV_MOD_PROTECTED " : "",
		          KV_VALUE_FLAGS(iov) & KV_MOD_PRIVATE ? "KV_MOD_PRIVATE " : "",
		          KV_VALUE_FLAGS(iov) & KV_MOD_RESERVED ? "KV_MOD_RESERVED ": "",
		          KV_VALUE_OWNER(iov));
		log_print(ID(kv_store_res), "      value: %s", flags & KV_STORE_VALUE_VECTOR ? "vector" : (const char *) KV_VALUE_DATA(iov));
		if (flags & KV_STORE_VALUE_VECTOR) {
			for (j = KV_VALUE_IDX_DATA; j < size; j++)
				log_print(ID(kv_store_res), "        [%u] = %s", j - KV_VALUE_IDX_DATA, (const char *) iov[j].iov_base);
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
	kv_store_iter_t *iter;
	void *value;
	size_t value_size, elem_count, dom_len, this_dev_len, ref_dev_len;
	const char *full_key, *key, *dom, *this_dev, *ref_dev;

	kv_store_value_flags_t flags;
	struct iovec tmp_iov[_KV_VALUE_IDX_COUNT];
	struct iovec *iov;
	int i;

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

		if (strcmp(key, KV_KEY_GEN_GROUP_IN) ||
		    (!(dom = _get_key_part(full_key, KEY_PART_DOM, &dom_len))) ||
		    !dom_len ||
		    strncmp(dom, KV_KEY_DOM_LAYER, dom_len))
			continue;

		this_dev = _get_key_part(full_key, KEY_PART_NS_PART, &this_dev_len);
		iov = _get_value_vector(flags, value, value_size, tmp_iov);

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

static int _kv_overwrite(const char *full_key, struct kv_store_update_spec *spec, void *garg)
{
	struct kv_update_arg *arg = garg;
	struct iovec tmp_iov_old[_KV_VALUE_IDX_COUNT];
	struct iovec tmp_iov_new[_KV_VALUE_IDX_COUNT];
	struct iovec *iov_old, *iov_new;
	const char *reason;

	if (!spec->old_data)
		return 1;

	iov_old = _get_value_vector(spec->old_flags, spec->old_data, spec->old_data_size, tmp_iov_old);
	iov_new = _get_value_vector(spec->new_flags, spec->new_data, spec->new_data_size, tmp_iov_new);

	if (KV_VALUE_FLAGS(iov_old) & KV_MOD_PRIVATE) {
		if (strcmp(KV_VALUE_OWNER(iov_old), KV_VALUE_OWNER(iov_new))) {
			reason = "private";
			arg->ret_code = EACCES;
			goto keep_old;
		}
	} else if (KV_VALUE_FLAGS(iov_old) & KV_MOD_PROTECTED) {
		if (strcmp(KV_VALUE_OWNER(iov_old), KV_VALUE_OWNER(iov_new))) {
			reason = "protected";
			arg->ret_code = EPERM;
			goto keep_old;
		}
	} else if (KV_VALUE_FLAGS(iov_old) & KV_MOD_RESERVED) {
		if (strcmp(KV_VALUE_OWNER(iov_old), KV_VALUE_OWNER(iov_new))) {
			reason = "reserved";
			arg->ret_code = EBUSY;
			goto keep_old;
		}
	}

	arg->ret_code = 0;
	return 1;
keep_old:
	log_debug(ID(arg->res), "Module %s can't overwrite value with key %s which is %s and attached to %s module.",
	          KV_VALUE_OWNER(iov_new), full_key, reason, KV_VALUE_OWNER(iov_old));
	return 0;
}

static int _flags_indicate_mod_owned(sid_ubridge_kv_flags_t flags)
{
	return flags & (KV_MOD_PROTECTED | KV_MOD_PRIVATE | KV_MOD_RESERVED);
}

static const char *_get_mod_name(struct sid_module *mod)
{
	return mod ? sid_module_get_name(mod) : MOD_NAME_CORE;
}

static const char *_res_get_mod_name(sid_resource_t *mod_res)
{
	return _get_mod_name(mod_res ? sid_resource_get_data(mod_res) : NULL);
}


static size_t _kv_value_ext_data_offset(struct kv_value *kv_value)
{
	return strlen(kv_value->data) + 1;
}

static int _passes_global_reservation_check(struct sid_ubridge_cmd_context *cmd, const char *owner,
                                            sid_ubridge_cmd_kv_namespace_t ns, const char *key)
{
	struct iovec tmp_iov[_KV_VALUE_IDX_COUNT];
	struct iovec *iov;
	const char *full_key = NULL;
	void *found;
	size_t value_size;
	kv_store_value_flags_t value_flags;
	struct kv_key_spec key_spec = {.op = KV_OP_SET,
		       .ns = ns,
		       .ns_part = ID_NULL,
		       .dom = ID_NULL,
		       .id = ID_NULL,
		       .id_part = ID_NULL,
		       .key = key
	};
	int r = 1;

	if ((ns != KV_NS_UDEV) && (ns != KV_NS_DEVICE))
		goto out;

	if (!(full_key = _buffer_compose_key(cmd->gen_buf, &key_spec))) {
		errno = ENOKEY;
		r = 0;
		goto out;
	}

	if (!(found = kv_store_get_value(cmd->kv_store_res, full_key, &value_size, &value_flags)))
		goto out;

	iov = _get_value_vector(value_flags, found, value_size, tmp_iov);

	if ((KV_VALUE_FLAGS(iov) & KV_MOD_RESERVED) && (!strcmp(KV_VALUE_OWNER(iov), owner)))
		goto out;

	log_debug(ID(cmd->kv_store_res), "Module %s can't overwrite value with key %s which is reserved and attached to %s module.",
	          owner, full_key, KV_VALUE_OWNER(iov));

	r = 0;
out:
	buffer_rewind_mem(cmd->gen_buf, full_key);
	return r;
}

static const char *_get_ns_part(struct sid_ubridge_cmd_context *cmd, sid_ubridge_cmd_kv_namespace_t ns)
{
	switch (ns) {
		case KV_NS_UDEV:
		case KV_NS_DEVICE:
			return cmd->dev_id;
		case KV_NS_MODULE:
			return _res_get_mod_name(cmd->mod_res);
		case KV_NS_GLOBAL:
		case KV_NS_UNDEFINED:
			break;
	}

	return ID_NULL;
}

static void _destroy_delta(struct kv_delta *delta)
{
	if (delta->plus) {
		buffer_destroy(delta->plus);
		delta->plus = NULL;
	}

	if (delta->minus) {
		buffer_destroy(delta->minus);
		delta->minus = NULL;
	}

	if (delta->final) {
		buffer_destroy(delta->final);
		delta->final = NULL;
	}
}

static void _destroy_unused_delta(struct kv_delta *delta)
{
	struct iovec *iov;
	size_t size;

	if (delta->plus) {
		buffer_get_data(delta->plus, (const void **) &iov, &size);
		if (size <= KV_VALUE_IDX_DATA) {
			buffer_destroy(delta->plus);
			delta->plus = NULL;
		}
	}

	if (delta->minus) {
		buffer_get_data(delta->minus, (const void **) &iov, &size);
		if (size <= KV_VALUE_IDX_DATA) {
			buffer_destroy(delta->minus);
			delta->minus = NULL;
		}
	}
}

static void *_do_sid_ubridge_cmd_set_kv(struct sid_ubridge_cmd_context *cmd, sid_ubridge_cmd_kv_namespace_t ns, const char *dom,
                                        const char *key, sid_ubridge_kv_flags_t flags, const void *value, size_t value_size)
{
	const char *owner = _res_get_mod_name(cmd->mod_res);
	const char *full_key = NULL;
	struct iovec iov[_KV_VALUE_IDX_COUNT];
	struct kv_value *kv_value;
	struct kv_update_arg update_arg;
	struct kv_key_spec key_spec = {.op = KV_OP_SET,
		       .ns = ns,
		       .ns_part = _get_ns_part(cmd, ns),
		       .dom = dom ? : ID_NULL,
		       .id = ID_NULL,
		       .id_part = ID_NULL,
		       .key = key
	};
	void *ret = NULL;

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
	if (!((ns == KV_NS_UDEV) && !strcmp(owner, OWNER_CORE)) &&
	    !_passes_global_reservation_check(cmd, owner, ns, key))
		goto out;

	if (!(full_key = _buffer_compose_key(cmd->gen_buf, &key_spec))) {
		errno = ENOKEY;
		goto out;
	}

	KV_VALUE_PREPARE_HEADER(iov, cmd->udev_dev.seqnum, flags, (char *) owner);
	iov[KV_VALUE_IDX_DATA] = (struct iovec) {
		(void *) value, value ? value_size : 0
	};

	update_arg.res = cmd->kv_store_res;
	update_arg.owner = owner;
	update_arg.gen_buf = cmd->gen_buf;
	update_arg.custom = NULL;
	update_arg.ret_code = 0;

	kv_value = kv_store_set_value(cmd->kv_store_res, full_key, iov, _KV_VALUE_IDX_COUNT,
	                              KV_STORE_VALUE_VECTOR, KV_STORE_VALUE_OP_MERGE,
	                              _kv_overwrite, &update_arg);

	if (!kv_value) {
		if (errno == EADV)
			errno = update_arg.ret_code;
		goto out;
	}

	if (!value_size)
		goto out;

	ret = kv_value->data + _kv_value_ext_data_offset(kv_value);
out:
	buffer_rewind_mem(cmd->gen_buf, full_key);
	return ret;
}

void *sid_ubridge_cmd_set_kv(struct sid_ubridge_cmd_context *cmd, sid_ubridge_cmd_kv_namespace_t ns,
                             const char *key, const void *value, size_t value_size, sid_ubridge_kv_flags_t flags)
{
	if (!cmd || !key || !*key || (key[0] == KEY_SYS_C[0])) {
		errno = EINVAL;
		return NULL;
	}

	if (ns == KV_NS_UDEV)
		flags |= KV_PERSISTENT;

	return _do_sid_ubridge_cmd_set_kv(cmd, ns, KV_KEY_DOM_USER, key, flags, value, value_size);
}

const void *sid_ubridge_cmd_get_kv(struct sid_ubridge_cmd_context *cmd, sid_ubridge_cmd_kv_namespace_t ns,
                                   const char *key, size_t *value_size, sid_ubridge_kv_flags_t *flags)
{
	const char *owner = _res_get_mod_name(cmd->mod_res);
	const char *full_key = NULL;
	struct kv_value *kv_value;
	size_t size, data_offset;
	struct kv_key_spec key_spec = {.op = KV_OP_SET,
		       .ns = ns,
		       .ns_part = _get_ns_part(cmd, ns),
		       .dom = KV_KEY_DOM_USER,
		       .id = ID_NULL,
		       .id_part = ID_NULL,
		       .key = key
	};
	void *ret = NULL;

	if (!cmd || !key || !*key || (key[0] == KEY_SYS_C[0])) {
		errno = EINVAL;
		goto out;
	}

	if (!(full_key = _buffer_compose_key(cmd->gen_buf, &key_spec))) {
		errno = ENOKEY;
		goto out;
	}

	if (!(kv_value = kv_store_get_value(cmd->kv_store_res, full_key, &size, NULL)))
		goto out;

	if (kv_value->flags & KV_MOD_PRIVATE) {
		if (strcmp(kv_value->data, owner)) {
			errno = EACCES;
			goto out;
		}
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
	buffer_rewind_mem(cmd->gen_buf, full_key);
	return ret;
}

static int _kv_reserve(const char *full_key, struct kv_store_update_spec *spec, void *garg)
{
	struct kv_update_arg *arg = garg;
	struct iovec tmp_iov_old[_KV_VALUE_IDX_COUNT];
	struct iovec tmp_iov_new[_KV_VALUE_IDX_COUNT];
	struct iovec *iov_old, *iov_new;

	if (!spec->old_data)
		return 1;

	iov_old = _get_value_vector(spec->old_flags, spec->old_data, spec->old_data_size, tmp_iov_old);
	iov_new = _get_value_vector(spec->new_flags, spec->new_data, spec->new_data_size, tmp_iov_new);

	if (strcmp(KV_VALUE_OWNER(iov_old), KV_VALUE_OWNER(iov_new))) {
		log_debug(ID(arg->res), "Module %s can't reserve key %s which is already reserved by %s module.",
		          KV_VALUE_OWNER(iov_new), full_key, KV_VALUE_OWNER(iov_old));
		arg->ret_code = EBUSY;
		return 0;
	}

	return 1;
}

static int _kv_unreserve(const char *full_key, struct kv_store_update_spec *spec, void *garg)
{
	struct kv_update_arg *arg = garg;
	struct iovec tmp_iov_old[_KV_VALUE_IDX_COUNT];
	struct iovec *iov_old;

	if (!spec->old_data)
		return 1;

	iov_old = _get_value_vector(spec->old_flags, spec->old_data, spec->old_data_size, tmp_iov_old);

	if (strcmp(KV_VALUE_OWNER(iov_old), arg->owner)) {
		log_debug(ID(arg->res), "Module %s can't unreserve key %s which is reserved by %s module.",
		          arg->owner, full_key, KV_VALUE_OWNER(iov_old));
		arg->ret_code = EBUSY;
		return 0;
	}

	return 1;
}

int _do_sid_ubridge_cmd_mod_reserve_kv(struct sid_module *mod, struct sid_ubridge_cmd_mod_context *cmd_mod,
                                       sid_ubridge_cmd_kv_namespace_t ns, const char *key, int unset)
{
	const char *owner = _get_mod_name(mod);
	const char *full_key = NULL;
	struct iovec iov[_KV_VALUE_IDX_COUNT - 1]; /* without KV_VALUE_IDX_DATA */
	struct kv_value *kv_value;
	static uint64_t null_int = 0;
	sid_ubridge_kv_flags_t flags = unset ? KV_FLAGS_UNSET : KV_MOD_RESERVED;
	struct kv_update_arg update_arg;
	int is_worker;
	struct kv_key_spec key_spec = {.op = KV_OP_SET,
		       .ns = ns,
		       .ns_part = ID_NULL,
		       .dom = ID_NULL,
		       .id = ID_NULL,
		       .id_part = ID_NULL,
		       .key = key
	};
	int r = -1;

	if (!(full_key = _buffer_compose_key(cmd_mod->gen_buf, &key_spec))) {
		errno = ENOKEY;
		goto out;
	}

	if (!(cmd_mod->kv_store_res)) {
		errno = ENOMEDIUM;
		goto out;
	}

	update_arg.res = cmd_mod->kv_store_res;
	update_arg.owner = owner;
	update_arg.custom = NULL;
	update_arg.ret_code = 0;

	is_worker = worker_control_is_worker(cmd_mod->kv_store_res);

	if (is_worker)
		flags |= KV_PERSISTENT;

	if (unset && !is_worker) {
		kv_store_unset_value(cmd_mod->kv_store_res, full_key, _kv_unreserve, &update_arg);

		if (errno == EADV)
			errno = update_arg.ret_code;
		goto out;
	} else {
		KV_VALUE_PREPARE_HEADER(iov, null_int, flags, (char *) owner);
		kv_value = kv_store_set_value(cmd_mod->kv_store_res, full_key, iov, _KV_VALUE_IDX_COUNT - 1,
		                              KV_STORE_VALUE_VECTOR, KV_STORE_VALUE_OP_MERGE,
		                              _kv_reserve, &update_arg);

		if (!kv_value) {
			if (errno == EADV)
				errno = update_arg.ret_code;
			goto out;
		}
	}

	r = 0;
out:
	buffer_rewind_mem(cmd_mod->gen_buf, full_key);
	return r;
}

int sid_ubridge_cmd_mod_reserve_kv(struct sid_module *mod, struct sid_ubridge_cmd_mod_context *cmd_mod,
                                   sid_ubridge_cmd_kv_namespace_t ns, const char *key)
{
	if (!mod || !cmd_mod || !key || !*key) {
		errno = EINVAL;
		return -1;
	}

	return _do_sid_ubridge_cmd_mod_reserve_kv(mod, cmd_mod, ns, key, 0);
}

int sid_ubridge_cmd_mod_unreserve_kv(struct sid_module *mod, struct sid_ubridge_cmd_mod_context *cmd_mod,
                                     sid_ubridge_cmd_kv_namespace_t ns, const char *key)
{
	if (!mod || !cmd_mod || !key || !*key) {
		errno = EINVAL;
		return -1;
	}

	return _do_sid_ubridge_cmd_mod_reserve_kv(mod, cmd_mod, ns, key, 1);
}

int sid_ubridge_cmd_dev_set_ready(struct sid_ubridge_cmd_context *cmd, dev_ready_t ready)
{
	sid_resource_t *orig_mod_res;

	if (!(_cmd_scan_phase_regs[cmd->scan_phase].flags & CMD_SCAN_CAP_RDY)) {
		errno = EPERM;
		return -1;
	}

	if (ready == DEV_NOT_RDY_UNPROCESSED) {
		errno = EINVAL;
		return -1;
	}

	orig_mod_res = cmd->mod_res;
	cmd->mod_res = NULL;

	_do_sid_ubridge_cmd_set_kv(cmd, KV_NS_DEVICE, NULL, KV_KEY_DEV_READY, DEFAULT_KV_FLAGS_CORE, &ready, sizeof(ready));

	cmd->mod_res = orig_mod_res;
	return 0;
}

dev_ready_t sid_ubridge_cmd_dev_get_ready(struct sid_ubridge_cmd_context *cmd)
{
	sid_resource_t *orig_mod_res;
	const dev_ready_t *p_ready;
	dev_ready_t result;

	orig_mod_res = cmd->mod_res;
	cmd->mod_res = NULL;

	if (!(p_ready = sid_ubridge_cmd_get_kv(cmd, KV_NS_DEVICE, KV_KEY_DEV_READY, NULL, NULL)))
		result = DEV_NOT_RDY_UNPROCESSED;
	else
		result = *p_ready;

	cmd->mod_res = orig_mod_res;
	return result;
}

int sid_ubridge_cmd_dev_set_reserved(struct sid_ubridge_cmd_context *cmd, dev_reserved_t reserved)
{
	sid_resource_t *orig_mod_res;

	if (!(_cmd_scan_phase_regs[cmd->scan_phase].flags & CMD_SCAN_CAP_RES)) {
		errno = EPERM;
		return -1;
	}

	orig_mod_res = cmd->mod_res;
	cmd->mod_res = NULL;

	_do_sid_ubridge_cmd_set_kv(cmd, KV_NS_DEVICE, NULL, KV_KEY_DEV_RESERVED, DEFAULT_KV_FLAGS_CORE, &reserved, sizeof(reserved));

	cmd->mod_res = orig_mod_res;
	return 0;
}

dev_reserved_t sid_ubridge_cmd_dev_get_reserved(struct sid_ubridge_cmd_context *cmd)
{
	sid_resource_t *orig_mod_res;
	const dev_reserved_t *p_reserved;
	dev_reserved_t result;

	orig_mod_res = cmd->mod_res;
	cmd->mod_res = NULL;

	if (!(p_reserved = sid_ubridge_cmd_get_kv(cmd, KV_NS_DEVICE, KV_KEY_DEV_RESERVED, NULL, NULL)))
		result = DEV_RES_UNPROCESSED;
	else
		result = *p_reserved;

	cmd->mod_res = orig_mod_res;
	return result;
}

static int _kv_write_new_only(const char *full_key, struct kv_store_update_spec *spec, void *garg)
{
	if (spec->old_data)
		return 0;

	return 1;
}

int sid_ubridge_cmd_group_create(struct sid_ubridge_cmd_context *cmd,
                                 sid_ubridge_cmd_kv_namespace_t group_ns,
                                 const char *group_id,
                                 sid_ubridge_kv_flags_t group_flags)
{
	const char *full_key = NULL;
	struct iovec iov[KV_VALUE_IDX_DATA];
	int r = -1;

	struct kv_key_spec key_spec = {.op = KV_OP_SET,
		       .ns = group_ns,
		       .ns_part = _get_ns_part(cmd, group_ns),
		       .dom = ID_NULL,
		       .id = group_id,
		       .id_part = ID_NULL,
		       .key = KV_KEY_GEN_GROUP_MEMBERS
	};

	struct kv_update_arg update_arg = {.res = cmd->kv_store_res,
		       .owner = _res_get_mod_name(cmd->mod_res),
		       .gen_buf = cmd->gen_buf,
		       .custom = NULL,
		       .ret_code = 0
	};

	full_key = _buffer_compose_key(cmd->gen_buf, &key_spec);
	KV_VALUE_PREPARE_HEADER(iov, cmd->udev_dev.seqnum, kv_flags_persist, core_owner);

	if (!kv_store_set_value(cmd->kv_store_res,
	                        full_key,
	                        iov, KV_VALUE_IDX_DATA,
	                        KV_STORE_VALUE_VECTOR,
	                        0,
	                        _kv_write_new_only,
	                        &update_arg)) {
		errno = update_arg.ret_code;
		goto out;
	}

	r = 0;
out:
	buffer_rewind_mem(cmd->gen_buf, full_key);
	return r;
}

int _handle_current_dev_for_group(struct sid_ubridge_cmd_context *cmd,
                                  sid_ubridge_cmd_kv_namespace_t group_ns,
                                  const char *group_id, kv_op_t op)
{
	const char *tmp_mem_start = buffer_add(cmd->gen_buf, "", 0);
	const char *cur_full_key, *rel_key_prefix;
	struct iovec iov[_KV_VALUE_IDX_COUNT];
	int r = 0;

	struct kv_rel_spec rel_spec = {.delta = &((struct kv_delta)
		{
			.op = op,
			.flags = DELTA_WITH_DIFF | DELTA_WITH_REL,
			.plus = NULL,
			.minus = NULL,
			.final = NULL
		}),

		.cur_key_spec = &((struct kv_key_spec)
		{
			.op = KV_OP_SET,
			.ns = group_ns,
			.ns_part = _get_ns_part(cmd, group_ns),
			.dom = KV_KEY_DOM_USER,
			.id = group_id,
			.id_part = ID_NULL,
			.key = KV_KEY_GEN_GROUP_MEMBERS
		}),

		.rel_key_spec = &((struct kv_key_spec)
		{
			.op = KV_OP_SET,
			.ns = KV_NS_DEVICE,
			.ns_part = _get_ns_part(cmd, KV_NS_DEVICE),
			.dom = ID_NULL,
			.id = ID_NULL,
			.id_part = ID_NULL,
			.key = KV_KEY_GEN_GROUP_IN
		})
	};

	struct kv_update_arg update_arg = {.res = cmd->kv_store_res,
		       .owner = OWNER_CORE,
		       .gen_buf = cmd->gen_buf,
		       .custom = &rel_spec
	};

	// TODO: check return values / maybe also pass flags / use proper owner

	KV_VALUE_PREPARE_HEADER(iov, cmd->udev_dev.seqnum, kv_flags_no_persist, core_owner);
	rel_key_prefix = _buffer_compose_key_prefix(cmd->gen_buf, rel_spec.rel_key_spec);
	iov[KV_VALUE_IDX_DATA] = (struct iovec) {
		(void *) rel_key_prefix, strlen(rel_key_prefix) + 1
	};

	cur_full_key = _buffer_compose_key(cmd->gen_buf, rel_spec.cur_key_spec);

	if (!kv_store_set_value(cmd->kv_store_res,
	                        cur_full_key,
	                        iov, _KV_VALUE_IDX_COUNT,
	                        KV_STORE_VALUE_VECTOR | KV_STORE_VALUE_REF,
	                        0,
	                        _kv_delta,
	                        &update_arg)) {
		errno = update_arg.ret_code;
		r = -1;
	}

	_destroy_delta(rel_spec.delta);
	buffer_rewind_mem(cmd->gen_buf, tmp_mem_start);
	return r;
}

int sid_ubridge_cmd_group_add_current_dev(struct sid_ubridge_cmd_context *cmd,
                                          sid_ubridge_cmd_kv_namespace_t group_ns,
                                          const char *group_id)
{
	return _handle_current_dev_for_group(cmd, group_ns, group_id, KV_OP_PLUS);
}

int sid_ubridge_cmd_group_remove_current_dev(struct sid_ubridge_cmd_context *cmd,
                                             sid_ubridge_cmd_kv_namespace_t group_ns,
                                             const char *group_id)
{
	return _handle_current_dev_for_group(cmd, group_ns, group_id, KV_OP_MINUS);
}

int sid_ubridge_cmd_group_destroy(struct sid_ubridge_cmd_context *cmd,
                                  sid_ubridge_cmd_kv_namespace_t group_ns,
                                  const char *group_id,
                                  int force)
{
	static sid_ubridge_kv_flags_t kv_flags_persist_no_reserved = (DEFAULT_KV_FLAGS_CORE) & ~KV_MOD_RESERVED;
	const char *cur_full_key = NULL;
	size_t size;
	struct iovec *iov;
	struct iovec iov_blank[KV_VALUE_IDX_DATA];
	int r = -1;

	struct kv_rel_spec rel_spec = {.delta = &((struct kv_delta)
		{
			.op = KV_OP_SET,
			.flags = DELTA_WITH_DIFF | DELTA_WITH_REL,
			.plus = NULL,
			.minus = NULL,
			.final = NULL
		}),

		.cur_key_spec = &((struct kv_key_spec)
		{
			.op = KV_OP_SET,
			.ns = group_ns,
			.ns_part = _get_ns_part(cmd, group_ns),
			.dom = ID_NULL,
			.id = group_id,
			.id_part = ID_NULL,
			.key = KV_KEY_GEN_GROUP_MEMBERS
		}),

		.rel_key_spec = &((struct kv_key_spec)
		{
			.op = KV_OP_SET,
			.ns = 0,
			.ns_part = ID_NULL,
			.dom = ID_NULL,
			.id = ID_NULL,
			.id_part = ID_NULL,
			.key = KV_KEY_GEN_GROUP_IN
		})
	};

	struct kv_update_arg update_arg = {.res = cmd->kv_store_res,
		       .owner = OWNER_CORE,
		       .gen_buf = cmd->gen_buf,
		       .custom = &rel_spec
	};

	// TODO: do not call kv_store_get_value, only kv_store_set_value and provide _kv_delta wrapper
	//       to do the "is empty?" check before the actual _kv_delta operation

	cur_full_key = _buffer_compose_key(cmd->gen_buf, rel_spec.cur_key_spec);

	if (!(iov = kv_store_get_value(cmd->kv_store_res, cur_full_key, &size, NULL)))
		goto out;

	if (size > KV_VALUE_IDX_DATA && !force) {
		errno = ENOTEMPTY;
		goto out;
	}

	KV_VALUE_PREPARE_HEADER(iov_blank, cmd->udev_dev.seqnum, kv_flags_persist_no_reserved, core_owner);

	if (!kv_store_set_value(cmd->kv_store_res,
	                        cur_full_key,
	                        iov_blank, KV_VALUE_IDX_DATA,
	                        KV_STORE_VALUE_VECTOR | KV_STORE_VALUE_REF,
	                        0,
	                        _kv_delta,
	                        &update_arg)) {
		errno = update_arg.ret_code;
		goto out;
	}

	r = 0;
out:
	_destroy_delta(rel_spec.delta);
	buffer_rewind_mem(cmd->gen_buf, cur_full_key);
	return r;
}

static int _device_add_field(struct sid_ubridge_cmd_context *cmd, const char *start)
{
	const char *key;
	const char *value;
	int r = -1;

	if (!(value = strchr(start, KV_PAIR_C[0])) || !*(++value))
		return -1;

	if (!(key = buffer_fmt_add(cmd->gen_buf, "%.*s", value - start - 1, start)))
		return -1;

	if (!(value = _do_sid_ubridge_cmd_set_kv(cmd, KV_NS_UDEV, NULL, key, 0, value, strlen(value) + 1)))
		goto out;

	/* Common key=value pairs are also directly in the cmd->udev_dev structure. */
	if (!strcmp(key, UDEV_KEY_ACTION))
		cmd->udev_dev.action = util_udev_str_to_udev_action(value);
	else if (!strcmp(key, UDEV_KEY_DEVPATH)) {
		cmd->udev_dev.path = value;
		cmd->udev_dev.name = util_str_rstr(value, "/");
		cmd->udev_dev.name++;
	} else if (!strcmp(key, UDEV_KEY_DEVTYPE))
		cmd->udev_dev.type = util_udev_str_to_udev_devtype(value);
	else if (!strcmp(key, UDEV_KEY_SEQNUM))
		cmd->udev_dev.seqnum = strtoull(value, NULL, 10);
	else if (!strcmp(key, UDEV_KEY_SYNTH_UUID))
		cmd->udev_dev.synth_uuid = value;

	r = 0;
out:
	buffer_rewind_mem(cmd->gen_buf, key);
	return r;
};

static int _parse_cmd_nullstr_udev_env(struct sid_ubridge_cmd_context *cmd, const char *env, size_t env_size)
{
	dev_t devno;
	const char *end;
	int r = 0;

	if (env_size <= sizeof(devno)) {
		r = -EINVAL;
		goto out;
	}

	memcpy(&devno, env, sizeof(devno));
	cmd->udev_dev.major = major(devno);
	cmd->udev_dev.minor = minor(devno);

	if (asprintf(&cmd->dev_id, "%d_%d", cmd->udev_dev.major, cmd->udev_dev.minor) < 0) {
		r = -ENOMEM;
		goto out;
	}

	/*
	 * We have this on input ('devno' prefix is already processed so skip it):
	 *
	 *   devnokey1=value1\0key2=value2\0...
	 */
	for (env += sizeof(devno), end = env + env_size; env < end; env += strlen(env) + 1) {
		if ((r = _device_add_field(cmd, env) < 0))
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
 *  Module name is equal to the name as exposed in SYSTEM_PROC_DEVICES_PATH + MODULE_NAME_SUFFIX.
 */
static const char *_lookup_module_name(sid_resource_t *cmd_res)
{
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(cmd_res);
	char buf[PATH_MAX];
	const char *mod_name = NULL;
	FILE *f = NULL;
	char line[80];
	int in_block_section = 0;
	char *p, *end, *found = NULL;
	int major;
	size_t len;

	if ((mod_name = sid_ubridge_cmd_get_kv(cmd, KV_NS_DEVICE, KV_KEY_DEV_MOD, NULL, NULL)))
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
		if (major == cmd->udev_dev.major) {
			found = end + 1;
			break;
		}
	}

	if (!found) {
		log_error(ID(cmd_res), "Unable to find major number %d for device %s in %s.",
		          cmd->udev_dev.major, cmd->udev_dev.name, SYSTEM_PROC_DEVICES_PATH);
		goto out;
	}

	p = found;
	while (isprint(*p))
		p++;
	p[0] = '\0';

	len = p - found;

	if (len >= (sizeof(buf) - strlen(SID_MODULE_NAME_SUFFIX))) {
		log_error(ID(cmd_res), "Insufficient result buffer for device lookup in %s, "
		          "found string \"%s\", buffer size is only %zu.", SYSTEM_PROC_DEVICES_PATH,
		          found, sizeof(buf));
		goto out;
	}

	memcpy(buf, found, len);
	memcpy(buf + len, SID_MODULE_NAME_SUFFIX, SID_MODULE_NAME_SUFFIX_LEN);
	buf[len + SID_MODULE_NAME_SUFFIX_LEN] = '\0';
	_canonicalize_module_name(buf);

	if (!(mod_name = _do_sid_ubridge_cmd_set_kv(cmd, KV_NS_DEVICE, NULL, KV_KEY_DEV_MOD, DEFAULT_KV_FLAGS_CORE, buf, strlen(buf) + 1)))
		log_error_errno(ID(cmd_res), errno, "Failed to store device " CMD_DEV_ID_FMT " module name.", CMD_DEV_ID(cmd));
out:
	if (f)
		fclose(f);
	return mod_name;
}

static int _cmd_exec_unknown(struct cmd_exec_arg *exec_arg)
{
	return 0;
}

static int _cmd_exec_reply(struct cmd_exec_arg *exec_arg)
{
	return 0;
}

static int _cmd_exec_version(struct cmd_exec_arg *exec_arg)
{
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(exec_arg->cmd_res);
	static struct usid_version version = {.major = SID_VERSION_MAJOR,
		       .minor = SID_VERSION_MINOR,
		       .release = SID_VERSION_RELEASE
	};

	buffer_add(cmd->res_buf, &version, sizeof(version));
	return 0;
}

static int _execute_block_modules(struct cmd_exec_arg *exec_arg, cmd_scan_phase_t phase)
{
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(exec_arg->cmd_res);
	sid_resource_t *orig_mod_res = cmd->mod_res;
	sid_resource_t *block_mod_res;
	struct sid_module *block_mod;
	const struct cmd_mod_fns *block_mod_fns;
	int r = -1;

	sid_resource_iter_reset(exec_arg->block_mod_iter);

	while ((block_mod_res = sid_resource_iter_next(exec_arg->block_mod_iter))) {
		if (sid_module_registry_get_module_symbols(block_mod_res, (const void ***) &block_mod_fns) < 0) {
			log_error(ID(exec_arg->cmd_res), "Failed to retrieve module symbols from module %s.", ID(block_mod_res));
			goto out;
		}

		cmd->mod_res = block_mod_res;
		block_mod = sid_resource_get_data(block_mod_res);

		switch (phase) {
			case CMD_SCAN_PHASE_A_IDENT:
				if (block_mod_fns->ident && block_mod_fns->ident(block_mod, cmd) < 0)
					goto out;
				break;
			case CMD_SCAN_PHASE_A_SCAN_PRE:
				if (block_mod_fns->scan_pre && block_mod_fns->scan_pre(block_mod, cmd) < 0)
					goto out;
				break;
			case CMD_SCAN_PHASE_A_SCAN_CURRENT:
				if (block_mod_fns->scan_current && block_mod_fns->scan_current(block_mod, cmd) < 0)
					goto out;
				break;
			case CMD_SCAN_PHASE_A_SCAN_NEXT:
				if (block_mod_fns->scan_next && block_mod_fns->scan_next(block_mod, cmd) < 0)
					goto out;
				break;
			case CMD_SCAN_PHASE_A_SCAN_POST_CURRENT:
				if (block_mod_fns->scan_post_current && block_mod_fns->scan_post_current(block_mod, cmd) < 0)
					goto out;
				break;
			case CMD_SCAN_PHASE_A_SCAN_POST_NEXT:
				if (block_mod_fns->scan_post_next && block_mod_fns->scan_post_next(block_mod, cmd) < 0)
					goto out;
				break;
			case CMD_SCAN_PHASE_B_TRIGGER_ACTION_CURRENT:
				if (block_mod_fns->trigger_action_current && block_mod_fns->trigger_action_current(block_mod, cmd) < 0)
					goto out;
				break;
			case CMD_SCAN_PHASE_B_TRIGGER_ACTION_NEXT:
				if (block_mod_fns->trigger_action_next && block_mod_fns->trigger_action_next(block_mod, cmd) < 0)
					goto out;
				break;
			case CMD_SCAN_PHASE_ERROR:
				if (block_mod_fns->error && block_mod_fns->error(block_mod, cmd) < 0)
					goto out;
				break;
			default:
				log_error(ID(exec_arg->cmd_res), INTERNAL_ERROR "%s: Trying illegal execution of block modules in %s state.",
				          __func__, _cmd_scan_phase_regs[phase].name);
				break;
		}
	}

	r = 0;
out:
	cmd->mod_res = orig_mod_res;
	return r;
}

static int _cmd_exec_ident(struct cmd_exec_arg *exec_arg)
{
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(exec_arg->cmd_res);
	const struct cmd_mod_fns *mod_fns;

	_execute_block_modules(exec_arg, CMD_SCAN_PHASE_A_IDENT);

	//sid_resource_dump_all_in_dot(sid_resource_search(exec_arg->cmd_res, SID_RESOURCE_SEARCH_TOP, NULL, NULL));

	sid_module_registry_get_module_symbols(cmd->mod_res, (const void ***) &mod_fns);
	if (mod_fns && mod_fns->ident)
		return mod_fns->ident(sid_resource_get_data(cmd->mod_res), cmd);

	return 0;
}

static int _cmd_exec_scan_pre(struct cmd_exec_arg *exec_arg)
{
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(exec_arg->cmd_res);
	const struct cmd_mod_fns *mod_fns;

	_execute_block_modules(exec_arg, CMD_SCAN_PHASE_A_SCAN_PRE);

	sid_module_registry_get_module_symbols(cmd->mod_res, (const void ***) &mod_fns);
	if (mod_fns && mod_fns->scan_pre)
		return mod_fns->scan_pre(sid_resource_get_data(cmd->mod_res), cmd);

	return 0;
}

static int _cmd_exec_scan_current(struct cmd_exec_arg *exec_arg)
{
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(exec_arg->cmd_res);
	const struct cmd_mod_fns *mod_fns;

	_execute_block_modules(exec_arg, CMD_SCAN_PHASE_A_SCAN_CURRENT);

	sid_module_registry_get_module_symbols(cmd->mod_res, (const void ***) &mod_fns);
	if (mod_fns && mod_fns->scan_current)
		if (mod_fns->scan_current(sid_resource_get_data(cmd->mod_res), cmd))
			return -1;

	return 0;
}

static int _cmd_exec_scan_next(struct cmd_exec_arg *exec_arg)
{
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(exec_arg->cmd_res);
	const struct cmd_mod_fns *mod_fns;
	const char *next_mod_name;

	_execute_block_modules(exec_arg, CMD_SCAN_PHASE_A_SCAN_NEXT);

	if ((next_mod_name = sid_ubridge_cmd_get_kv(cmd, KV_NS_DEVICE, KV_KEY_DEV_NEXT_MOD, NULL, NULL))) {
		if (!(exec_arg->type_mod_res_next = sid_module_registry_get_module(exec_arg->type_mod_registry_res, next_mod_name))) {
			log_debug(ID(exec_arg->cmd_res), "Module %s not loaded.", next_mod_name);
			return -1;
		}
	} else
		exec_arg->type_mod_res_next = NULL;

	cmd->mod_res = exec_arg->type_mod_res_next;

	sid_module_registry_get_module_symbols(cmd->mod_res, (const void ***) &mod_fns);
	if (mod_fns && mod_fns->scan_next)
		return mod_fns->scan_next(sid_resource_get_data(cmd->mod_res), cmd);

	return 0;
}

static int _cmd_exec_scan_post_current(struct cmd_exec_arg *exec_arg)
{
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(exec_arg->cmd_res);
	const struct cmd_mod_fns *mod_fns;

	cmd->mod_res = exec_arg->type_mod_res_current;

	_execute_block_modules(exec_arg, CMD_SCAN_PHASE_A_SCAN_POST_CURRENT);

	sid_module_registry_get_module_symbols(cmd->mod_res, (const void ***) &mod_fns);
	if (mod_fns && mod_fns->scan_post_current)
		return mod_fns->scan_post_current(sid_resource_get_data(cmd->mod_res), cmd);

	return 0;
}

static int _cmd_exec_scan_post_next(struct cmd_exec_arg *exec_arg)
{
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(exec_arg->cmd_res);
	const struct cmd_mod_fns *mod_fns;

	cmd->mod_res = exec_arg->type_mod_res_next;

	_execute_block_modules(exec_arg, CMD_SCAN_PHASE_A_SCAN_POST_NEXT);

	sid_module_registry_get_module_symbols(cmd->mod_res, (const void ***) &mod_fns);
	if (mod_fns && mod_fns->scan_post_next)
		return mod_fns->scan_post_next(sid_resource_get_data(cmd->mod_res), cmd);

	return 0;
}

static int _cmd_exec_trigger_action_current(struct cmd_exec_arg *exec_arg)
{
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(exec_arg->cmd_res);

	cmd->mod_res = exec_arg->type_mod_res_current;
	return 0;
}

static int _cmd_exec_trigger_action_next(struct cmd_exec_arg *exec_arg)
{
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(exec_arg->cmd_res);

	cmd->mod_res = exec_arg->type_mod_res_next;
	return 0;
}

static int _cmd_exec_scan_error(struct cmd_exec_arg *exec_arg)
{
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(exec_arg->cmd_res);
	const struct cmd_mod_fns *mod_fns;
	int r = 0;

	_execute_block_modules(exec_arg, CMD_SCAN_PHASE_ERROR);

	cmd->mod_res = exec_arg->type_mod_res_current;
	sid_module_registry_get_module_symbols(cmd->mod_res, (const void ***) &mod_fns);
	if (mod_fns && mod_fns->error)
		r |= mod_fns->error(sid_resource_get_data(cmd->mod_res), cmd);

	cmd->mod_res = exec_arg->type_mod_res_next;
	sid_module_registry_get_module_symbols(cmd->mod_res, (const void ***) &mod_fns);
	if (mod_fns && mod_fns->error)
		r |= mod_fns->error(sid_resource_get_data(cmd->mod_res), cmd);

	return r;
}

static int _get_sysfs_value(sid_resource_t *res, const char *path, char *buf, size_t buf_size)
{
	FILE *fp;
	size_t len;
	int r = -1;

	if (!(fp = fopen(path, "r"))) {
		log_sys_error(ID(res), "fopen", path);
		goto out;
	}

	if (!(fgets(buf, buf_size, fp))) {
		log_sys_error(ID(res), "fgets", path);
		goto out;
	}

	if ((len = strlen(buf)) && buf[len-1] == '\n')
		buf[--len] = '\0';

	if (!len)
		log_error(ID(res), "No value found in %s.", path);
	else
		r = 0;
out:
	if (fp)
		fclose(fp);

	return r;
}

static int _init_delta_buffer(struct buffer **delta_buf, size_t size, struct iovec *header, size_t header_size)
{
	struct buffer *buf;
	size_t i;

	if (!size)
		return 0;

	if (size < header_size) {
		errno = EINVAL;
		return -1;
	}

	if (!(buf = buffer_create(BUFFER_TYPE_VECTOR, BUFFER_MODE_PLAIN, size, 0))) {
		errno = ENOMEM;
		return -1;
	}

	for (i = 0; i < header_size; i++)
		buffer_add(buf, header[i].iov_base, header[i].iov_len);

	*delta_buf = buf;
	return 0;
}

static int _init_delta_struct(struct kv_delta *delta, size_t minus_size, size_t plus_size, size_t final_size,
                              struct iovec *header, size_t header_size)
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

static int _delta_step_calculate(struct kv_store_update_spec *spec,
                                 struct kv_update_arg *update_arg)
{
	struct kv_delta *delta = ((struct kv_rel_spec *) update_arg->custom)->delta;
	struct iovec *old_value = spec->old_data;
	size_t old_size = spec->old_data_size;
	struct iovec *new_value = spec->new_data;
	size_t new_size = spec->new_data_size;
	size_t i_old, i_new;
	int cmp_result;
	int r = -1;

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
						buffer_add(delta->minus, old_value[i_old].iov_base, old_value[i_old].iov_len);
						break;
					case KV_OP_PLUS:
					/* we're keeping old item: add it to delta->final */
					/* no break here intentionally! */
					case KV_OP_MINUS:
						/* we're keeping old item: add it to delta->final */
						buffer_add(delta->final, old_value[i_old].iov_base, old_value[i_old].iov_len);
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
						buffer_add(delta->plus, new_value[i_new].iov_base, new_value[i_new].iov_len);
						buffer_add(delta->final, new_value[i_new].iov_base, new_value[i_new].iov_len);
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
						/* we're trying to add already existing item: add it to delta->final but not delta->plus */
						buffer_add(delta->final, new_value[i_new].iov_base, new_value[i_new].iov_len);
						break;
					case KV_OP_MINUS:
						/* we're removing item: add it to delta->minus */
						buffer_add(delta->minus, new_value[i_new].iov_base, new_value[i_new].iov_len);
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
						buffer_add(delta->plus, new_value[i_new].iov_base, new_value[i_new].iov_len);
						buffer_add(delta->final, new_value[i_new].iov_base, new_value[i_new].iov_len);
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
						buffer_add(delta->minus, old_value[i_old].iov_base, old_value[i_old].iov_len);
						break;
					case KV_OP_PLUS:
					/* we're keeping old item: add it to delta->final */
					/* no break here intentionally! */
					case KV_OP_MINUS:
						/* we're not changing the old item so add it to delta->final */
						buffer_add(delta->final, old_value[i_old].iov_base, old_value[i_old].iov_len);
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
	int cmp_result;

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

static int _delta_abs_calculate(struct kv_store_update_spec *spec,
                                struct kv_update_arg *update_arg,
                                struct kv_delta *abs_delta)
{
	struct cross_bitmap_calc_arg cross1 = {0};
	struct cross_bitmap_calc_arg cross2 = {0};
	struct kv_rel_spec *rel_spec = update_arg->custom;
	kv_op_t orig_op = rel_spec->cur_key_spec->op;
	const char *delta_full_key;
	struct iovec *abs_plus, *abs_minus;
	size_t i, abs_plus_size, abs_minus_size;
	int r = -1;

	if (!rel_spec->delta->plus && !rel_spec->delta->minus)
		return 0;

	rel_spec->cur_key_spec->op = KV_OP_PLUS;
	delta_full_key = _buffer_compose_key(update_arg->gen_buf, rel_spec->cur_key_spec);
	if ((cross1.old_value = kv_store_get_value(update_arg->res, delta_full_key, &cross1.old_size, NULL))) {
		if (!(cross1.old_bmp = bitmap_create(cross1.old_size, true)))
			goto out;
	}
	buffer_rewind_mem(update_arg->gen_buf, delta_full_key);

	rel_spec->cur_key_spec->op = KV_OP_MINUS;
	delta_full_key = _buffer_compose_key(update_arg->gen_buf, rel_spec->cur_key_spec);
	if ((cross2.old_value = kv_store_get_value(update_arg->res, delta_full_key, &cross2.old_size, NULL))) {
		if (!(cross2.old_bmp = bitmap_create(cross2.old_size, true)))
			goto out;
	}
	buffer_rewind_mem(update_arg->gen_buf, delta_full_key);

	/*
	 * set up cross1 - old plus vs. new minus
	 *
	 * OLD              NEW
	 *
	 * plus  <----|     plus
	 * minus      |---> minus
	 */
	if (rel_spec->delta->minus) {
		buffer_get_data(rel_spec->delta->minus, (const void **) &cross1.new_value, &cross1.new_size);

		if (!(cross1.new_bmp = bitmap_create(cross1.new_size, true)))
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
		buffer_get_data(rel_spec->delta->plus, (const void **) &cross2.new_value, &cross2.new_size);

		if (!(cross2.new_bmp = bitmap_create(cross2.new_size, true)))
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

	abs_plus_size = ((cross1.old_bmp ? bitmap_get_bit_set_count(cross1.old_bmp) : 0) +
	                 (cross2.new_bmp ? bitmap_get_bit_set_count(cross2.new_bmp) : 0));

	/* go through the old and new plus and minus vectors and merge non-contradicting items */
	if (_init_delta_struct(abs_delta, abs_minus_size, abs_plus_size, 0, spec->new_data, KV_VALUE_IDX_DATA) < 0)
		goto out;

	if (rel_spec->delta->flags & DELTA_WITH_REL)
		abs_delta->flags |= DELTA_WITH_REL;

	if (cross1.old_value) {
		for (i = KV_VALUE_IDX_DATA; i < cross1.old_size; i++) {
			if (bitmap_bit_is_set(cross1.old_bmp, i))
				buffer_add(abs_delta->plus, cross1.old_value[i].iov_base, cross1.old_value[i].iov_len);
		}
	}

	if (cross1.new_value) {
		for (i = KV_VALUE_IDX_DATA; i < cross1.new_size; i++) {
			if (bitmap_bit_is_set(cross1.new_bmp, i))
				buffer_add(abs_delta->minus, cross1.new_value[i].iov_base, cross1.new_value[i].iov_len);
		}
	}

	if (cross2.old_value) {
		for (i = KV_VALUE_IDX_DATA; i < cross2.old_size; i++) {
			if (bitmap_bit_is_set(cross2.old_bmp, i))
				buffer_add(abs_delta->minus, cross2.old_value[i].iov_base, cross2.old_value[i].iov_len);
		}
	}

	if (cross2.new_value) {
		for (i = KV_VALUE_IDX_DATA; i < cross2.new_size; i++) {
			if (bitmap_bit_is_set(cross2.new_bmp, i))
				buffer_add(abs_delta->plus, cross2.new_value[i].iov_base, cross2.new_value[i].iov_len);
		}
	}

	if (abs_delta->plus) {
		buffer_get_data(abs_delta->plus, (const void **) &abs_plus, &abs_plus_size);
		qsort(abs_plus + KV_VALUE_IDX_DATA, abs_plus_size - KV_VALUE_IDX_DATA, sizeof(struct iovec), _iov_str_item_cmp);
	}

	if (abs_delta->minus) {
		buffer_get_data(abs_delta->minus, (const void **) &abs_minus, &abs_minus_size);
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
		iov[KV_VALUE_IDX_FLAGS] = (struct iovec) {
		&kv_flags_persist, sizeof(kv_flags_persist)
	};
	else
		iov[KV_VALUE_IDX_FLAGS] = (struct iovec) {
		&kv_flags_no_persist, sizeof(kv_flags_no_persist)
	};
}

static void _flip_key_specs(struct kv_rel_spec *rel_spec)
{
	struct kv_key_spec *tmp_key_spec;

	tmp_key_spec = rel_spec->cur_key_spec;
	rel_spec->cur_key_spec = rel_spec->rel_key_spec;
	rel_spec->rel_key_spec = tmp_key_spec;
}

static int _delta_update(struct kv_store_update_spec *spec,
                         struct kv_update_arg *update_arg,
                         struct kv_delta *abs_delta, kv_op_t op)
{
	uint64_t seqnum = KV_VALUE_SEQNUM(spec->new_data);
	struct kv_rel_spec *rel_spec = update_arg->custom;
	kv_op_t orig_op = rel_spec->cur_key_spec->op;
	const char *tmp_mem_start = buffer_add(update_arg->gen_buf, "", 0);
	struct kv_delta *orig_delta;
	struct iovec *delta_iov, *abs_delta_iov;
	size_t delta_iov_cnt, abs_delta_iov_cnt, i;
	const char *key_prefix, *ns_part, *full_key;
	struct iovec rel_iov[_KV_VALUE_IDX_COUNT];

	if (op == KV_OP_PLUS) {
		if (!abs_delta->plus)
			return 0;
		buffer_get_data(abs_delta->plus, (const void **) &abs_delta_iov, &abs_delta_iov_cnt);
		buffer_get_data(rel_spec->delta->plus, (const void **) &delta_iov, &delta_iov_cnt);
	} else if (op == KV_OP_MINUS) {
		if (!abs_delta->minus)
			return 0;
		buffer_get_data(abs_delta->minus, (const void **) &abs_delta_iov, &abs_delta_iov_cnt);
		buffer_get_data(rel_spec->delta->minus, (const void **) &delta_iov, &delta_iov_cnt);
	} else {
		log_error(ID(update_arg->res), INTERNAL_ERROR "%s: incorrect delta operation requested.", __func__);
		return -1;
	}

	/* store absolute delta for current item - persistent */
	rel_spec->cur_key_spec->op = op;
	full_key = _buffer_compose_key(update_arg->gen_buf, rel_spec->cur_key_spec);
	rel_spec->cur_key_spec->op = orig_op;

	_value_vector_mark_persist(abs_delta_iov, 1);
	kv_store_set_value(update_arg->res, full_key, abs_delta_iov, abs_delta_iov_cnt, KV_STORE_VALUE_VECTOR, 0, _kv_overwrite, update_arg);
	_value_vector_mark_persist(abs_delta_iov, 0);

	buffer_rewind_mem(update_arg->gen_buf, full_key);

	/* the other way round now - store final and absolute delta for each relative */
	if (delta_iov_cnt && rel_spec->delta->flags & DELTA_WITH_REL) {
		_flip_key_specs(rel_spec);
		orig_delta = rel_spec->delta;

		rel_spec->delta = &((struct kv_delta) {
			0
		});
		rel_spec->delta->op = op;
		rel_spec->delta->flags = DELTA_WITH_DIFF;

		key_prefix = _buffer_compose_key_prefix(update_arg->gen_buf, rel_spec->rel_key_spec);
		KV_VALUE_PREPARE_HEADER(rel_iov, seqnum, kv_flags_no_persist, (char *) update_arg->owner);
		rel_iov[KV_VALUE_IDX_DATA] = (struct iovec) {
			.iov_base = (void *) key_prefix, .iov_len = strlen(key_prefix) + 1
		};

		for (i = KV_VALUE_IDX_DATA; i < delta_iov_cnt; i++) {
			ns_part = _buffer_copy_ns_part_from_key(update_arg->gen_buf, delta_iov[i].iov_base);
			rel_spec->cur_key_spec->ns_part = ns_part;
			full_key = _buffer_compose_key(update_arg->gen_buf, rel_spec->cur_key_spec);

			kv_store_set_value(update_arg->res, full_key, rel_iov, _KV_VALUE_IDX_COUNT,
			                   KV_STORE_VALUE_VECTOR | KV_STORE_VALUE_REF, 0, _kv_delta, update_arg);

			_destroy_delta(rel_spec->delta);
		}

		rel_spec->delta = orig_delta;
		_flip_key_specs(rel_spec);
	}

	rel_spec->cur_key_spec->op = orig_op;
	buffer_rewind_mem(update_arg->gen_buf, tmp_mem_start);
	return 0;
}

static int _kv_delta(const char *full_key __attribute__ ((unused)),
                     struct kv_store_update_spec *spec, void *garg)
{
	struct kv_update_arg *update_arg = garg;
	struct kv_rel_spec *rel_spec = update_arg->custom;
	struct kv_delta abs_delta = {0};
	int r = 0; /* no change by default */

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
		buffer_get_data(rel_spec->delta->final,
		                (const void **) &spec->new_data, &spec->new_data_size);

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
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(cmd_res);
	const char *tmp_mem_start = buffer_add(cmd->gen_buf, "", 0);
	const char *s;
	struct dirent **dirent = NULL;
	struct buffer *vec_buf = NULL;
	char devno_buf[16];
	struct iovec *iov;
	size_t iov_cnt;
	int count = 0, i;
	int r = -1;

	struct kv_rel_spec rel_spec = {.delta = &((struct kv_delta)
		{
			.op = KV_OP_SET,
			.flags = DELTA_WITH_DIFF | DELTA_WITH_REL,
			.plus = NULL,
			.minus = NULL,
			.final = NULL
		}),

		.cur_key_spec = &((struct kv_key_spec)
		{
			.op = KV_OP_SET,
			.ns = KV_NS_DEVICE,
			.ns_part = _get_ns_part(cmd, KV_NS_DEVICE),
			.dom = KV_KEY_DOM_LAYER,
			.id = ID_NULL,
			.id_part = ID_NULL,
			.key = KV_KEY_GEN_GROUP_MEMBERS
		}),

		.rel_key_spec = &((struct kv_key_spec)
		{
			.op = KV_OP_SET,
			.ns = KV_NS_DEVICE,
			.ns_part = ID_NULL, /* will be calculated later */
			.dom = KV_KEY_DOM_LAYER,
			.id = ID_NULL,
			.id_part = ID_NULL,
			.key = KV_KEY_GEN_GROUP_IN
		})
	};

	struct kv_update_arg update_arg = {.res = cmd->kv_store_res,
		       .owner = OWNER_CORE,
		       .gen_buf = cmd->gen_buf,
		       .custom = &rel_spec
	};

	if (cmd->udev_dev.action != UDEV_ACTION_REMOVE) {
		if (!(s = buffer_fmt_add(cmd->gen_buf, "%s%s/%s",
		                         SYSTEM_SYSFS_PATH,
		                         cmd->udev_dev.path,
		                         SYSTEM_SYSFS_SLAVES))) {
			log_error(ID(cmd_res), "Failed to compose sysfs %s path for device " CMD_DEV_ID_FMT ".", SYSTEM_SYSFS_SLAVES, CMD_DEV_ID(cmd));
			goto out;
		}

		if ((count = scandir(s, &dirent, NULL, NULL)) < 0) {
			/*
			 * FIXME: Add code to deal with/warn about: (errno == ENOENT) && (cmd->udev_dev.action != UDEV_ACTION_REMOVE).
			 *        That means we don't have REMOVE uevent, but at the same time, we don't have sysfs content, e.g. because
			 *        we're processing this uevent too late: the device has already been removed right after this uevent
			 *        was triggered. For now, error out even in this case.
			 */
			log_sys_error(ID(cmd_res), "scandir", s);
			goto out;
		}

		buffer_rewind_mem(cmd->gen_buf, s);
	}

	/*
	 * Create vec_buf used to set up database records.
	 * (count - 2 + 3) == (count + 1)
	 * -2 to subtract "." and ".." directory which we're not interested in
	 * +3 for "seqnum|flags|owner" header
	 */
	if (!(vec_buf = buffer_create(BUFFER_TYPE_VECTOR, BUFFER_MODE_PLAIN, count + 1, 1))) {
		log_error(ID(cmd_res), "Failed to create buffer to record hierarchy for device " CMD_DEV_ID_FMT ".", CMD_DEV_ID(cmd));
		goto out;
	}

	/* Add record header to vec_buf: seqnum | flags | owner. */
	buffer_add(vec_buf, &cmd->udev_dev.seqnum, sizeof(cmd->udev_dev.seqnum));
	buffer_add(vec_buf, &kv_flags_no_persist, sizeof(kv_flags_no_persist));
	buffer_add(vec_buf, core_owner, strlen(core_owner) + 1);

	/* Read relatives from sysfs into vec_buf. */
	if (cmd->udev_dev.action != UDEV_ACTION_REMOVE) {
		for (i = 0; i < count; i++) {
			if (dirent[i]->d_name[0] == '.') {
				free(dirent[i]);
				continue;
			}

			if ((s = buffer_fmt_add(cmd->gen_buf, "%s%s/%s/%s/dev",
			                        SYSTEM_SYSFS_PATH,
			                        cmd->udev_dev.path,
			                        SYSTEM_SYSFS_SLAVES,
			                        dirent[i]->d_name))) {

				if (_get_sysfs_value(cmd_res, s, devno_buf, sizeof(devno_buf)) < 0)
					continue;
				buffer_rewind_mem(cmd->gen_buf, s);

				_canonicalize_kv_key(devno_buf);
				rel_spec.rel_key_spec->ns_part = devno_buf;

				s = _buffer_compose_key_prefix(cmd->gen_buf, rel_spec.rel_key_spec);
				buffer_add(vec_buf, (void *) s, strlen(s) + 1);
			} else
				log_error(ID(cmd_res), "Failed to compose sysfs path for device %s which is relative of device " CMD_DEV_ID_FMT ".",
				          dirent[i]->d_name, CMD_DEV_ID(cmd));

			free(dirent[i]);
		}
		free(dirent);
		rel_spec.rel_key_spec->ns_part = ID_NULL;
	}


	/* Get the actual vector with relatives and sort it. */
	buffer_get_data(vec_buf, (const void **) (&iov), &iov_cnt);
	qsort(iov + 3, iov_cnt - 3, sizeof(struct iovec), _iov_str_item_cmp);

	if (!(s = _buffer_compose_key(cmd->gen_buf, rel_spec.cur_key_spec))) {
		log_error(ID(cmd_res), _key_prefix_err_msg, cmd->udev_dev.name, cmd->udev_dev.major, cmd->udev_dev.minor);
		goto out;
	}

	/*
	 * Handle delta.final vector for this device.
	 * The delta.final is computed inside _kv_delta out of vec_buf.
	 * The _kv_delta also sets delta.plus and delta.minus vectors with info about changes when compared to previous record.
	 *
	 * Here, we set:
	 *	SID_{LUP,LDW} for current device
	 */
	iov = kv_store_set_value(cmd->kv_store_res, s, iov, iov_cnt, KV_STORE_VALUE_VECTOR | KV_STORE_VALUE_REF, 0,
	                         _kv_delta, &update_arg);

	r = 0;
out:
	_destroy_delta(rel_spec.delta);
	if (vec_buf)
		buffer_destroy(vec_buf);
	buffer_rewind_mem(cmd->gen_buf, tmp_mem_start);
	return r;
}

static int _refresh_device_partition_hierarchy_from_sysfs(sid_resource_t *cmd_res)
{
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(cmd_res);
	const char *tmp_mem_start = buffer_add(cmd->gen_buf, "", 0);
	struct iovec iov_to_store[_KV_VALUE_IDX_COUNT];
	char devno_buf[16];
	const char *s;
	int r = -1;

	struct kv_rel_spec rel_spec = {.delta = &((struct kv_delta)
		{
			.op = KV_OP_SET,
			.flags = DELTA_WITH_DIFF | DELTA_WITH_REL,
			.plus = NULL,
			.minus = NULL,
			.final = NULL
		}),

		.cur_key_spec = &((struct kv_key_spec)
		{
			.op = KV_OP_SET,
			.ns = KV_NS_DEVICE,
			.ns_part = _get_ns_part(cmd, KV_NS_DEVICE),
			.dom = KV_KEY_DOM_LAYER,
			.id = ID_NULL,
			.id_part = ID_NULL,
			.key = KV_KEY_GEN_GROUP_MEMBERS
		}),

		.rel_key_spec = &((struct kv_key_spec)
		{
			.op = KV_OP_SET,
			.ns = KV_NS_DEVICE,
			.ns_part = ID_NULL, /* will be calculated later */
			.dom = KV_KEY_DOM_LAYER,
			.id = ID_NULL,
			.id_part = ID_NULL,
			.key = KV_KEY_GEN_GROUP_IN
		})
	};

	struct kv_update_arg update_arg = {.res = cmd->kv_store_res,
		       .owner = OWNER_CORE,
		       .gen_buf = cmd->gen_buf,
		       .custom = &rel_spec
	};

	KV_VALUE_PREPARE_HEADER(iov_to_store, cmd->udev_dev.seqnum, kv_flags_no_persist, core_owner);

	if (!(s = buffer_fmt_add(cmd->gen_buf, "%s%s/../dev",
	                         SYSTEM_SYSFS_PATH,
	                         cmd->udev_dev.path))) {
		log_error(ID(cmd_res), "Failed to compose sysfs path for whole device of partition device " CMD_DEV_ID_FMT ".", CMD_DEV_ID(cmd));
		goto out;
	}

	if (_get_sysfs_value(cmd_res, s, devno_buf, sizeof(devno_buf)) < 0)
		goto out;
	buffer_rewind_mem(cmd->gen_buf, s);

	_canonicalize_kv_key(devno_buf);
	rel_spec.rel_key_spec->ns_part = devno_buf;

	s = _buffer_compose_key_prefix(cmd->gen_buf, rel_spec.rel_key_spec);
	iov_to_store[KV_VALUE_IDX_DATA] = (struct iovec) {
		(void *) s, strlen(s) + 1
	};

	rel_spec.rel_key_spec->ns_part = ID_NULL;

	if (!(s = _buffer_compose_key(cmd->gen_buf, rel_spec.cur_key_spec))) {
		log_error(ID(cmd_res), _key_prefix_err_msg, cmd->udev_dev.name, cmd->udev_dev.major, cmd->udev_dev.minor);
		goto out;
	}

	/*
	 * Handle delta.final vector for this device.
	 * The delta.final is computed inside _kv_delta out of vec_buf.
	 * The _kv_delta also sets delta.plus and delta.minus vectors with info about changes when compared to previous record.
	 *
	 * Here, we set:
	 *	SID_{LUP,LDW} for current device
	 */
	kv_store_set_value(cmd->kv_store_res, s, iov_to_store, _KV_VALUE_IDX_COUNT, KV_STORE_VALUE_VECTOR | KV_STORE_VALUE_REF, 0,
	                   _kv_delta, &update_arg);

	r = 0;
out:
	_destroy_delta(rel_spec.delta);
	buffer_rewind_mem(cmd->gen_buf, tmp_mem_start);
	return r;
}

static int _refresh_device_hierarchy_from_sysfs(sid_resource_t *cmd_res)
{
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(cmd_res);

	switch (cmd->udev_dev.type) {
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

static int _set_device_kv_records(sid_resource_t *cmd_res)
{
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(cmd_res);
	dev_ready_t ready;
	const dev_ready_t *p_ready;
	dev_reserved_t reserved;

	if (!(p_ready = sid_ubridge_cmd_get_kv(cmd, KV_NS_DEVICE, KV_KEY_DEV_READY, NULL, NULL))) {
		ready = DEV_NOT_RDY_UNPROCESSED;
		reserved = DEV_RES_UNPROCESSED;

		_do_sid_ubridge_cmd_set_kv(cmd, KV_NS_DEVICE, NULL, KV_KEY_DEV_READY, DEFAULT_KV_FLAGS_CORE, &ready, sizeof(ready));
		_do_sid_ubridge_cmd_set_kv(cmd, KV_NS_DEVICE, NULL, KV_KEY_DEV_RESERVED, DEFAULT_KV_FLAGS_CORE, &reserved, sizeof(reserved));
	}

	_refresh_device_hierarchy_from_sysfs(cmd_res);

	return 0;
}

static struct cmd_reg _cmd_scan_phase_regs[] = {
	[CMD_SCAN_PHASE_A_INIT]                   = {
		.name = "init",
		.flags = CMD_SCAN_CAP_RDY | CMD_SCAN_CAP_RES,
		.exec = NULL
	},

	[CMD_SCAN_PHASE_A_IDENT]                  = {
		.name = "ident",
		.flags = 0,
		.exec = _cmd_exec_ident
	},

	[CMD_SCAN_PHASE_A_SCAN_PRE]               = {
		.name = "scan-pre",
		.flags = CMD_SCAN_CAP_RDY,
		.exec = _cmd_exec_scan_pre
	},

	[CMD_SCAN_PHASE_A_SCAN_CURRENT]           = {
		.name = "scan-current",
		.flags = CMD_SCAN_CAP_RDY,
		.exec = _cmd_exec_scan_current
	},

	[CMD_SCAN_PHASE_A_SCAN_NEXT]              = {
		.name = "scan-next",
		.flags = CMD_SCAN_CAP_RES,
		.exec = _cmd_exec_scan_next
	},

	[CMD_SCAN_PHASE_A_SCAN_POST_CURRENT]      = {
		.name = "scan-post-current",
		.flags = 0,
		.exec = _cmd_exec_scan_post_current
	},

	[CMD_SCAN_PHASE_A_SCAN_POST_NEXT]         = {
		.name = "scan-post-next",
		.flags = 0,
		.exec = _cmd_exec_scan_post_next
	},

	[CMD_SCAN_PHASE_A_WAITING]                = {
		.name = "waiting",
		.flags = 0,
		.exec = NULL
	},

	[CMD_SCAN_PHASE_A_EXIT]                   = {
		.name = "exit",
		.flags = CMD_SCAN_CAP_RDY | CMD_SCAN_CAP_RES,
		.exec = NULL
	},

	[CMD_SCAN_PHASE_B_TRIGGER_ACTION_CURRENT] = {
		.name = "trigger-action-current",
		.flags = 0,
		.exec = _cmd_exec_trigger_action_current
	},

	[CMD_SCAN_PHASE_B_TRIGGER_ACTION_NEXT]    = {
		.name = "trigger-action-next",
		.flags = 0,
		.exec = _cmd_exec_trigger_action_next
	},

	[CMD_SCAN_PHASE_ERROR]                    = {
		.name = "error",
		.flags = 0,
		.exec = _cmd_exec_scan_error
	},
};

static int _cmd_exec_scan(struct cmd_exec_arg *exec_arg)
{
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(exec_arg->cmd_res);
	sid_resource_t *block_mod_registry_res;
	const char *mod_name;
	cmd_scan_phase_t phase;
	int r = -1;

	cmd->scan_phase = CMD_SCAN_PHASE_A_INIT;

	if (!(block_mod_registry_res = sid_resource_search(exec_arg->cmd_res, SID_RESOURCE_SEARCH_GENUS,
	                                                   &sid_resource_type_module_registry, MODULES_BLOCK_ID))) {
		log_error(ID(exec_arg->cmd_res), INTERNAL_ERROR "%s: Failed to find block module registry resource.", __func__);
		goto out;
	}

	if (!(exec_arg->block_mod_iter = sid_resource_iter_create(block_mod_registry_res))) {
		log_error(ID(exec_arg->cmd_res), "Failed to create block module iterator.");
		goto out;
	}

	if (!(exec_arg->type_mod_registry_res = sid_resource_search(block_mod_registry_res, SID_RESOURCE_SEARCH_SIB,
	                                                            &sid_resource_type_module_registry, MODULES_TYPE_ID))) {
		log_error(ID(exec_arg->cmd_res), INTERNAL_ERROR "%s: Failed to find type module registry resource.", __func__);
		goto out;
	}

	if (_set_device_kv_records(exec_arg->cmd_res) < 0) {
		log_error(ID(exec_arg->cmd_res), "Failed to set device hierarchy.");
		goto out;
	}

	if (!(mod_name = _lookup_module_name(exec_arg->cmd_res)))
		goto out;

	if (!(cmd->mod_res = exec_arg->type_mod_res_current = sid_module_registry_get_module(exec_arg->type_mod_registry_res, mod_name))) {
		log_debug(ID(exec_arg->cmd_res), "Module %s not loaded.", mod_name);
		goto out;
	}

	for (phase = __CMD_SCAN_PHASE_A_START; phase <= __CMD_SCAN_PHASE_A_END; phase++) {
		log_debug(ID(exec_arg->cmd_res), "Executing %s phase.", _cmd_scan_phase_regs[phase].name);
		cmd->scan_phase = phase;
		if ((r = _cmd_scan_phase_regs[phase].exec(exec_arg)) < 0) {
			log_error(ID(exec_arg->cmd_res), "%s phase failed.", _cmd_scan_phase_regs[phase].name);
			if (_cmd_scan_phase_regs[CMD_SCAN_PHASE_ERROR].exec(exec_arg) < 0)
				log_error(ID(exec_arg->cmd_res), "error phase failed.");
			goto out;
		}
	}
out:
	if (exec_arg->block_mod_iter) {
		(void) sid_resource_iter_destroy(exec_arg->block_mod_iter);
		exec_arg->block_mod_iter = NULL;
	}

	return r;
}

static int _cmd_exec_checkpoint(struct cmd_exec_arg *exec_arg)
{
	return 0;
}

static struct cmd_reg _cmd_regs[] = {
	[USID_CMD_ACTIVE] =     {.name = NULL, .flags = 0, .exec = _cmd_exec_unknown},
	[USID_CMD_CHECKPOINT] = {.name = NULL, .flags = 0, .exec = _cmd_exec_checkpoint},
	[USID_CMD_REPLY] =      {.name = NULL, .flags = 0, .exec = _cmd_exec_reply},
	[USID_CMD_SCAN] =       {.name = NULL, .flags = 0, .exec = _cmd_exec_scan},
	[USID_CMD_UNKNOWN] =    {.name = NULL, .flags = 0, .exec = _cmd_exec_unknown},
	[USID_CMD_VERSION] =    {.name = NULL, .flags = 0, .exec = _cmd_exec_version},
};

static int _export_kv_store(sid_resource_t *cmd_res)
{
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(cmd_res);
	struct kv_value *kv_value;
	kv_store_iter_t *iter;
	const char *key;
	void *value;
	bool vector;
	size_t size, iov_size, key_size, data_offset;
	kv_store_value_flags_t flags;
	struct iovec *iov;
	int export_fd = -1;
	size_t bytes_written = 0;
	unsigned i;
	ssize_t r;

	/*
	 * Export key-value store to udev or for sync with master kv store.
	 *
	 * For udev, we append key=value pairs to the output buffer that is sent back
	 * to udev as result of "usid scan" command.
	 *
	 * For others, we serialize the temp key-value store to an anonymous file in memory
	 * created by memfd_create. Then we pass the file FD over to worker proxy that reads
	 * it and it updates the "master" key-value store.
	 *
	 * We only send key=value pairs which are marked with KV_PERSISTENT flag.
	 */
	if (!(iter = kv_store_iter_create(cmd->kv_store_res))) {
		// TODO: Discard udev kv-store we've already appended to the output buffer!
		log_error(ID(cmd_res), "Failed to create iterator for temp key-value store.");
		return -1;
	}

	export_fd = memfd_create("kv_store_export", MFD_CLOEXEC);

	/* Reserve space to write the overall data size. */
	lseek(export_fd, sizeof(bytes_written), SEEK_SET);

	// FIXME: maybe buffer first so there's only single write
	while ((value = kv_store_iter_next(iter, &size, &flags))) {
		vector = flags & KV_STORE_VALUE_VECTOR;

		if (vector) {
			iov = value;
			iov_size = size;
			kv_value = NULL;

			if (!(KV_VALUE_FLAGS(iov) & KV_PERSISTENT))
				continue;

			KV_VALUE_FLAGS(iov) &= ~KV_PERSISTENT;
		} else {
			iov = NULL;
			iov_size = 0;
			kv_value = value;

			if (!(kv_value->flags & KV_PERSISTENT))
				continue;

			kv_value->flags &= ~KV_PERSISTENT;
		}

		key = kv_store_iter_current_key(iter);
		key_size = strlen(key) + 1;

		// TODO: Also deal with situation if the udev namespace values are defined as vectors by chance.
		if (_get_ns_from_key(key) == KV_NS_UDEV) {
			if (vector) {
				log_error(ID(cmd_res), INTERNAL_ERROR "%s: Unsupported vector value for key %s in udev namespace.",
				          __func__, key);
				return -1;
			}
			key = _get_key_part(key, KEY_PART_CORE, NULL);
			buffer_add(cmd->res_buf, (void *) key, strlen(key));
			buffer_add(cmd->res_buf, KV_PAIR_C, 1);
			data_offset = _kv_value_ext_data_offset(kv_value);
			buffer_add(cmd->res_buf, kv_value->data + data_offset, strlen(kv_value->data + data_offset));
			buffer_add(cmd->res_buf, KV_END_C, 1);
			continue;
		}

		/*
		 * Export keys with data to master process.
		 *
		 * Serialization format fields:
		 *
		 *  1) overall message size (size_t)
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

		/* FIXME: Try to reduce the "write" calls. */
		if ((r = write(export_fd, &flags, sizeof(flags))) == sizeof(flags))
			bytes_written += r;
		else
			goto bad;


		if ((r = write(export_fd, &key_size, sizeof(key_size))) == sizeof(key_size))
			bytes_written += r;
		else
			goto bad;

		if ((r = write(export_fd, &size, sizeof(size))) == sizeof(size))
			bytes_written += r;
		else
			goto bad;

		if ((r = write(export_fd, key, strlen(key) + 1)) == strlen(key) + 1)
			bytes_written += r;
		else
			goto bad;

		if (flags & KV_STORE_VALUE_VECTOR) {
			for (i = 0, size = 0; i < iov_size; i++) {
				size += iov[i].iov_len;

				if ((r = write(export_fd, &iov[i].iov_len, sizeof(iov->iov_len))) == sizeof(iov->iov_len))
					bytes_written += r;
				else
					goto bad;

				if ((r = write(export_fd, iov[i].iov_base, iov[i].iov_len)) == iov[i].iov_len)
					bytes_written += r;
				else
					goto bad;
			}
		} else {
			if ((r = write(export_fd, kv_value, size)) == size)
				bytes_written += r;
			else
				goto bad;
		}


	}

	lseek(export_fd, 0, SEEK_SET);
	if ((r = write(export_fd, &bytes_written, sizeof(bytes_written))) < 0)
		goto bad;
	lseek(export_fd, 0, SEEK_SET);

	if (bytes_written)
		worker_control_send(cmd_res, NULL, 0, export_fd);

	kv_store_iter_destroy(iter);

	close(export_fd);

	return 0;
bad:
	if (export_fd >= 0)
		close(export_fd);

	return -1;
}

static int _cmd_handler(sid_resource_event_source_t *es, void *data)
{
	sid_resource_t *cmd_res = data;
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(cmd_res);
	struct connection *conn = sid_resource_get_data(sid_resource_search(cmd_res, SID_RESOURCE_SEARCH_IMM_ANC, NULL, NULL));
	struct usid_msg_header response_header = {0};
	struct cmd_exec_arg exec_arg = {0};

	int r = -1;

	(void) buffer_add(cmd->res_buf, &response_header, sizeof(response_header));

	if (cmd->request_header.prot <= UBRIDGE_PROTOCOL) {
		/* If client speaks older protocol, reply using this protocol, if possible. */
		response_header.prot = cmd->request_header.prot;
		exec_arg.cmd_res = cmd_res;
		if ((r = _cmd_regs[cmd->request_header.cmd].exec(&exec_arg)) < 0)
			log_error(ID(cmd_res), "Failed to execute command");
	}

	if (_export_kv_store(cmd_res) < 0) {
		log_error(ID(cmd_res), "Failed to synchronize key-value store.");
		r = -1;
	}

	if (r < 0)
		response_header.status |= COMMAND_STATUS_FAILURE;

	(void) buffer_write(cmd->res_buf, conn->fd);

	return r;
}

static int _connection_cleanup(sid_resource_t *conn_res)
{
	sid_resource_t *worker_res = sid_resource_search(conn_res, SID_RESOURCE_SEARCH_IMM_ANC, NULL, NULL);
	sid_resource_iter_t *iter;
	sid_resource_t *cmd_res;

	if (!(iter = sid_resource_iter_create(conn_res)))
		return -1;

	while ((cmd_res = sid_resource_iter_next(iter)))
		(void) sid_resource_destroy(cmd_res);

	sid_resource_iter_destroy(iter);

	sid_resource_destroy(conn_res);

	// TODO: If there are more connections per worker used,
	// 	 then check if this is the last connection.
	// 	 If it's not the last one, then do not yield the worker.

	(void) worker_control_worker_yield(worker_res);

	return 0;
}

static int _on_connection_event(sid_resource_event_source_t *es, int fd, uint32_t revents, void *data)
{
	sid_resource_t *conn_res = data;
	struct connection *conn = sid_resource_get_data(conn_res);
	struct usid_msg msg;
	char id[32];
	ssize_t n;
	int r = 0;

	if (revents & EPOLLERR) {
		if (revents & EPOLLHUP)
			log_error(ID(conn_res), "Peer connection closed prematurely.");
		else
			log_error(ID(conn_res), "Connection error.");
		(void) _connection_cleanup(conn_res);
		return -1;
	}

	n = buffer_read(conn->buf, fd);
	if (n > 0) {
		if (buffer_is_complete(conn->buf)) {
			(void) buffer_get_data(conn->buf, (const void **) &msg.header, &msg.size);

			/* Sanitize command number - map all out of range command numbers to CMD_UNKNOWN. */
			if (msg.header->cmd < _USID_CMD_START || msg.header->cmd > _USID_CMD_END)
				msg.header->cmd = USID_CMD_UNKNOWN;

			snprintf(id, sizeof(id), "%d/%s", getpid(), usid_cmd_names[msg.header->cmd]);

			if (!sid_resource_create(conn_res, &sid_resource_type_ubridge_command, 0, id, &msg, NULL))
				log_error(ID(conn_res), "Failed to register command for processing.");

			(void) buffer_reset(conn->buf, 0, 1);
		}
	} else if (n < 0) {
		if (errno == EAGAIN || errno == EINTR)
			return 0;
		log_sys_error(ID(conn_res), "buffer_read_msg", "");
		r = -1;
	} else {
		if (_connection_cleanup(conn_res) < 0)
			r = -1;
	}

	return r;
}

static int _init_connection(sid_resource_t *res, const void *kickstart_data, void **data)
{
	struct connection *conn;

	if (!(conn = zalloc(sizeof(*conn)))) {
		log_error(ID(res), "Failed to allocate new connection structure.");
		goto fail;
	}

	memcpy(&conn->fd, kickstart_data, sizeof(int));

	if (sid_resource_create_io_event_source(res, NULL, conn->fd, _on_connection_event, "client connection", res) < 0) {
		log_error(ID(res), "Failed to register connection event handler.");
		goto fail;
	}

	if (!(conn->buf = buffer_create(BUFFER_TYPE_LINEAR, BUFFER_MODE_SIZE_PREFIX, 0, 1))) {
		log_error(ID(res), "Failed to create connection buffer.");
		goto fail;
	}

	*data = conn;
	return 0;
fail:
	if (conn) {
		if (conn->buf)
			buffer_destroy(conn->buf);
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
		buffer_destroy(conn->buf);

	free(conn);
	return 0;
}

static int _init_command(sid_resource_t *res, const void *kickstart_data, void **data)
{
	const struct usid_msg *msg = kickstart_data;
	struct sid_ubridge_cmd_context *cmd = NULL;
	const char *worker_id;
	int r;

	if (!(cmd = zalloc(sizeof(*cmd)))) {
		log_error(ID(res), "Failed to allocate new command structure.");
		return -1;
	}

	if (!(cmd->res_buf = buffer_create(BUFFER_TYPE_VECTOR, BUFFER_MODE_SIZE_PREFIX, 0, 1))) {
		log_error(ID(res), "Failed to create response buffer.");
		goto fail;
	}

	cmd->request_header = *msg->header;

	if (!(cmd->gen_buf = buffer_create(BUFFER_TYPE_LINEAR, BUFFER_MODE_PLAIN, 0, PATH_MAX))) {
		log_error(ID(res), "Failed to create generic buffer.");
		goto fail;
	}

	if (!(cmd->kv_store_res = sid_resource_search(res, SID_RESOURCE_SEARCH_GENUS,
	                                              &sid_resource_type_kv_store, MAIN_KV_STORE_NAME))) {
		log_error(ID(res), INTERNAL_ERROR "%s: Failed to find key-value store.", __func__);
		goto fail;
	}

	if (msg->header->cmd == USID_CMD_SCAN) {
		/* currently, we only parse udev environment for the SCAN command */
		if ((r = _parse_cmd_nullstr_udev_env(cmd, msg->header->data, msg->size - sizeof(*msg->header))) < 0) {
			log_error_errno(ID(res), r, "Failed to parse udev environment variables.");
			goto fail;
		}
	}

	if (!(worker_id = worker_control_get_worker_id(res))) {
		log_error(ID(res), "Failed to get worker ID to set %s udev variable.", KV_KEY_UDEV_SID_SESSION_ID);
		goto fail;
	}

	if (!_do_sid_ubridge_cmd_set_kv(cmd, KV_NS_UDEV, NULL, KV_KEY_UDEV_SID_SESSION_ID, KV_PERSISTENT, worker_id, strlen(worker_id) + 1)) {
		log_error(ID(res), "Failed to set %s udev variable.", KV_KEY_UDEV_SID_SESSION_ID);
		goto fail;
	}


	if (sid_resource_create_deferred_event_source(res, NULL, _cmd_handler, "command handler", res) < 0) {
		log_error(ID(res), "Failed to register command handler.");
		goto fail;
	}

	*data = cmd;
	return 0;
fail:
	if (cmd) {
		if (cmd->gen_buf)
			buffer_destroy(cmd->gen_buf);
		free(cmd);
	}
	return -1;
}

static int _destroy_command(sid_resource_t *res)
{
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(res);

	buffer_destroy(cmd->gen_buf);
	buffer_destroy(cmd->res_buf);
	free(cmd->dev_id);
	free(cmd);
	return 0;
}

static int _master_kv_store_unset(const char *full_key, struct kv_store_update_spec *spec, void *garg)
{
	struct kv_update_arg *arg = garg;
	struct iovec tmp_iov_old[_KV_VALUE_IDX_COUNT];
	struct iovec *iov_old;

	if (!spec->old_data)
		return 1;

	iov_old = _get_value_vector(spec->old_flags, spec->old_data, spec->old_data_size, tmp_iov_old);

	if (_flags_indicate_mod_owned(KV_VALUE_FLAGS(iov_old)) && strcmp(KV_VALUE_OWNER(iov_old), arg->owner)) {
		log_debug(ID(arg->res), "Refusing request from module %s to unset existing value for key %s (seqnum %" PRIu64
		          "which belongs to module %s.",  arg->owner, full_key, KV_VALUE_SEQNUM(iov_old),
		          KV_VALUE_OWNER(iov_old));
		arg->ret_code = EBUSY;
		return 0;
	}

	return 1;
}

static int _master_kv_store_update(const char *full_key, struct kv_store_update_spec *spec, void *garg)
{
	struct kv_update_arg *arg = garg;
	struct kv_rel_spec *rel_spec = arg->custom;
	struct iovec tmp_iov_old[_KV_VALUE_IDX_COUNT];
	struct iovec tmp_iov_new[_KV_VALUE_IDX_COUNT];
	struct iovec *iov_old, *iov_new;
	int r;

	iov_old = _get_value_vector(spec->old_flags, spec->old_data, spec->old_data_size, tmp_iov_old);
	iov_new = _get_value_vector(spec->new_flags, spec->new_data, spec->new_data_size, tmp_iov_new);

	if (rel_spec->delta->op == KV_OP_SET)
		/* overwrite whole value */
		r = (!iov_old ||
		     ((KV_VALUE_SEQNUM(iov_new) >= KV_VALUE_SEQNUM(iov_old)) &&
		      _kv_overwrite(full_key, spec, arg)));
	else {
		/* resolve delta */
		r = _kv_delta(full_key, spec, garg);
		/* resolving delta might have changed new_data so get it afresh for the log_debug below */
		iov_new = _get_value_vector(spec->new_flags, spec->new_data, spec->new_data_size, tmp_iov_new);
	}

	if (r)
		log_debug(ID(arg->res), "Updating value for key %s (new seqnum %" PRIu64 " >= old seqnum %" PRIu64 ")",
		          full_key, KV_VALUE_SEQNUM(iov_new), iov_old ? KV_VALUE_SEQNUM(iov_old) : 0);
	else
		log_debug(ID(arg->res), "Keeping old value for key %s (new seqnum %" PRIu64 " < old seqnum %" PRIu64 ")",
		          full_key, KV_VALUE_SEQNUM(iov_new), iov_old ? KV_VALUE_SEQNUM(iov_old) : 0);

	return r;
}

static int _sync_master_kv_store(sid_resource_t *worker_proxy_res, sid_resource_t *ubridge_res, int fd)
{
	static const char syncing_msg[] = "Syncing master key-value store:  %s=%s (seqnum %" PRIu64 ")";
	struct ubridge *ubridge = sid_resource_get_data(ubridge_res);
	kv_store_value_flags_t flags;
	size_t msg_size, full_key_size, data_size, data_offset, i;
	char *full_key, *shm = NULL, *p, *end;
	struct kv_value *value = NULL;
	struct iovec *iov = NULL;
	void *data_to_store;
	struct kv_rel_spec rel_spec = {.delta = &((struct kv_delta)
		{
			0
		})
	};
	struct kv_update_arg update_arg = {.gen_buf = ubridge->cmd_mod.gen_buf, .custom = &rel_spec};
	int unset;
	int r = -1;

	if (read(fd, &msg_size, sizeof(msg_size)) != sizeof(msg_size)) {
		log_error_errno(ID(worker_proxy_res), errno, "Failed to read shared memory size");
		goto out;
	}

	if ((p = shm = mmap(NULL, msg_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED) {
		log_error_errno(ID(worker_proxy_res), errno, "Failed to map memory with key-value store");
		goto out;
	}

	p += sizeof(msg_size);
	end = p + msg_size;

	while (p < end) {
		flags = *((kv_store_value_flags_t *) p);
		p+= sizeof(flags);

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
				log_error(ID(worker_proxy_res), "Received incorrect vector of size %zu to sync with master key-value store.",
				          data_size);
				goto out;
			}

			if (!(iov = malloc(data_size * sizeof(struct iovec)))) {
				log_error(ID(worker_proxy_res), "Failed to allocate vector to sync master key-value store.");
				goto out;
			}

			for (i = 0; i < data_size; i++) {
				iov[i].iov_len = *((size_t *) p);
				p += sizeof(size_t);
				iov[i].iov_base = p;
				p += iov[i].iov_len;
			}

			unset = !(KV_VALUE_FLAGS(iov) & KV_MOD_RESERVED) && (data_size == KV_VALUE_IDX_DATA);

			update_arg.owner = KV_VALUE_OWNER(iov);
			update_arg.res = ubridge->main_kv_store_res;
			update_arg.ret_code = 0;

			log_debug(ID(worker_proxy_res), syncing_msg, full_key,
			          unset ? "NULL" : "[vector]", KV_VALUE_SEQNUM(iov));

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
					log_error(ID(worker_proxy_res), INTERNAL_ERROR
					          "Illegal operator found for key %s while trying to sync master key-value store.", full_key);
					goto out;
			}

			data_to_store = iov;
		} else {
			if (data_size <= sizeof(struct kv_value)) {
				log_error(ID(worker_proxy_res), "Received incorrect value of size %zu to sync with master key-value store.",
				          data_size);
				goto out;
			}

			value = (struct kv_value *) p;
			p += data_size;

			data_offset = _kv_value_ext_data_offset(value);
			unset = ((value->flags != KV_MOD_RESERVED) &&
			         (data_size == (sizeof(struct kv_value) + data_offset)));

			update_arg.owner = value->data;
			update_arg.res = ubridge->main_kv_store_res;
			update_arg.ret_code = 0;

			log_debug(ID(worker_proxy_res), syncing_msg, full_key,
			          unset ? "NULL"
			          : data_offset ? value->data + data_offset
			          : value->data, value->seqnum);

			rel_spec.delta->op = KV_OP_SET;

			data_to_store = value;
		}

		if (unset)
			kv_store_unset_value(ubridge->main_kv_store_res, full_key, _master_kv_store_unset, &update_arg);
		else
			kv_store_set_value(ubridge->main_kv_store_res, full_key, data_to_store, data_size, flags, 0,
			                   _master_kv_store_update, &update_arg);

		_destroy_delta(rel_spec.delta);
		free(iov);
		iov = NULL;
	}

	r = 0;

	//_dump_kv_store(__func__, ubridge->main_kv_store_res);
	_dump_kv_store_dev_stack_in_dot(__func__, ubridge->main_kv_store_res);
out:
	free(iov);

	if (shm && munmap(shm, msg_size) < 0) {
		log_error_errno(ID(worker_proxy_res), errno, "Failed to unmap memory with key-value store");
		r = -1;
	}

	return r;
}

static int _worker_recv_fn(sid_resource_t *worker_res, void *data, size_t data_size, int fd, void *arg)
{
	sid_resource_t *conn_res;

	if (!(conn_res = sid_resource_create(worker_res, &sid_resource_type_ubridge_connection, 0, NULL, &fd, NULL))) {
		log_error(ID(worker_res), "Failed to create connection resource.");
		return -1;
	}

	return 0;
}

static int _worker_proxy_recv_fn(sid_resource_t *worker_proxy_res, void *data, size_t data_size, int fd, void *arg)
{
	_sync_master_kv_store(worker_proxy_res, arg, fd);
	close(fd);

	return 0;
}

static int _worker_init_fn(sid_resource_t *worker_res, void *init_fn_arg)
{
	struct ubridge *ubridge = init_fn_arg;

	(void) sid_resource_isolate_with_children(ubridge->modules_res);
	(void) sid_resource_isolate_with_children(ubridge->main_kv_store_res);

	(void) sid_resource_add_child(worker_res, ubridge->modules_res);
	(void) sid_resource_add_child(worker_res, ubridge->main_kv_store_res);

	worker_control_set_recv_callback(worker_res, _worker_recv_fn, NULL);

	return 0;
}

static int _on_ubridge_interface_event(sid_resource_event_source_t *es, int fd, uint32_t revents, void *data)
{
	char uuid[UTIL_UUID_STR_SIZE];
	sid_resource_t *ubridge_res = data;
	struct ubridge *ubridge = sid_resource_get_data(ubridge_res);
	sid_resource_t *worker_proxy_res;
	int conn_fd;

	log_debug(ID(ubridge_res), "Received an event.");

	if (!(worker_proxy_res = worker_control_get_idle_worker(ubridge->worker_control_res))) {
		log_debug(ID(ubridge_res), "Idle worker not found, creating a new one.");

		if (!util_uuid_gen_str(uuid, sizeof(uuid))) {
			log_error(ID(ubridge_res), "Failed to generate UUID for new worker.");
			return -1;
		}

		if (!(worker_proxy_res = worker_control_get_new_worker(ubridge->worker_control_res, uuid, _worker_init_fn, ubridge)))
			return -1;
	}

	/* worker never reaches this point, only worker-proxy does */

	worker_control_set_recv_callback(worker_proxy_res, _worker_proxy_recv_fn, ubridge_res);

	if ((conn_fd = accept4(ubridge->socket_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC)) < 0) {
		log_sys_error(ID(ubridge_res), "accept", "");
		return -1;
	}

	if (worker_control_send(worker_proxy_res, NULL, 0, conn_fd) < 0) {
		log_sys_error(ID(ubridge_res), "worker_control_send_to_worker", "");
		(void) close(conn_fd);
		return -1;
	}

	(void) close(conn_fd);
	return 0;
}

static int _on_ubridge_udev_monitor_event(sid_resource_event_source_t *es, int fd, uint32_t revents, void *data)
{
	sid_resource_t *res = data;
	struct ubridge *ubridge = sid_resource_get_data(res);
	sid_resource_t *worker_proxy_res;
	struct udev_device *udev_dev;
	const char *worker_id;
	int r = -1;

	if (!(udev_dev = udev_monitor_receive_device(ubridge->umonitor.mon)))
		goto out;

	if (!(worker_id = udev_device_get_property_value(udev_dev, KV_KEY_UDEV_SID_SESSION_ID)))
		goto out;

	if (!(worker_proxy_res = worker_control_find_worker(ubridge->worker_control_res, worker_id)))
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
	int fd;

	if (service_fd_activation_present(1)) {
		if (!(val = getenv(SERVICE_KEY_ACTIVATION_TYPE))) {
			log_error(ID(ubridge_res), "Missing %s key in environment.",
			          SERVICE_KEY_ACTIVATION_TYPE);
			return -ENOKEY;
		}

		if (strcmp(val, SERVICE_VALUE_ACTIVATION_FD)) {
			log_error(ID(ubridge_res), "Incorrect value for key %s: %s.",
			          SERVICE_VALUE_ACTIVATION_FD, val);
			return -EINVAL;
		}

		/* The very first FD passed in is the one we are interested in. */
		fd = SERVICE_FD_ACTIVATION_FDS_START;

		if (!(service_fd_is_socket_unix(fd, SOCK_STREAM, 1, UBRIDGE_SOCKET_PATH, UBRIDGE_SOCKET_PATH_LEN))) {
			log_error(ID(ubridge_res), "Passed file descriptor is of incorrect type.");
			return -EINVAL;
		}
	} else {
		/* No systemd autoactivation - create new socket FD. */
		if ((fd = comms_unix_create(UBRIDGE_SOCKET_PATH, UBRIDGE_SOCKET_PATH_LEN, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC)) < 0) {
			log_error_errno(ID(ubridge_res), fd, "Failed to create local server socket.");
			return fd;
		}
	}

	*ubridge_socket_fd = fd;
	return 0;
}

static int _set_up_udev_monitor(sid_resource_t *ubridge_res, struct umonitor *umonitor)
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

	if (sid_resource_create_io_event_source(ubridge_res, NULL, umonitor_fd,
	                                        _on_ubridge_udev_monitor_event, "udev monitor", ubridge_res) < 0) {
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

static struct sid_module_registry_resource_params block_res_mod_params = {.directory     = UBRIDGE_CMD_BLOCK_MODULE_DIRECTORY,
	       .flags         = SID_MODULE_REGISTRY_PRELOAD,
	       .callback_arg  = NULL,
	       .symbol_params =
	{
		{
			UBRIDGE_CMD_MODULE_FN_NAME_IDENT,
			SID_MODULE_SYMBOL_INDIRECT,
		},
		{
			UBRIDGE_CMD_MODULE_FN_NAME_SCAN_PRE,
			SID_MODULE_SYMBOL_INDIRECT,
		},
		{
			UBRIDGE_CMD_MODULE_FN_NAME_SCAN_CURRENT,
			SID_MODULE_SYMBOL_INDIRECT,
		},
		{
			UBRIDGE_CMD_MODULE_FN_NAME_SCAN_NEXT,
			SID_MODULE_SYMBOL_INDIRECT,
		},
		{
			UBRIDGE_CMD_MODULE_FN_NAME_SCAN_POST_CURRENT,
			SID_MODULE_SYMBOL_INDIRECT,
		},
		{
			UBRIDGE_CMD_MODULE_FN_NAME_SCAN_POST_NEXT,
			SID_MODULE_SYMBOL_INDIRECT,
		},
		{
			UBRIDGE_CMD_MODULE_FN_NAME_TRIGGER_ACTION_CURRENT,
			SID_MODULE_SYMBOL_INDIRECT,
		},
		{
			UBRIDGE_CMD_MODULE_FN_NAME_TRIGGER_ACTION_NEXT,
			SID_MODULE_SYMBOL_INDIRECT,
		},
		{
			UBRIDGE_CMD_MODULE_FN_NAME_ERROR,
			SID_MODULE_SYMBOL_FAIL_ON_MISSING |
			SID_MODULE_SYMBOL_INDIRECT,
		},
		{NULL, 0}
	}
};

static struct sid_module_registry_resource_params type_res_mod_params = {.directory     = UBRIDGE_CMD_TYPE_MODULE_DIRECTORY,
	       .flags         = SID_MODULE_REGISTRY_PRELOAD,
	       .callback_arg  = NULL,
	       .symbol_params =
	{
		{
			UBRIDGE_CMD_MODULE_FN_NAME_IDENT,
			SID_MODULE_SYMBOL_FAIL_ON_MISSING |
			SID_MODULE_SYMBOL_INDIRECT,
		},
		{
			UBRIDGE_CMD_MODULE_FN_NAME_SCAN_PRE,
			SID_MODULE_SYMBOL_INDIRECT,
		},
		{
			UBRIDGE_CMD_MODULE_FN_NAME_SCAN_CURRENT,
			SID_MODULE_SYMBOL_INDIRECT,
		},
		{
			UBRIDGE_CMD_MODULE_FN_NAME_SCAN_NEXT,
			SID_MODULE_SYMBOL_INDIRECT,
		},
		{
			UBRIDGE_CMD_MODULE_FN_NAME_SCAN_POST_CURRENT,
			SID_MODULE_SYMBOL_INDIRECT,
		},
		{
			UBRIDGE_CMD_MODULE_FN_NAME_SCAN_POST_NEXT,
			SID_MODULE_SYMBOL_INDIRECT,
		},
		{
			UBRIDGE_CMD_MODULE_FN_NAME_TRIGGER_ACTION_CURRENT,
			SID_MODULE_SYMBOL_INDIRECT,
		},
		{
			UBRIDGE_CMD_MODULE_FN_NAME_TRIGGER_ACTION_NEXT,
			SID_MODULE_SYMBOL_INDIRECT,
		},
		{
			UBRIDGE_CMD_MODULE_FN_NAME_ERROR,
			SID_MODULE_SYMBOL_FAIL_ON_MISSING |
			SID_MODULE_SYMBOL_INDIRECT,
		},
		{NULL, 0}
	}
};

static const struct sid_kv_store_resource_params main_kv_store_res_params = {.backend = KV_STORE_BACKEND_HASH,
	       .hash.initial_size = 32
};

static int _init_ubridge(sid_resource_t *res, const void *kickstart_data, void **data)
{
	struct ubridge *ubridge = NULL;

	if (!(ubridge = zalloc(sizeof(struct ubridge)))) {
		log_error(ID(res), "Failed to allocate memory for interface structure.");
		goto fail;
	}
	ubridge->socket_fd = -1;

	if (!(ubridge->internal_res = sid_resource_create(res, &sid_resource_type_aggregate,
	                                                  SID_RESOURCE_RESTRICT_WALK_UP |
	                                                  SID_RESOURCE_RESTRICT_WALK_DOWN |
	                                                  SID_RESOURCE_DISALLOW_ISOLATION,
	                                                  INTERNAL_AGGREGATE_ID, ubridge, NULL))) {
		log_error(ID(res), "Failed to create internal ubridge resource.");
		goto fail;
	}

	if (!(ubridge->main_kv_store_res = sid_resource_create(ubridge->internal_res, &sid_resource_type_kv_store, SID_RESOURCE_RESTRICT_WALK_UP,
	                                                       MAIN_KV_STORE_NAME, &main_kv_store_res_params, NULL))) {
		log_error(ID(res), "Failed to create main key-value store.");
		goto fail;
	}

	if (!(ubridge->worker_control_res = sid_resource_create(ubridge->internal_res, &sid_resource_type_worker_control, 0,
	                                                        NULL, NULL, NULL))) {
		log_error(ID(res), "Failed to create worker control.");
		goto fail;
	}

	if (!(ubridge->cmd_mod.gen_buf = buffer_create(BUFFER_TYPE_LINEAR, BUFFER_MODE_PLAIN, 0, PATH_MAX))) {
		log_error(ID(res), "Failed to create generic buffer.");
		goto fail;
	}

	ubridge->cmd_mod.kv_store_res = ubridge->main_kv_store_res;

	block_res_mod_params.callback_arg = type_res_mod_params.callback_arg = &ubridge->cmd_mod;

	if (!(ubridge->modules_res = sid_resource_create(ubridge->internal_res, &sid_resource_type_aggregate, 0, MODULES_AGGREGATE_ID,
	                                                 NULL, NULL))) {
		log_error(ID(res), "Failed to create aggreagete resource for module handlers.");
		goto fail;
	}

	if (!(sid_resource_create(ubridge->modules_res, &sid_resource_type_module_registry, SID_RESOURCE_DISALLOW_ISOLATION, MODULES_BLOCK_ID,
	                          &block_res_mod_params, NULL)) ||
	    !(sid_resource_create(ubridge->modules_res, &sid_resource_type_module_registry, SID_RESOURCE_DISALLOW_ISOLATION, MODULES_TYPE_ID,
	                          &type_res_mod_params, NULL))) {
		log_error(ID(res), "Failed to create module handler.");
		goto fail;
	}

	if (_set_up_ubridge_socket(res, &ubridge->socket_fd) < 0) {
		log_error(ID(res), "Failed to set up local server socket.");
		goto fail;
	}

	if (sid_resource_create_io_event_source(res, NULL, ubridge->socket_fd, _on_ubridge_interface_event, UBRIDGE_NAME, res) < 0) {
		log_error(ID(res), "Failed to register interface with event loop.");
		goto fail;
	}

	if (_set_up_udev_monitor(res, &ubridge->umonitor) < 0) {
		log_error(ID(res), "Failed to set up udev monitor.");
		goto fail;
	}

	block_res_mod_params.callback_arg = type_res_mod_params.callback_arg = NULL;
	//sid_resource_dump_all_in_dot(sid_resource_search(res, SID_RESOURCE_SEARCH_TOP, NULL, NULL));

	*data = ubridge;
	return 0;
fail:
	if (ubridge) {
		if (ubridge->cmd_mod.gen_buf)
			buffer_destroy(ubridge->cmd_mod.gen_buf);
		block_res_mod_params.callback_arg = type_res_mod_params.callback_arg = NULL;
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

	if (ubridge->cmd_mod.gen_buf)
		buffer_destroy(ubridge->cmd_mod.gen_buf);

	if (ubridge->socket_fd != -1)
		(void) close(ubridge->socket_fd);

	free(ubridge);
	return 0;
}

const sid_resource_type_t sid_resource_type_ubridge_command = {
	.name = COMMAND_NAME,
	.init = _init_command,
	.destroy = _destroy_command,
};

const sid_resource_type_t sid_resource_type_ubridge_connection = {
	.name = CONNECTION_NAME,
	.init = _init_connection,
	.destroy = _destroy_connection,
};

const sid_resource_type_t sid_resource_type_ubridge = {
	.name = UBRIDGE_NAME,
	.init = _init_ubridge,
	.destroy = _destroy_ubridge,
};
