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

#include "configure.h"
#include "buffer.h"
#include "comms.h"
#include "kv-store.h"
#include "list.h"
#include "log.h"
#include "mem.h"
#include "module-registry.h"
#include "resource.h"
#include "ubridge-cmd-module.h"
#include "util.h"
#include "worker-control.h"

#include <ctype.h>
#include <dirent.h>
#include <libudev.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <unistd.h>

#define UBRIDGE_PROTOCOL             1
#define UBRIDGE_SOCKET_PATH          "@sid-ubridge.socket"

#define UBRIDGE_NAME                 "ubridge"
#define CONNECTION_NAME              "connection"
#define COMMAND_NAME                 "command"

#define INTERNAL_AGGREGATE_ID        "ubridge-internal"
#define MODULES_AGGREGATE_ID         "modules"
#define MODULES_BLOCK_ID             "block"
#define MODULES_TYPE_ID              "type"

#define COMMAND_STATUS_MASK_OVERALL  UINT64_C(0x0000000000000001)
#define COMMAND_STATUS_SUCCESS       UINT64_C(0x0000000000000000)
#define COMMAND_STATUS_FAILURE       UINT64_C(0x0000000000000001)

#define PROC_DEVICES_PATH            "/proc/devices"

#define UBRIDGE_CMD_BLOCK_MODULE_DIRECTORY "/usr/local/lib/sid/modules/ubridge-cmd/block"
#define UBRIDGE_CMD_TYPE_MODULE_DIRECTORY  "/usr/local/lib/sid/modules/ubridge-cmd/type"

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

#define KV_PAIR             "="
#define KV_END              ""

#define ID_NULL ""

#define KV_PREFIX_NULL           ID_NULL
#define KV_PREFIX_OP_DELTA_PLUS  "+"
#define KV_PREFIX_OP_DELTA_MINUS "-"
#define KV_PREFIX_NS_UDEV        "U"
#define KV_PREFIX_NS_DEVICE      "D"
#define KV_PREFIX_NS_MODULE      "M"
#define KV_PREFIX_NS_GLOBAL      "G"

#define KV_KEY_DEV_READY         "SID_RDY"
#define KV_KEY_DEV_RESERVED      "SID_RES"
#define KV_KEY_DEV_LAYER_UP      "SID_LUP"
#define KV_KEY_DEV_LAYER_DOWN    "SID_LDW"
#define KV_KEY_DEV_MOD           "SID_MOD"
#define KV_KEY_DEV_NEXT_MOD      SID_UBRIDGE_CMD_KEY_DEVICE_NEXT_MOD
#define KV_KEY_GEN_GROUP_MEMBERS "SID_GMB"
#define KV_KEY_GEN_GROUP_IN      "SID_GIN"

#define CORE_MOD_NAME         "core"
#define DEFAULT_CORE_KV_FLAGS  KV_PERSISTENT | KV_MOD_RESERVED | KV_MOD_PRIVATE

#define UDEV_KEY_ACTION     "ACTION"
#define UDEV_KEY_DEVNAME    "DEVNAME"
#define UDEV_KEY_DEVTYPE    "DEVTYPE"
#define UDEV_KEY_MAJOR      "MAJOR"
#define UDEV_KEY_MINOR      "MINOR"
#define UDEV_KEY_SEQNUM     "SEQNUM"
#define UDEV_KEY_SYNTH_UUID "SYNTH_UUID"

#define CMD_DEV_ID_FMT  "%s (%d:%d)"
#define CMD_DEV_ID(cmd) cmd->udev_dev.name, cmd->udev_dev.major, cmd->udev_dev.minor

/* internal resources */
const sid_resource_reg_t sid_resource_reg_ubridge_connection;
const sid_resource_reg_t sid_resource_reg_ubridge_command;

struct sid_ubridge_cmd_mod_context {
	sid_resource_t *kv_store_res;
	struct buffer *gen_buf;
};

struct ubridge {
	int socket_fd;
	sid_event_source *es;
	sid_resource_t *internal_res;
	sid_resource_t *modules_res;
	sid_resource_t *main_kv_store_res;
	sid_resource_t *worker_control_res;
	struct sid_ubridge_cmd_mod_context cmd_mod;
};

typedef enum {
	__CMD_START = 0,
	CMD_UNKNOWN = 0,
	CMD_REPLY = 1,
	CMD_VERSION = 2,
	CMD_IDENTIFY = 3,
	CMD_CHECKPOINT = 4,
	__CMD_END
} command_t;

typedef enum {
	CMD_IDENT_PHASE_A_INIT = 0,                                     /* initializing phase "A" */

	__CMD_IDENT_PHASE_A_START = 1,                                  /* phase "A" module processing starts */
	CMD_IDENT_PHASE_A_IDENT = __CMD_IDENT_PHASE_A_START,            /* module */
	CMD_IDENT_PHASE_A_SCAN_PRE,                                     /* module */
	CMD_IDENT_PHASE_A_SCAN_CURRENT,                                 /* module */
	CMD_IDENT_PHASE_A_SCAN_NEXT,                                    /* module */
	CMD_IDENT_PHASE_A_SCAN_POST_CURRENT,                            /* module */
	CMD_IDENT_PHASE_A_SCAN_POST_NEXT,                               /* module */
	__CMD_IDENT_PHASE_A_END = CMD_IDENT_PHASE_A_SCAN_POST_NEXT,     /* phase "A" module processing ends */

	CMD_IDENT_PHASE_A_WAITING,                                      /* phase "A" waiting for confirmation */

	CMD_IDENT_PHASE_A_EXIT,                                         /* exiting phase "A" */

	CMD_IDENT_PHASE_B_TRIGGER_ACTION_CURRENT,
	__CMD_IDENT_PHASE_B_TRIGGER_ACTION_START = CMD_IDENT_PHASE_B_TRIGGER_ACTION_CURRENT,
	CMD_IDENT_PHASE_B_TRIGGER_ACTION_NEXT,
	__CMD_IDENT_PHASE_B_TRIGGER_ACTION_END = CMD_IDENT_PHASE_B_TRIGGER_ACTION_NEXT,

	CMD_IDENT_PHASE_ERROR,
} cmd_ident_phase_t;

struct raw_command_header {
	uint8_t protocol;
	uint8_t cmd_number;	/* IN: cmd number  OUT: CMD_RESPONSE */
	uint64_t status;	/* IN: udev seqnum OUT: response status */
	char data[0];
} __attribute__((packed));

struct raw_command {
	struct raw_command_header *header;
	size_t len;		/* header + data */
};

struct version {
	uint16_t major;
	uint16_t minor;
	uint16_t release;
} __attribute__((packed));

struct udevice {
	udev_action_t action;
	int major;
	int minor;
	char *name;
	char *type;
	uint64_t seqnum;
	char *synth_uuid;
};

struct connection {
	int fd;
	sid_event_source *es;
	struct buffer *buf;
};

struct sid_ubridge_cmd_context {
	uint8_t protocol;
	command_t type;
	union {
		cmd_ident_phase_t ident_phase;
	};
	uint16_t status;
	sid_event_source *es;
	char *dev_id;
	struct udevice udev_dev;
	sid_resource_t *kv_store_res;
	sid_resource_t *mod_res; /* the module that is processed at the moment */
	struct buffer *gen_buf;
	struct buffer *result_buf;

};

struct command_module_fns {
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

struct udev_monitor_setup {
	struct udev *udev;
	struct udev_monitor *monitor;
	sid_event_source *es;
	char tag[25]; /* "sid_<20_chars_for_64_bit_uevent_seqnum_in_decimal>" + "\0" */
};

struct command_exec_args {
	sid_resource_t *cmd_res;
	sid_resource_t *type_mod_registry_res;
	sid_resource_iter_t *block_mod_iter;  /* all block modules to execute */
	sid_resource_t *type_mod_res_current; /* one type module for current layer to execute */
	sid_resource_t *type_mod_res_next;    /* one type module for next layer to execute */
	struct udev_monitor_setup umonitor;
};

struct command_reg {
	const char *name;
	uint32_t flags;
	int (*execute) (struct command_exec_args *exec_arg);
};

struct ubridge_kv_value {
	uint64_t seqnum;
	sid_ubridge_kv_flags_t flags;
	char data[0];
} __attribute__((packed));

enum {
	VALUE_VECTOR_IDX_SEQNUM,
	VALUE_VECTOR_IDX_FLAGS,
	VALUE_VECTOR_IDX_MOD_NAME,
	VALUE_VECTOR_IDX_DATA,
	_VALUE_VECTOR_IDX_COUNT,
};

#define VALUE_VECTOR_PREPARE_HEADER(iov, seqnum, flags, mod_name) \
		iov[VALUE_VECTOR_IDX_SEQNUM] = (struct iovec) {&(seqnum), sizeof(seqnum)}; \
		iov[VALUE_VECTOR_IDX_FLAGS] = (struct iovec) {&(flags), sizeof(flags)}; \
		iov[VALUE_VECTOR_IDX_MOD_NAME] = (struct iovec) {mod_name, strlen(mod_name) + 1};

#define VALUE_VECTOR_SEQNUM(iov) (*((uint64_t *) ((struct iovec *) iov)[VALUE_VECTOR_IDX_SEQNUM].iov_base))
#define VALUE_VECTOR_FLAGS(iov) (*((sid_ubridge_kv_flags_t *) ((struct iovec *) iov)[VALUE_VECTOR_IDX_FLAGS].iov_base))
#define VALUE_VECTOR_MOD_NAME(iov) ((char *) ((struct iovec *) iov)[VALUE_VECTOR_IDX_MOD_NAME].iov_base)
#define VALUE_VECTOR_DATA(iov) (((struct iovec *) iov)[VALUE_VECTOR_IDX_DATA].iov_base)

struct key_prefix_spec {
	const char *prefix;
	sid_ubridge_cmd_kv_namespace_t ns;
	const char *id;
	const char *id_sub;
};

struct kv_update_arg {
	sid_resource_t *res;
	struct buffer *gen_buf;
	const char *mod_name; /* in */
	void *custom;	      /* in/out */
	int ret_code;	      /* out */
};

typedef enum {
	DELTA_OP_DETECT,
	DELTA_OP_PLUS,
	DELTA_OP_MINUS,
} delta_op_t;

struct delta {
	delta_op_t op;
	struct buffer *plus;
	struct buffer *minus;
	struct buffer *final;
};

struct relation_spec {
	struct delta *delta;
	struct key_prefix_spec *cur_key_prefix_spec;
	const char *cur_key;
	struct key_prefix_spec *rel_key_prefix_spec;
	const char *rel_key;
};

#define CMD_IDENT_CAP_RDY UINT32_C(0x000000001) /* can set ready state */
#define CMD_IDENT_CAP_RES UINT32_C(0x000000002) /* can set reserved state */

static struct command_reg _cmd_ident_phase_regs[];
static sid_ubridge_kv_flags_t kv_flags_no_persist = (DEFAULT_CORE_KV_FLAGS) & ~KV_PERSISTENT;
static sid_ubridge_kv_flags_t kv_flags_persist = DEFAULT_CORE_KV_FLAGS;
static char *core_mod_name = CORE_MOD_NAME;

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

const char *sid_ubridge_cmd_dev_get_type(struct sid_ubridge_cmd_context *cmd)
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

static const char *_buffer_get_key_prefix(struct buffer *buf, struct key_prefix_spec *spec)
{
	static const char *ns_to_key_prefix_map[] = {[KV_NS_UDEV]   = KV_PREFIX_NS_UDEV,
						     [KV_NS_DEVICE] = KV_PREFIX_NS_DEVICE,
						     [KV_NS_MODULE] = KV_PREFIX_NS_MODULE,
						     [KV_NS_GLOBAL] = KV_PREFIX_NS_GLOBAL};

	return buffer_fmt_add(buf, "%s" KV_STORE_KEY_JOIN
				   "%s" KV_STORE_KEY_JOIN
				   "%s" KV_STORE_KEY_JOIN
				   "%s",
				   spec->prefix,
				   ns_to_key_prefix_map[spec->ns],
				   spec->id,
				   spec->id_sub);
}

static struct iovec *_get_value_vector(kv_store_value_flags_t flags, void *value, size_t value_size, struct iovec *iov)
{
	size_t mod_name_size;
	struct ubridge_kv_value *ubridge_kv_value;

	if (!value)
		return NULL;

	if (flags & KV_STORE_VALUE_VECTOR)
		return value;

	ubridge_kv_value = value;
	mod_name_size = strlen(ubridge_kv_value->data) + 1;

	VALUE_VECTOR_PREPARE_HEADER(iov, ubridge_kv_value->seqnum, ubridge_kv_value->flags, ubridge_kv_value->data)
	iov[VALUE_VECTOR_IDX_DATA] = (struct iovec) {ubridge_kv_value->data + mod_name_size, value_size - sizeof(*ubridge_kv_value) - mod_name_size};

	return iov;
}

static void _dump_kv_store(const char *str, sid_resource_t *kv_store_res)
{
	kv_store_iter_t *iter;
	size_t size;
	kv_store_value_flags_t flags;
	void *value;
	struct iovec tmp_iov[_VALUE_VECTOR_IDX_COUNT];
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
		log_print(ID(kv_store_res), "      seqnum: %" PRIu64 "  flags: %s%s%s%s  mod_name: %s",
			  VALUE_VECTOR_SEQNUM(iov),
			  VALUE_VECTOR_FLAGS(iov) & KV_PERSISTENT ? "KV_PERSISTENT " : "",
			  VALUE_VECTOR_FLAGS(iov) & KV_MOD_PROTECTED ? "KV_MOD_PROTECTED " : "",
			  VALUE_VECTOR_FLAGS(iov) & KV_MOD_PRIVATE ? "KV_MOD_PRIVATE " : "",
			  VALUE_VECTOR_FLAGS(iov) & KV_MOD_RESERVED ? "KV_MOD_RESERVED ": "",
			  VALUE_VECTOR_MOD_NAME(iov));
		log_print(ID(kv_store_res), "      value: %s", flags & KV_STORE_VALUE_VECTOR ? "vector" : (const char *) VALUE_VECTOR_DATA(iov));
		if (flags & KV_STORE_VALUE_VECTOR) {
			for (j = VALUE_VECTOR_IDX_DATA; j < size; j++)
				log_print(ID(kv_store_res), "        [%u] = %s", j - VALUE_VECTOR_IDX_DATA, (const char *) iov[j].iov_base);
		}
		log_print(ID(kv_store_res), " ");
		i++;
	}
	log_print(ID(kv_store_res), "======= KV STORE DUMP END %s =========\n", str);

	kv_store_iter_destroy(iter);
}

static int _kv_overwrite(const char *key_prefix, const char *key, struct kv_store_update_spec *spec, void *garg)
{
	struct kv_update_arg *arg = garg;
	struct iovec tmp_iov_old[_VALUE_VECTOR_IDX_COUNT];
	struct iovec tmp_iov_new[_VALUE_VECTOR_IDX_COUNT];
	struct iovec *iov_old, *iov_new;
	const char *reason;

	if (!spec->old_data)
		return 1;

	iov_old = _get_value_vector(spec->old_flags, spec->old_data, spec->old_data_size, tmp_iov_old);
	iov_new = _get_value_vector(spec->new_flags, spec->new_data, spec->new_data_size, tmp_iov_new);

	if (VALUE_VECTOR_FLAGS(iov_old) & KV_MOD_PRIVATE) {
		if (strcmp(VALUE_VECTOR_MOD_NAME(iov_old), VALUE_VECTOR_MOD_NAME(iov_new))) {
			reason = "private";
			arg->ret_code = EACCES;
			goto keep_old;
		}
	}
	else if (VALUE_VECTOR_FLAGS(iov_old) & KV_MOD_PROTECTED) {
		if (strcmp(VALUE_VECTOR_MOD_NAME(iov_old), VALUE_VECTOR_MOD_NAME(iov_new))) {
			reason = "protected";
			arg->ret_code = EPERM;
			goto keep_old;
		}
	}
	else if (VALUE_VECTOR_FLAGS(iov_old) & KV_MOD_RESERVED) {
		if (strcmp(VALUE_VECTOR_MOD_NAME(iov_old), VALUE_VECTOR_MOD_NAME(iov_new))) {
			reason = "reserved";
			arg->ret_code = EBUSY;
			goto keep_old;
		}
	}

	arg->ret_code = 0;
	return 1;
keep_old:
	log_debug(ID(arg->res), "Module %s can't overwrite value with key %s%s%s which is %s and attached to %s module.",
		  VALUE_VECTOR_MOD_NAME(iov_new), key_prefix ? key_prefix : "", key_prefix ? KV_STORE_KEY_JOIN : "",
		  key, reason, VALUE_VECTOR_MOD_NAME(iov_old));
	return 0;
}

static int _flags_indicate_mod_owned(sid_ubridge_kv_flags_t flags)
{
	return flags & (KV_MOD_PROTECTED | KV_MOD_PRIVATE | KV_MOD_RESERVED);
}

static const char *_get_mod_name(struct sid_module *mod)
{
	return mod ? sid_module_get_name(mod) : CORE_MOD_NAME;
}

static const char *_res_get_mod_name(sid_resource_t *mod_res)
{
	return _get_mod_name(mod_res ? sid_resource_get_data(mod_res) : NULL);
}


static size_t _get_ubridge_kv_value_data_offset(struct ubridge_kv_value *ubridge_kv_value)
{
	return strlen(ubridge_kv_value->data) + 1;
}

static int _passes_global_reservation_check(struct sid_ubridge_cmd_context *cmd, const char *mod_name,
					    sid_ubridge_cmd_kv_namespace_t ns, const char *key)
{
	struct iovec tmp_iov[_VALUE_VECTOR_IDX_COUNT];
	struct iovec *iov;
	const char *key_prefix = NULL;
	void *found;
	size_t value_size;
	kv_store_value_flags_t value_flags;
	struct key_prefix_spec key_prefix_spec = {.prefix = KV_PREFIX_NULL,
						  .ns = ns,
						  .id = KV_PREFIX_NULL,
						  .id_sub = KV_PREFIX_NULL};
	int r = 1;

	if ((ns != KV_NS_UDEV) && (ns != KV_NS_DEVICE))
		goto out;

	if (!(key_prefix = _buffer_get_key_prefix(cmd->gen_buf, &key_prefix_spec))) {
		errno = ENOKEY;
		r = 0;
		goto out;
	}

	if (!(found = kv_store_get_value(cmd->kv_store_res, key_prefix, key, &value_size, &value_flags)))
		goto out;

	iov = _get_value_vector(value_flags, found, value_size, tmp_iov);

	if ((VALUE_VECTOR_FLAGS(iov) & KV_MOD_RESERVED) && (!strcmp(VALUE_VECTOR_MOD_NAME(iov), mod_name)))
		goto out;

	log_debug(ID(cmd->kv_store_res), "Module %s can't overwrite value with key %s%s%s which is reserved and attached to %s module.",
		  mod_name, key_prefix, KV_STORE_KEY_JOIN, key, VALUE_VECTOR_MOD_NAME(iov));

	r = 0;
out:
	if (key_prefix)
		buffer_rewind_mem(cmd->gen_buf, key_prefix);
	return r;
}

static const char *_get_ns_based_id(struct sid_ubridge_cmd_context *cmd, sid_ubridge_cmd_kv_namespace_t ns)
{
	switch (ns) {
		case KV_NS_UDEV:
		case KV_NS_DEVICE:
			return cmd->dev_id;
		case KV_NS_MODULE:
			return _res_get_mod_name(cmd->mod_res);
		case KV_NS_GLOBAL:
			break;
	}

	return ID_NULL;
}

static void *_do_sid_ubridge_cmd_set_kv(struct sid_ubridge_cmd_context *cmd, sid_ubridge_cmd_kv_namespace_t ns,
					const char *key, sid_ubridge_kv_flags_t flags, const void *value, size_t value_size)
{
	const char *mod_name = _res_get_mod_name(cmd->mod_res);
	const char *key_prefix = NULL;
	struct iovec iov[4];
	struct ubridge_kv_value *ubridge_kv_value;
	struct kv_update_arg update_arg;
	struct key_prefix_spec key_prefix_spec = {.prefix = KV_PREFIX_NULL,
						  .ns = ns,
						  .id = _get_ns_based_id(cmd, ns),
						  .id_sub = KV_PREFIX_NULL};
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
	if (!((ns == KV_NS_UDEV) && !*mod_name) &&
	    !_passes_global_reservation_check(cmd, mod_name, ns, key))
		goto out;

	if (!(key_prefix = _buffer_get_key_prefix(cmd->gen_buf, &key_prefix_spec))) {
		errno = ENOKEY;
		goto out;
	}

	VALUE_VECTOR_PREPARE_HEADER(iov, cmd->udev_dev.seqnum, flags, (char *) mod_name);
	iov[VALUE_VECTOR_IDX_DATA] = (struct iovec) {(void *) value, value ? value_size : 0};

	update_arg.res = cmd->kv_store_res;
	update_arg.mod_name = mod_name;
	update_arg.gen_buf = cmd->gen_buf;
	update_arg.custom = NULL;
	update_arg.ret_code = 0;

	ubridge_kv_value = kv_store_set_value(cmd->kv_store_res, key_prefix, key, iov, 4,
					      KV_STORE_VALUE_VECTOR, KV_STORE_VALUE_OP_MERGE,
					      _kv_overwrite, &update_arg);

	if (!ubridge_kv_value) {
		if (errno == EADV)
			errno = update_arg.ret_code;
		goto out;
	}

	if (!value_size)
		goto out;

	ret = ubridge_kv_value->data + _get_ubridge_kv_value_data_offset(ubridge_kv_value);
out:
	if (key_prefix)
		buffer_rewind_mem(cmd->gen_buf, key_prefix);
	return ret;
}

void *sid_ubridge_cmd_set_kv(struct sid_ubridge_cmd_context *cmd, sid_ubridge_cmd_kv_namespace_t ns,
			     const char *key, const void *value, size_t value_size, sid_ubridge_kv_flags_t flags)
{
	if (!cmd || !key || !*key) {
		errno = EINVAL;
		return NULL;
	}

	if (ns == KV_NS_UDEV)
		flags |= KV_PERSISTENT;

	return _do_sid_ubridge_cmd_set_kv(cmd, ns, key, flags, value, value_size);
}

const void *sid_ubridge_cmd_get_kv(struct sid_ubridge_cmd_context *cmd, sid_ubridge_cmd_kv_namespace_t ns,
				   const char *key, size_t *value_size, sid_ubridge_kv_flags_t *flags)
{
	const char *mod_name = _res_get_mod_name(cmd->mod_res);
	const char *key_prefix = NULL;
	struct ubridge_kv_value *ubridge_kv_value;
	size_t size, data_offset;
	struct key_prefix_spec key_prefix_spec = {.prefix = KV_PREFIX_NULL,
						  .ns = ns,
						  .id = _get_ns_based_id(cmd, ns),
						  .id_sub = KV_PREFIX_NULL};
	void *ret = NULL;

	if (!cmd || !key || !*key) {
		errno = EINVAL;
		goto out;
	}

	if (!(key_prefix = _buffer_get_key_prefix(cmd->gen_buf, &key_prefix_spec))) {
		errno = ENOKEY;
		goto out;
	}

	if (!(ubridge_kv_value = kv_store_get_value(cmd->kv_store_res, key_prefix, key, &size, NULL)))
		goto out;

	if (ubridge_kv_value->flags & KV_MOD_PRIVATE) {
		if (strcmp(ubridge_kv_value->data, mod_name)) {
			errno = EACCES;
			goto out;
		}
	}

	if (flags)
		*flags = ubridge_kv_value->flags;

	data_offset = _get_ubridge_kv_value_data_offset(ubridge_kv_value);
	size -= (sizeof(*ubridge_kv_value) + data_offset);

	if (value_size)
		*value_size = size;

	if (size)
		ret = ubridge_kv_value->data + data_offset;
out:
	if (key_prefix)
		buffer_rewind_mem(cmd->gen_buf, key_prefix);
	return ret;
}

static int _kv_reserve(const char *key_prefix, const char *key, struct kv_store_update_spec *spec, void *garg)
{
	struct kv_update_arg *arg = garg;
	struct iovec tmp_iov_old[_VALUE_VECTOR_IDX_COUNT];
	struct iovec tmp_iov_new[_VALUE_VECTOR_IDX_COUNT];
	struct iovec *iov_old, *iov_new;

	if (!spec->old_data)
		return 1;

	iov_old = _get_value_vector(spec->old_flags, spec->old_data, spec->old_data_size, tmp_iov_old);
	iov_new = _get_value_vector(spec->new_flags, spec->new_data, spec->new_data_size, tmp_iov_new);

	if (strcmp(VALUE_VECTOR_MOD_NAME(iov_old), VALUE_VECTOR_MOD_NAME(iov_new))) {
		log_debug(ID(arg->res), "Module %s can't reserve key %s%s%s which is already reserved by %s module.",
			  VALUE_VECTOR_MOD_NAME(iov_new), key_prefix ? key_prefix : "",
			  key_prefix ? KV_STORE_KEY_JOIN : "", key, VALUE_VECTOR_MOD_NAME(iov_old));
		arg->ret_code = EBUSY;
		return 0;
	}

	return 1;
}

static int _kv_unreserve(const char *key_prefix, const char *key, struct kv_store_update_spec *spec, void *garg)
{
	struct kv_update_arg *arg = garg;
	struct iovec tmp_iov_old[_VALUE_VECTOR_IDX_COUNT];
	struct iovec *iov_old;

	if (!spec->old_data)
		return 1;

	iov_old = _get_value_vector(spec->old_flags, spec->old_data, spec->old_data_size, tmp_iov_old);

	if (strcmp(VALUE_VECTOR_MOD_NAME(iov_old), arg->mod_name)) {
		log_debug(ID(arg->res), "Module %s can't unreserve key %s%s%s which is reserved by %s module.",
			  arg->mod_name, key_prefix ? key_prefix : "", key_prefix ? KV_STORE_KEY_JOIN : "",
			  key, VALUE_VECTOR_MOD_NAME(iov_old));
		arg->ret_code = EBUSY;
		return 0;
	}

	return 1;
}

int _do_sid_ubridge_cmd_mod_reserve_kv(struct sid_module *mod, struct sid_ubridge_cmd_mod_context *cmd_mod,
				       sid_ubridge_cmd_kv_namespace_t ns, const char *key, int unset)
{
	const char *mod_name = _get_mod_name(mod);
	const char *key_prefix = NULL;
	struct iovec iov[_VALUE_VECTOR_IDX_COUNT - 1]; /* without VALUE_VECTOR_IDX_DATA */
	struct ubridge_kv_value *ubridge_kv_value;
	static uint64_t null_int = 0;
	sid_ubridge_kv_flags_t flags = unset ? KV_FLAGS_UNSET : KV_MOD_RESERVED;
	struct kv_update_arg update_arg;
	int is_worker;
	struct key_prefix_spec key_prefix_spec = {.prefix = KV_PREFIX_NULL,
						  .ns = ns,
						  .id = KV_PREFIX_NULL,
						  .id_sub = KV_PREFIX_NULL};
	int r = -1;

	if (!(key_prefix = _buffer_get_key_prefix(cmd_mod->gen_buf, &key_prefix_spec))) {
		errno = ENOKEY;
		goto out;
	}

	if (!(cmd_mod->kv_store_res)) {
		errno = ENOMEDIUM;
		goto out;
	}

	update_arg.res = cmd_mod->kv_store_res;
	update_arg.mod_name = mod_name;
	update_arg.custom = NULL;
	update_arg.ret_code = 0;

	is_worker = worker_control_is_worker(cmd_mod->kv_store_res);

	if (is_worker)
		flags |= KV_PERSISTENT;

	if (unset && !is_worker) {
		kv_store_unset_value(cmd_mod->kv_store_res, key_prefix, key, _kv_unreserve, &update_arg);

		if (errno == EADV)
			errno = update_arg.ret_code;
		goto out;
	} else {
		VALUE_VECTOR_PREPARE_HEADER(iov, null_int, flags, (char *) mod_name);
		log_debug(">>>", "RESERVING %s" KV_STORE_KEY_JOIN "%s", key_prefix, key);
		ubridge_kv_value = kv_store_set_value(cmd_mod->kv_store_res, key_prefix, key, iov, _VALUE_VECTOR_IDX_COUNT - 1,
						    KV_STORE_VALUE_VECTOR, KV_STORE_VALUE_OP_MERGE,
						    _kv_reserve, &update_arg);

		if (!ubridge_kv_value) {
			if (errno == EADV)
				errno = update_arg.ret_code;
			goto out;
		}
	}

	r = 0;
out:
	if (key_prefix)
		buffer_rewind_mem(cmd_mod->gen_buf, key_prefix);
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

	if (!_cmd_ident_phase_regs[cmd->ident_phase].flags & CMD_IDENT_CAP_RDY) {
		errno = EPERM;
		return -1;
	}

	if (ready == DEV_NOT_RDY_UNPROCESSED) {
		errno = EINVAL;
		return -1;
	}

	orig_mod_res = cmd->mod_res;
	cmd->mod_res = NULL;

	_do_sid_ubridge_cmd_set_kv(cmd, KV_NS_DEVICE, KV_KEY_DEV_READY, DEFAULT_CORE_KV_FLAGS, &ready, sizeof(ready));

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

	if (!(_cmd_ident_phase_regs[cmd->ident_phase].flags & CMD_IDENT_CAP_RES)) {
		errno = EPERM;
		return -1;
	}

	orig_mod_res = cmd->mod_res;
	cmd->mod_res = NULL;

	_do_sid_ubridge_cmd_set_kv(cmd, KV_NS_DEVICE, KV_KEY_DEV_RESERVED, DEFAULT_CORE_KV_FLAGS, &reserved, sizeof(reserved));

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

static int _device_add_field(struct sid_ubridge_cmd_context *cmd, char *key)
{
	char *value;
	size_t key_len;

	if (!(value = strchr(key, KV_PAIR[0])) || !*(value++))
		return -1;

	key_len = value - key - 1;
	key[key_len] = '\0';

	if (!(value = _do_sid_ubridge_cmd_set_kv(cmd, KV_NS_UDEV, key, 0, value, strlen(value) + 1)))
		goto bad;

	/* Common key=value pairs are also directly in the cmd->udev_dev structure. */
	if (!strncmp(key, UDEV_KEY_ACTION, key_len))
		cmd->udev_dev.action = util_get_udev_action_from_string(value);
	else if (!strncmp(key, UDEV_KEY_DEVNAME, key_len))
		cmd->udev_dev.name = value;
	else if (!strncmp(key, UDEV_KEY_DEVTYPE, key_len))
		cmd->udev_dev.type = value;
	else if (!strncmp(key, UDEV_KEY_MAJOR, key_len))
		cmd->udev_dev.major = atoi(value);
	else if (!strncmp(key, UDEV_KEY_MINOR, key_len))
		cmd->udev_dev.minor = atoi(value);
	else if (!strncmp(key, UDEV_KEY_SEQNUM, key_len))
		cmd->udev_dev.seqnum = strtoull(value, NULL, 10);
	else if (!strncmp(key, UDEV_KEY_SYNTH_UUID, key_len))
		cmd->udev_dev.synth_uuid = value;

	key[key_len] = KV_PAIR[0];

	return 0;
bad:
	key[key_len] = KV_PAIR[0];

	return -1;
};

static int _parse_cmd_nullstr_udev_env(const struct raw_command *raw_cmd, struct sid_ubridge_cmd_context *cmd)
{
	char buf[32];
	dev_t devno;
	size_t i = 0;
	const char *delim;
	char *str;
	size_t raw_udev_env_len = raw_cmd->len - sizeof(struct raw_command_header);

	if (raw_cmd->header->cmd_number != CMD_IDENTIFY)
		return 0;

	if (raw_udev_env_len < sizeof(devno))
		goto fail;

	memcpy(&devno, raw_cmd->header->data, sizeof(devno));
	raw_udev_env_len -= sizeof(devno);

	cmd->udev_dev.major = major(devno);
	cmd->udev_dev.minor = minor(devno);

	snprintf(buf, sizeof(buf), "%d_%d", cmd->udev_dev.major, cmd->udev_dev.minor);
	cmd->dev_id = strdup(buf);

	/*
	 * We have this on input:
	 *
	 *   key1=value1\0key2=value2\0...
	 */
	while (i < raw_udev_env_len) {
		str = raw_cmd->header->data + sizeof(devno) + i;

		if (!(delim = memchr(str, KV_END[0], raw_udev_env_len - i)))
			goto fail;

		if (_device_add_field(cmd, str) < 0)
			goto fail;

		i += delim - str + 1;
	}

	return 0;
fail:
	return -EINVAL;
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
 *  Module name is equal to the name as exposed in PROC_DEVICES_PATH + MODULE_NAME_SUFFIX.
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

	if (!(f = fopen(PROC_DEVICES_PATH, "r"))) {
		log_sys_error(ID(cmd_res), "fopen", PROC_DEVICES_PATH);
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
			  cmd->udev_dev.major, cmd->udev_dev.name, PROC_DEVICES_PATH);
		goto out;
	}

	p = found;
	while (isprint(*p))
		p++;
	p[0] = '\0';

	len = p - found;

	if (len >= (sizeof(buf) - strlen(SID_MODULE_NAME_SUFFIX))) {
		log_error(ID(cmd_res), "Insufficient result buffer for device lookup in %s, "
			  "found string \"%s\", buffer size is only %zu.", PROC_DEVICES_PATH,
			  found, sizeof(buf));
		goto out;
	}

	memcpy(buf, found, len);
	memcpy(buf + len, SID_MODULE_NAME_SUFFIX, SID_MODULE_NAME_SUFFIX_LEN);
	buf[len + SID_MODULE_NAME_SUFFIX_LEN] = '\0';
	_canonicalize_module_name(buf);

	if (!(mod_name = _do_sid_ubridge_cmd_set_kv(cmd, KV_NS_DEVICE, KV_KEY_DEV_MOD, DEFAULT_CORE_KV_FLAGS, buf, strlen(buf) + 1)))
		log_error_errno(ID(cmd_res), errno, "Failed to store device " CMD_DEV_ID_FMT " module name.", CMD_DEV_ID(cmd));
out:
	if (f)
		fclose(f);
	return mod_name;
}

static int _cmd_execute_unknown(struct command_exec_args *exec_args)
{
	return 0;
}

static int _cmd_execute_reply(struct command_exec_args *exec_args)
{
	return 0;
}

static int _cmd_execute_version(struct command_exec_args *exec_args)
{
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(exec_args->cmd_res);
	static struct version this_version = {.major = SID_VERSION_MAJOR,
					      .minor = SID_VERSION_MINOR,
					      .release = SID_VERSION_RELEASE};

	buffer_add(cmd->result_buf, &this_version, sizeof(this_version));
	return 0;
}

static int _execute_block_modules(struct command_exec_args *exec_args, cmd_ident_phase_t phase)
{
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(exec_args->cmd_res);
	sid_resource_t *orig_mod_res = cmd->mod_res;
	sid_resource_t *block_mod_res;
	struct sid_module *block_mod;
	const struct command_module_fns *block_mod_fns;
	int r = -1;

	sid_resource_iter_reset(exec_args->block_mod_iter);

	while ((block_mod_res = sid_resource_iter_next(exec_args->block_mod_iter))) {
		if (sid_module_registry_get_module_symbols(block_mod_res, (const void ***) &block_mod_fns) < 0) {
			log_error(ID(exec_args->cmd_res), "Failed to retrieve module symbols from module %s.", ID(block_mod_res));
			goto out;
		}

		cmd->mod_res = block_mod_res;
		block_mod = sid_resource_get_data(block_mod_res);

		switch (phase) {
			case CMD_IDENT_PHASE_A_IDENT:
				if (block_mod_fns->ident && block_mod_fns->ident(block_mod, cmd) < 0)
					goto out;
				break;
			case CMD_IDENT_PHASE_A_SCAN_PRE:
				if (block_mod_fns->scan_pre && block_mod_fns->scan_pre(block_mod, cmd) < 0)
					goto out;
				break;
			case CMD_IDENT_PHASE_A_SCAN_CURRENT:
				if (block_mod_fns->scan_current && block_mod_fns->scan_current(block_mod, cmd) < 0)
					goto out;
				break;
			case CMD_IDENT_PHASE_A_SCAN_NEXT:
				if (block_mod_fns->scan_next && block_mod_fns->scan_next(block_mod, cmd) < 0)
					goto out;
				break;
			case CMD_IDENT_PHASE_A_SCAN_POST_CURRENT:
				if (block_mod_fns->scan_post_current && block_mod_fns->scan_post_current(block_mod, cmd) < 0)
					goto out;
				break;
			case CMD_IDENT_PHASE_A_SCAN_POST_NEXT:
				if (block_mod_fns->scan_post_next && block_mod_fns->scan_post_next(block_mod, cmd) < 0)
					goto out;
				break;
			case CMD_IDENT_PHASE_B_TRIGGER_ACTION_CURRENT:
				if (block_mod_fns->trigger_action_current && block_mod_fns->trigger_action_current(block_mod, cmd) < 0)
					goto out;
				break;
			case CMD_IDENT_PHASE_B_TRIGGER_ACTION_NEXT:
				if (block_mod_fns->trigger_action_next && block_mod_fns->trigger_action_next(block_mod, cmd) < 0)
					goto out;
				break;
			case CMD_IDENT_PHASE_ERROR:
				if (block_mod_fns->error && block_mod_fns->error(block_mod, cmd) < 0)
					goto out;
				break;
			default:
				log_error(ID(exec_args->cmd_res), INTERNAL_ERROR "%s: Trying illegal execution of block modules in %s state.",
					  __func__, _cmd_ident_phase_regs[phase].name);
				break;
		}
	}

	r = 0;
out:
	cmd->mod_res = orig_mod_res;
	return r;
}

static int _cmd_execute_identify_ident(struct command_exec_args *exec_args)
{
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(exec_args->cmd_res);
	const struct command_module_fns *mod_fns;

	_execute_block_modules(exec_args, CMD_IDENT_PHASE_A_IDENT);

	//sid_resource_dump_all_in_dot(sid_resource_get_top_level(exec_args->cmd_res));

	sid_module_registry_get_module_symbols(cmd->mod_res, (const void ***) &mod_fns);
	if (mod_fns && mod_fns->ident)
		return mod_fns->ident(sid_resource_get_data(cmd->mod_res), cmd);

	return 0;
}

static int _cmd_execute_identify_scan_pre(struct command_exec_args *exec_args)
{
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(exec_args->cmd_res);
	const struct command_module_fns *mod_fns;

	_execute_block_modules(exec_args, CMD_IDENT_PHASE_A_SCAN_PRE);

	sid_module_registry_get_module_symbols(cmd->mod_res, (const void ***) &mod_fns);
	if (mod_fns && mod_fns->scan_pre)
		return mod_fns->scan_pre(sid_resource_get_data(cmd->mod_res), cmd);

	return 0;
}

static int _cmd_execute_identify_scan_current(struct command_exec_args *exec_args)
{
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(exec_args->cmd_res);
	const struct command_module_fns *mod_fns;

	_execute_block_modules(exec_args, CMD_IDENT_PHASE_A_SCAN_CURRENT);

	sid_module_registry_get_module_symbols(cmd->mod_res, (const void ***) &mod_fns);
	if (mod_fns && mod_fns->scan_current)
		if (mod_fns->scan_current(sid_resource_get_data(cmd->mod_res), cmd))
			return -1;

	return 0;
}

static int _cmd_execute_identify_scan_next(struct command_exec_args *exec_args)
{
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(exec_args->cmd_res);
	const struct command_module_fns *mod_fns;
	const char *next_mod_name;

	_execute_block_modules(exec_args, CMD_IDENT_PHASE_A_SCAN_NEXT);

	if ((next_mod_name = sid_ubridge_cmd_get_kv(cmd, KV_NS_DEVICE, KV_KEY_DEV_NEXT_MOD, NULL, NULL))) {
		if (!(exec_args->type_mod_res_next = sid_module_registry_get_module(exec_args->type_mod_registry_res, next_mod_name))) {
			log_debug(ID(exec_args->cmd_res), "Module %s not loaded.", next_mod_name);
			return -1;
		}
	} else
		exec_args->type_mod_res_next = NULL;

	cmd->mod_res = exec_args->type_mod_res_next;

	sid_module_registry_get_module_symbols(cmd->mod_res, (const void ***) &mod_fns);
	if (mod_fns && mod_fns->scan_next)
		return mod_fns->scan_next(sid_resource_get_data(cmd->mod_res), cmd);

	return 0;
}

static int _cmd_execute_identify_scan_post_current(struct command_exec_args *exec_args)
{
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(exec_args->cmd_res);
	const struct command_module_fns *mod_fns;

	cmd->mod_res = exec_args->type_mod_res_current;

	_execute_block_modules(exec_args, CMD_IDENT_PHASE_A_SCAN_POST_CURRENT);

	sid_module_registry_get_module_symbols(cmd->mod_res, (const void ***) &mod_fns);
	if (mod_fns && mod_fns->scan_post_current)
		return mod_fns->scan_post_current(sid_resource_get_data(cmd->mod_res), cmd);

	return 0;
}

static int _cmd_execute_identify_scan_post_next(struct command_exec_args *exec_args)
{
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(exec_args->cmd_res);
	const struct command_module_fns *mod_fns;

	cmd->mod_res = exec_args->type_mod_res_next;

	_execute_block_modules(exec_args, CMD_IDENT_PHASE_A_SCAN_POST_NEXT);

	sid_module_registry_get_module_symbols(cmd->mod_res, (const void ***) &mod_fns);
	if (mod_fns && mod_fns->scan_post_next)
		return mod_fns->scan_post_next(sid_resource_get_data(cmd->mod_res), cmd);

	return 0;
}

static int _cmd_execute_identify_trigger_action_current(struct command_exec_args *exec_args)
{
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(exec_args->cmd_res);

	cmd->mod_res = exec_args->type_mod_res_current;
	return 0;
}

static int _cmd_execute_identify_trigger_action_next(struct command_exec_args *exec_args)
{
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(exec_args->cmd_res);

	cmd->mod_res = exec_args->type_mod_res_next;
	return 0;
}

static int _cmd_execute_identify_error(struct command_exec_args *exec_args)
{
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(exec_args->cmd_res);
	const struct command_module_fns *mod_fns;
	int r = 0;

	_execute_block_modules(exec_args, CMD_IDENT_PHASE_ERROR);

	cmd->mod_res = exec_args->type_mod_res_current;
	sid_module_registry_get_module_symbols(cmd->mod_res, (const void ***) &mod_fns);
	if (mod_fns && mod_fns->error)
		r |= mod_fns->error(sid_resource_get_data(cmd->mod_res), cmd);

	cmd->mod_res = exec_args->type_mod_res_next;
	sid_module_registry_get_module_symbols(cmd->mod_res, (const void ***) &mod_fns);
	if (mod_fns && mod_fns->error)
		r |= mod_fns->error(sid_resource_get_data(cmd->mod_res), cmd);

	return r;
}

static int _on_cmd_udev_monitor(sid_event_source *es, int fd, uint32_t revents, void *data)
{
	return _cmd_ident_phase_regs[CMD_IDENT_PHASE_B_TRIGGER_ACTION_CURRENT].execute(data) &&
	       _cmd_ident_phase_regs[CMD_IDENT_PHASE_B_TRIGGER_ACTION_NEXT].execute(data);
}

static int _set_up_udev_monitor(struct command_exec_args *exec_args)
{
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(exec_args->cmd_res);
	struct udev_monitor_setup *umonitor = &exec_args->umonitor;
	int umonitor_fd = -1;

	if (!(umonitor->udev = udev_new())) {
		log_error(ID(exec_args->cmd_res), "Failed to create udev handle.");
		goto fail;
	}

	if (!(umonitor->monitor = udev_monitor_new_from_netlink(umonitor->udev, "udev"))) {
		log_error(ID(exec_args->cmd_res), "Failed to create udev monitor.");
		goto fail;
	}

	snprintf(umonitor->tag, sizeof(umonitor->tag), "sid_%" PRIu64, cmd->udev_dev.seqnum);

	if (udev_monitor_filter_add_match_tag(umonitor->monitor, umonitor->tag) < 0) {
		log_error(ID(exec_args->cmd_res), "Failed to create tag filter.");
		goto fail;
	}

	umonitor_fd = udev_monitor_get_fd(umonitor->monitor);

	if (sid_resource_create_io_event_source(exec_args->cmd_res, &umonitor->es, umonitor_fd,
						_on_cmd_udev_monitor, NULL, exec_args) < 0) {
		log_error(ID(exec_args->cmd_res), "Failed to register udev monitoring.");
		goto fail;
	}

	if (udev_monitor_enable_receiving(umonitor->monitor) < 0) {
		log_error(ID(exec_args->cmd_res), "Failed to enable udev monitoring.");
		goto fail;
	}

	return 0;
fail:
	if (umonitor->udev) {
		if (umonitor->monitor)
			udev_monitor_unref(umonitor->monitor);
		udev_unref(umonitor->udev);
		if (umonitor->es)
			(void) sid_resource_destroy_event_source(exec_args->cmd_res, &umonitor->es);
	}
	return -1;
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

static void _destroy_delta(struct delta *delta)
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

static int _sorted_set_delta_calculate(struct kv_store_update_spec *spec, struct delta *delta)
{
	struct iovec *old_value = spec->old_data;
	size_t old_size = spec->old_data_size;
	struct iovec *new_value = spec->new_data;
	size_t new_size = spec->new_data_size;
	unsigned i_old, i_new;
	int cmp_result;
	int r = -1;

	/*
	 * Result vector is "delta->final".
	 * Delta plus vector is "delta->plus" (items which are detected as added).
	 * Delta minus vector is "delta->minus" (items which are detected as removed).
	 */

	if (!old_size)
		old_size = VALUE_VECTOR_IDX_DATA;

	if (!new_size)
		new_size = VALUE_VECTOR_IDX_DATA;

	if (!(delta->final = buffer_create(BUFFER_TYPE_VECTOR, BUFFER_MODE_PLAIN, old_size + new_size, 0))) {
		errno = ENOMEM;
		goto out;
	}
	/* copy the record header completely from new_value vector */
	buffer_add(delta->final, new_value[VALUE_VECTOR_IDX_SEQNUM].iov_base, new_value[VALUE_VECTOR_IDX_SEQNUM].iov_len);
	buffer_add(delta->final, new_value[VALUE_VECTOR_IDX_FLAGS].iov_base, new_value[VALUE_VECTOR_IDX_FLAGS].iov_len);
	buffer_add(delta->final, new_value[VALUE_VECTOR_IDX_MOD_NAME].iov_base, new_value[VALUE_VECTOR_IDX_MOD_NAME].iov_len);

	if (delta->op == DELTA_OP_DETECT) {
		if (!(delta->plus = buffer_create(BUFFER_TYPE_VECTOR, BUFFER_MODE_PLAIN, new_size, 0)) ||
		    !(delta->minus = buffer_create(BUFFER_TYPE_VECTOR, BUFFER_MODE_PLAIN, old_size, 0))) {
			errno = ENOMEM;
			goto out;
		}

		buffer_add(delta->plus, new_value[VALUE_VECTOR_IDX_SEQNUM].iov_base, new_value[VALUE_VECTOR_IDX_SEQNUM].iov_len);
		buffer_add(delta->plus, new_value[VALUE_VECTOR_IDX_FLAGS].iov_base, new_value[VALUE_VECTOR_IDX_FLAGS].iov_len);
		buffer_add(delta->plus, new_value[VALUE_VECTOR_IDX_MOD_NAME].iov_base, new_value[VALUE_VECTOR_IDX_MOD_NAME].iov_len);

		buffer_add(delta->minus, new_value[VALUE_VECTOR_IDX_SEQNUM].iov_base, new_value[VALUE_VECTOR_IDX_SEQNUM].iov_len);
		buffer_add(delta->minus, new_value[VALUE_VECTOR_IDX_FLAGS].iov_base, new_value[VALUE_VECTOR_IDX_FLAGS].iov_len);
		buffer_add(delta->minus, new_value[VALUE_VECTOR_IDX_MOD_NAME].iov_base, new_value[VALUE_VECTOR_IDX_MOD_NAME].iov_len);
	} else
		delta->plus = delta->minus = NULL;

	/* start right beyond the header */
	i_old = i_new = VALUE_VECTOR_IDX_DATA;

	/* look for differences between old_value and new_value vector */
	while (1) {
		if ((i_old < old_size) && (i_new < new_size)) {
			/* both vectors still still have items to handle */
			cmp_result = strcmp(old_value[i_old].iov_base, new_value[i_new].iov_base);
			if (cmp_result < 0) {
				/* the old vector has item the new one doesn't have */
				switch (delta->op) {
					case DELTA_OP_DETECT:
						/* we have detected removed item: add it to delta->minus */
						buffer_add(delta->minus, old_value[i_old].iov_base, old_value[i_old].iov_len);
						break;
					case DELTA_OP_PLUS:
						/* we're not changing the old item: add it to delta->final */
						/* no break here intentionally! */
					case DELTA_OP_MINUS:
						/* we're not changing the old item: add it to delta->final */
						buffer_add(delta->final, old_value[i_old].iov_base, old_value[i_old].iov_len);
						break;
				}
				i_old++;
			} else if (cmp_result > 0) {
				/* the new vector has item the old one doesn't have */
				switch (delta->op) {
					case DELTA_OP_DETECT:
						/* we have detected new item: add it to delta->plus and add it to delta->final */
						buffer_add(delta->plus, new_value[i_new].iov_base, new_value[i_new].iov_len);
						/* no break here intentionally! */
					case DELTA_OP_PLUS:
						/* we're adding new item: add it to delta->final */
						buffer_add(delta->final, new_value[i_new].iov_base, new_value[i_new].iov_len);
						break;
					case DELTA_OP_MINUS:
						/* we're removing item: don't add it to delta->final */
						break;
				}
				i_new++;
			} else {
				/* both old and new has the item */
				switch (delta->op) {
					case DELTA_OP_DETECT:
						/* we have detected no change for this item: add it to delta->final */
						/* no break here intentionally! */
					case DELTA_OP_PLUS:
						/* we're adding new item: add it to delta->final */
						buffer_add(delta->final, new_value[i_new].iov_base, new_value[i_new].iov_len);
						break;
					case DELTA_OP_MINUS:
						/* we're removing item: don't add it to delta->final */
						break;
				}
				i_old++;
				i_new++;
			}
			continue;
		} else if (i_old == old_size) {
			/* only new vector still has items to handle */
			while (i_new < new_size) {
				switch (delta->op) {
					case DELTA_OP_DETECT:
						/* we have detected new item: add it to delta->final */
						buffer_add(delta->plus, new_value[i_new].iov_base, new_value[i_new].iov_len);
						/* no break here intentionally! */
					case DELTA_OP_PLUS:
						/* we're adding new item: add it to delta->final */
						buffer_add(delta->final, new_value[i_new].iov_base, new_value[i_new].iov_len);
						break;
					case DELTA_OP_MINUS:
						/* we're removing item: don't add to delta->final */
						break;
				}
				i_new++;
			}
		} else if (i_new == new_size) {
			/* only old vector still has items to handle */
			while (i_old < old_size) {
				switch (delta->op) {
					case DELTA_OP_DETECT:
						/* we have detected removed item so add it to delta->minus */
						buffer_add(delta->minus, old_value[i_old].iov_base, old_value[i_old].iov_len);
						break;
					case DELTA_OP_PLUS:
						/* we're not changing the old item so add it to delta->final */
						/* no break here intentionally! */
					case DELTA_OP_MINUS:
						/* we're not changing the old item so add it to delta->final */
						buffer_add(delta->final, old_value[i_old].iov_base, old_value[i_old].iov_len);
						break;
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
	return r;
}

static void _value_vector_mark_persist(struct iovec *iov, int persist)
{
	if (persist)
		iov[VALUE_VECTOR_IDX_FLAGS] = (struct iovec) {&kv_flags_persist, sizeof(kv_flags_persist)};
	else
		iov[VALUE_VECTOR_IDX_FLAGS] = (struct iovec) {&kv_flags_no_persist, sizeof(kv_flags_no_persist)};
}

static int _kv_sorted_id_set_delta_resolve(const char *key_prefix, const char *key, struct kv_store_update_spec *spec, void *garg);

static const char _key_prefix_err_msg[] = "Failed to get key prefix to store hierarchy records for device " CMD_DEV_ID_FMT ".";

static int _refresh_relation_from_delta(delta_op_t delta_op, struct buffer *delta_buf, struct buffer *cur_buf, struct kv_update_arg *update_arg)
{
	struct relation_spec *rel_spec = update_arg->custom;
	struct delta *orig_delta = rel_spec->delta;
	const char *delta_key_prefix, *key_prefix;
	struct iovec *delta_iov, *cur_iov;
	size_t delta_iov_cnt, cur_iov_cnt, i;
	const char *tmp_mem_start = buffer_add(update_arg->gen_buf, "", 0);
	int r = -1;

	buffer_get_data(delta_buf, (const void **) (&delta_iov), &delta_iov_cnt);

	/* no relatives recorded in delta buffer so there's nothing to do */
	if (delta_iov_cnt <= VALUE_VECTOR_IDX_DATA)
		return 0;

	if (delta_op == DELTA_OP_PLUS)
		delta_key_prefix = KV_PREFIX_OP_DELTA_PLUS;
	else if (delta_op == DELTA_OP_MINUS)
		delta_key_prefix = KV_PREFIX_OP_DELTA_MINUS;
	else {
		log_error(ID(update_arg->res), INTERNAL_ERROR "%s: incorrect delta operation requested.", __func__);
		goto out;
	}

	/* store delta for current item - persistent */
	rel_spec->cur_key_prefix_spec->prefix = delta_key_prefix;
	key_prefix = _buffer_get_key_prefix(update_arg->gen_buf, rel_spec->cur_key_prefix_spec);
	_value_vector_mark_persist(delta_iov, 1);

	kv_store_set_value(update_arg->res, key_prefix, rel_spec->cur_key, delta_iov, delta_iov_cnt, KV_STORE_VALUE_VECTOR, 0, _kv_overwrite, update_arg);

	_value_vector_mark_persist(delta_iov, 0);
	buffer_rewind_mem(update_arg->gen_buf, key_prefix);
	rel_spec->cur_key_prefix_spec->prefix = KV_PREFIX_NULL;

	/* store final and delta for each relative */
	buffer_get_data(cur_buf, (const void **) (&cur_iov), &cur_iov_cnt);

	rel_spec->delta = &((struct delta) {0});
	rel_spec->delta->op = delta_op;

	for (i = VALUE_VECTOR_IDX_DATA; i < delta_iov_cnt; i++) {
		rel_spec->rel_key_prefix_spec->id = delta_iov[i].iov_base;

		/* final - nonpersistent */
		key_prefix = _buffer_get_key_prefix(update_arg->gen_buf, rel_spec->rel_key_prefix_spec);

		kv_store_set_value(update_arg->res, key_prefix, rel_spec->rel_key, cur_iov, cur_iov_cnt,
				   KV_STORE_VALUE_VECTOR | KV_STORE_VALUE_REF, 0, _kv_sorted_id_set_delta_resolve, update_arg);

		_destroy_delta(rel_spec->delta);
		buffer_rewind_mem(update_arg->gen_buf, key_prefix);

		/* delta - persistent */
		rel_spec->rel_key_prefix_spec->prefix = delta_key_prefix;
		key_prefix = _buffer_get_key_prefix(update_arg->gen_buf, rel_spec->rel_key_prefix_spec);
		_value_vector_mark_persist(cur_iov, 1);

		kv_store_set_value(update_arg->res, key_prefix, rel_spec->rel_key, cur_iov, cur_iov_cnt,
				   KV_STORE_VALUE_VECTOR, 0, _kv_overwrite, update_arg);

		_value_vector_mark_persist(cur_iov, 0);
		buffer_rewind_mem(update_arg->gen_buf, key_prefix);
		rel_spec->rel_key_prefix_spec->prefix = KV_PREFIX_NULL;
	}

	r = 0;
out:
	if (tmp_mem_start)
		buffer_rewind_mem(update_arg->gen_buf, tmp_mem_start);
	rel_spec->delta = orig_delta;
	return r;
}

static int _kv_sorted_id_set_delta_resolve(const char *key_prefix, const char *key, struct kv_store_update_spec *spec, void *garg)
{
	struct kv_update_arg *update_arg = garg;
	struct relation_spec *rel_spec = update_arg->custom;
	struct buffer *cur_buf = NULL;
	uint64_t seqnum;
	struct iovec *iov;
	size_t size;
	int r = 0; /* no change by default */

	/* FIXME: propagate error out of this function so it can be reported by caller. */

	if (_sorted_set_delta_calculate(spec, rel_spec->delta) < 0)
		goto out;

	if (rel_spec->delta->op == DELTA_OP_DETECT) {
		if (!(cur_buf = buffer_create(BUFFER_TYPE_VECTOR, BUFFER_MODE_PLAIN, _VALUE_VECTOR_IDX_COUNT + 1, 0)))
			goto out;

		seqnum = VALUE_VECTOR_SEQNUM(spec->new_data);
		buffer_add(cur_buf, &seqnum, sizeof(seqnum));
		buffer_add(cur_buf, &kv_flags_no_persist, sizeof(kv_flags_no_persist));
		buffer_add(cur_buf, (void *) update_arg->mod_name, strlen(update_arg->mod_name) + 1);
		buffer_add(cur_buf, (void *) rel_spec->cur_key_prefix_spec->id, strlen(rel_spec->cur_key_prefix_spec->id) + 1);

		/*
		 * Handle delta.{plus,minus} vector for this item and relatives.
		 *
		 * Here, we set:
		 * 	{+,-}SID_{LUP,LDW} here for current item (the "ref") to add/remove relatives
		 * 	{+,-}SID_{LWD,LUP} here reciprocally for relatives to add/remove current item (the "ref")
		 */
		if ((_refresh_relation_from_delta(DELTA_OP_PLUS, rel_spec->delta->plus, cur_buf, update_arg) < 0) ||
		    (_refresh_relation_from_delta(DELTA_OP_MINUS, rel_spec->delta->minus, cur_buf, update_arg) < 0))
			goto out;
	}

	/*
	 * Get the actual vector out of delta.final and rewrite spec->new_data with this one.
	 * Also, make the vector to be copied instead of referenced only because we will destroy the delta buffer completely.
	 */
	buffer_get_data(rel_spec->delta->final, (const void **) &iov, &size);
	spec->new_data_size = size;
	spec->new_data = iov;
	spec->new_flags &= ~KV_STORE_VALUE_REF;

	r = 1;
out:
	if (cur_buf)
		buffer_destroy(cur_buf);
	return r;
}

static int _iov_str_item_cmp(const void *a, const void *b)
{
	const struct iovec *iovec_item_a = (struct iovec *) a;
	const struct iovec *iovec_item_b = (struct iovec *) b;

	return strcmp((const char *) iovec_item_a->iov_base, (const char *) iovec_item_b->iov_base);
}

static int _do_refresh_device_hierarchy_from_sysfs(sid_resource_t *cmd_res, const char *sysfs_item, const char *key, const char *rel_key)
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

	struct relation_spec rel_spec = {.delta = &((struct delta) {0}),
					 .cur_key_prefix_spec = &((struct key_prefix_spec) {
									.prefix= KV_PREFIX_NULL,
									.ns = KV_NS_DEVICE,
									.id = _get_ns_based_id(cmd, KV_NS_DEVICE),
									.id_sub = KV_PREFIX_NULL}),
					 .cur_key = key,
					 .rel_key_prefix_spec = &((struct key_prefix_spec) {
									.prefix = KV_PREFIX_NULL,
									.ns = KV_NS_DEVICE,
									.id = KV_PREFIX_NULL, /* will be calculated later */
									.id_sub = KV_PREFIX_NULL}),
					 .rel_key = rel_key};

	struct kv_update_arg update_arg = {.res = cmd->kv_store_res,
					   .mod_name = CORE_MOD_NAME,
					   .gen_buf = cmd->gen_buf,
					   .custom = &rel_spec};

	if (cmd->udev_dev.action != UDEV_ACTION_REMOVE) {
		if (!(s = buffer_fmt_add(cmd->gen_buf, "/sys/dev/block/%d:%d/%s", cmd->udev_dev.major, cmd->udev_dev.minor, sysfs_item))) {
			log_error(ID(cmd_res), "Failed to compose sysfs %s path for device " CMD_DEV_ID_FMT ".", sysfs_item, CMD_DEV_ID(cmd));
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
	 * +3 for "seqnum|flags|mod_name" header
	 */
	if (!(vec_buf = buffer_create(BUFFER_TYPE_VECTOR, BUFFER_MODE_PLAIN, count + 1, 1))) {
		log_error(ID(cmd_res), "Failed to create buffer to record hierarchy for device " CMD_DEV_ID_FMT ".", CMD_DEV_ID(cmd));
		goto out;
	}

	/* Add record header to vec_buf: seqnum | flags | mod_name. */
	buffer_add(vec_buf, &cmd->udev_dev.seqnum, sizeof(cmd->udev_dev.seqnum));
	buffer_add(vec_buf, &kv_flags_no_persist, sizeof(kv_flags_no_persist));
	buffer_add(vec_buf, core_mod_name, strlen(core_mod_name) + 1);

	/* Read relatives from sysfs into vec_buf. */
	if (cmd->udev_dev.action != UDEV_ACTION_REMOVE) {
		for (i = 0; i < count; i++) {
			if (dirent[i]->d_name[0] == '.') {
				free(dirent[i]);
				continue;
			}

			if ((s = buffer_fmt_add(cmd->gen_buf, "/sys/block/%s/dev", dirent[i]->d_name))) {
				_get_sysfs_value(cmd_res, s, devno_buf, sizeof(devno_buf));
				buffer_rewind_mem(cmd->gen_buf, s);
				_canonicalize_kv_key(devno_buf);
				s = buffer_fmt_add(cmd->gen_buf, devno_buf);
				buffer_add(vec_buf, (void *) s, strlen(s) + 1);
			} else
				log_error(ID(cmd_res), "Failed to compose sysfs path for device %s which is relative of device " CMD_DEV_ID_FMT ".",
					  dirent[i]->d_name, CMD_DEV_ID(cmd));

			free(dirent[i]);
		}
		free(dirent);
	}

	/* Get the actual vector with relatives and sort it. */
	buffer_get_data(vec_buf, (const void **) (&iov), &iov_cnt);
	qsort(iov + 3, iov_cnt - 3, sizeof(struct iovec), _iov_str_item_cmp);

	if (!(s = _buffer_get_key_prefix(cmd->gen_buf, rel_spec.cur_key_prefix_spec))) {
		log_error(ID(cmd_res), _key_prefix_err_msg, cmd->udev_dev.name, cmd->udev_dev.major, cmd->udev_dev.minor);
		goto out;
	}

	rel_spec.delta->op = DELTA_OP_DETECT;

	/*
	 * Handle delta.final vector for this device.
	 * The delta.final is computed inside _kv_sorted_id_set_delta_resolve out of vec_buf.
	 * The _kv_sorted_id_set_delta_resolve also sets delta.plus and delta.minus vectors with info about changes when compared to previous record.
	 *
	 * Here, we set:
	 *	SID_{LUP,LDW} for current device
	 */
	iov = kv_store_set_value(cmd->kv_store_res, s, key, iov, iov_cnt, KV_STORE_VALUE_VECTOR | KV_STORE_VALUE_REF, 0,
				 _kv_sorted_id_set_delta_resolve, &update_arg);

	r = 0;
out:
	_destroy_delta(rel_spec.delta);

	if (vec_buf)
		buffer_destroy(vec_buf);

	if (tmp_mem_start)
		buffer_rewind_mem(cmd->gen_buf, tmp_mem_start);

	return r;
}

static int _refresh_device_hierarchy_from_sysfs(sid_resource_t *cmd_res)
{
	if ((_do_refresh_device_hierarchy_from_sysfs(cmd_res, "holders", KV_KEY_DEV_LAYER_UP, KV_KEY_DEV_LAYER_DOWN) < 0) ||
	    (_do_refresh_device_hierarchy_from_sysfs(cmd_res, "slaves", KV_KEY_DEV_LAYER_DOWN, KV_KEY_DEV_LAYER_UP) < 0))
		return -1;

	_dump_kv_store(__func__, ((struct sid_ubridge_cmd_context *) sid_resource_get_data(cmd_res))->kv_store_res);

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

		_do_sid_ubridge_cmd_set_kv(cmd, KV_NS_DEVICE, KV_KEY_DEV_READY, DEFAULT_CORE_KV_FLAGS, &ready, sizeof(ready));
		_do_sid_ubridge_cmd_set_kv(cmd, KV_NS_DEVICE, KV_KEY_DEV_RESERVED, DEFAULT_CORE_KV_FLAGS, &reserved, sizeof(reserved));
	}

	_refresh_device_hierarchy_from_sysfs(cmd_res);

	return 0;
}

static struct command_reg _cmd_ident_phase_regs[] = {
	[CMD_IDENT_PHASE_A_INIT]                   = {.name = "init",
                                                      .flags = CMD_IDENT_CAP_RDY | CMD_IDENT_CAP_RES,
                                                      .execute = NULL},

	[CMD_IDENT_PHASE_A_IDENT]                  = {.name = "ident",
                                                      .flags = 0,
                                                      .execute = _cmd_execute_identify_ident},

	[CMD_IDENT_PHASE_A_SCAN_PRE]               = {.name = "scan-pre",
                                                      .flags = CMD_IDENT_CAP_RDY,
                                                      .execute = _cmd_execute_identify_scan_pre},

	[CMD_IDENT_PHASE_A_SCAN_CURRENT]           = {.name = "scan-current",
                                                      .flags = CMD_IDENT_CAP_RDY,
                                                      .execute = _cmd_execute_identify_scan_current},

	[CMD_IDENT_PHASE_A_SCAN_NEXT]              = {.name = "scan-next",
                                                      .flags = CMD_IDENT_CAP_RES,
                                                      .execute = _cmd_execute_identify_scan_next},

	[CMD_IDENT_PHASE_A_SCAN_POST_CURRENT]      = {.name = "scan-post-current",
                                                      .flags = 0,
                                                      .execute = _cmd_execute_identify_scan_post_current},

	[CMD_IDENT_PHASE_A_SCAN_POST_NEXT]         = {.name = "scan-post-next",
                                                      .flags = 0,
                                                      .execute = _cmd_execute_identify_scan_post_next},

	[CMD_IDENT_PHASE_A_WAITING]                = {.name = "waiting",
                                                      .flags = 0,
                                                      .execute = NULL},

	[CMD_IDENT_PHASE_A_EXIT]                   = {.name = "exit",
                                                      .flags = CMD_IDENT_CAP_RDY | CMD_IDENT_CAP_RES,
                                                      .execute = NULL},

	[CMD_IDENT_PHASE_B_TRIGGER_ACTION_CURRENT] = {.name = "trigger-action-current",
                                                      .flags = 0,
                                                      .execute = _cmd_execute_identify_trigger_action_current},

	[CMD_IDENT_PHASE_B_TRIGGER_ACTION_NEXT]    = {.name = "trigger-action-next",
                                                      .flags = 0,
                                                      .execute = _cmd_execute_identify_trigger_action_next},

	[CMD_IDENT_PHASE_ERROR]                    = {.name = "error",
                                                      .flags = 0,
                                                      .execute = _cmd_execute_identify_error},
};

static int _cmd_execute_identify(struct command_exec_args *exec_args)
{
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(exec_args->cmd_res);
	sid_resource_t *modules_aggr_res, *block_mod_registry_res;
	const char *mod_name;
	cmd_ident_phase_t phase;
	int r = -1;

	cmd->ident_phase = CMD_IDENT_PHASE_A_INIT;

	if (!(modules_aggr_res = sid_resource_get_child(sid_resource_get_top_level(exec_args->cmd_res), &sid_resource_reg_aggregate, MODULES_AGGREGATE_ID))) {
		log_error(ID(exec_args->cmd_res), INTERNAL_ERROR "%s: Failed to find modules aggregate resource.", __func__);
		goto out;
	}

	if (!(block_mod_registry_res = sid_resource_get_child(modules_aggr_res, &sid_resource_reg_module_registry, MODULES_BLOCK_ID))) {
		log_error(ID(exec_args->cmd_res), INTERNAL_ERROR "%s: Failed to find block module registry resource.", __func__);
		goto out;
	}

	if (!(exec_args->block_mod_iter = sid_resource_iter_create(block_mod_registry_res))) {
		log_error(ID(exec_args->cmd_res), "Failed to create block module iterator.");
		goto out;
	}

	if (!(exec_args->type_mod_registry_res = sid_resource_get_child(modules_aggr_res, &sid_resource_reg_module_registry, MODULES_TYPE_ID))) {
		log_error(ID(exec_args->cmd_res), INTERNAL_ERROR "%s: Failed to find type module registry resource.", __func__);
		goto out;
	}

	if (_set_device_kv_records(exec_args->cmd_res) < 0) {
		log_error(ID(exec_args->cmd_res), "Failed to set device hierarchy.");
		goto out;
	}

	if (!(mod_name = _lookup_module_name(exec_args->cmd_res)))
		goto out;

	if (!(cmd->mod_res = exec_args->type_mod_res_current = sid_module_registry_get_module(exec_args->type_mod_registry_res, mod_name))) {
		log_debug(ID(exec_args->cmd_res), "Module %s not loaded.", mod_name);
		goto out;
	}

	for (phase = __CMD_IDENT_PHASE_A_START; phase <= __CMD_IDENT_PHASE_A_END; phase++) {
		log_debug(ID(exec_args->cmd_res), "Executing %s phase.", _cmd_ident_phase_regs[phase].name);
		cmd->ident_phase = phase;
		if ((r = _cmd_ident_phase_regs[phase].execute(exec_args)) < 0) {
			log_error(ID(exec_args->cmd_res), "%s phase failed.", _cmd_ident_phase_regs[phase].name);
			if (_cmd_ident_phase_regs[CMD_IDENT_PHASE_ERROR].execute(exec_args) < 0)
				log_error(ID(exec_args->cmd_res), "error phase failed.");
			goto out;
		}
	}
out:
	if (exec_args->block_mod_iter) {
		(void) sid_resource_iter_destroy(exec_args->block_mod_iter);
		exec_args->block_mod_iter = NULL;
	}

	return r;
}

static int _cmd_execute_checkpoint(struct command_exec_args *exec_args)
{
	return 0;
}

static struct command_reg _command_regs[] = {
	{.name = "unknown",    .flags = 0, .execute = _cmd_execute_unknown},
	{.name = "reply",      .flags = 0, .execute = _cmd_execute_reply},
	{.name = "version",    .flags = 0, .execute = _cmd_execute_version},
	{.name = "identify",   .flags = 0, .execute = _cmd_execute_identify},
	{.name = "checkpoint", .flags = 0, .execute = _cmd_execute_checkpoint}
};

static int _export_kv_store(sid_resource_t *cmd_res)
{
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(cmd_res);
	struct ubridge_kv_value *ubridge_kv_value;
	kv_store_iter_t *iter;
	const char *key;
	void *value;
	size_t size, iov_size, key_size, data_offset;
	kv_store_value_flags_t flags;
	sid_ubridge_kv_flags_t *value_flags;
	struct iovec *iov;
	int export_fd = -1;
	size_t bytes_written = 0;
	unsigned i;
	ssize_t r;

	/*
	 * Export key-value store to udev or for sync with master kv store.
	 *
	 * For udev, we append key=value pairs to the output buffer that is sent back
	 * to udev as result of "sid identify" udev builtin command.
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
		key = kv_store_iter_current_key(iter);

		if (flags & KV_STORE_VALUE_VECTOR) {
			iov = value;
			iov_size = size;
			ubridge_kv_value = NULL;
			value_flags = (sid_ubridge_kv_flags_t *) iov[VALUE_VECTOR_IDX_FLAGS].iov_base;
		} else {
			iov = NULL;
			ubridge_kv_value = value;
			value_flags = &ubridge_kv_value->flags;
		}

		if (!(*value_flags & KV_PERSISTENT))
			continue;

		*value_flags &= ~KV_PERSISTENT;

		key_size = strlen(key) + 1;

		// TODO: Also deal with situation if the udev namespace values are defined as vectors by chance.
		if (!strncmp(key, KV_PREFIX_NS_UDEV, strlen(KV_PREFIX_NULL KV_PREFIX_NS_UDEV))) {
			if (strcmp(key + sizeof(KV_PREFIX_NULL KV_PREFIX_NS_UDEV) - 1, KV_PREFIX_NULL)) {
				buffer_add(cmd->result_buf, (void *) key, key_size - 1);
				buffer_add(cmd->result_buf, KV_PAIR, 1);
				data_offset = _get_ubridge_kv_value_data_offset(ubridge_kv_value);
				buffer_add(cmd->result_buf, ubridge_kv_value->data + data_offset, strlen(ubridge_kv_value->data + data_offset));
				buffer_add(cmd->result_buf, KV_END, 1);
				continue;
			}
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
			if ((r = write(export_fd, ubridge_kv_value, size)) == size)
				bytes_written += r;
			else
				goto bad;
		}


	}

	lseek(export_fd, 0, SEEK_SET);
	write(export_fd, &bytes_written, sizeof(bytes_written));
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

static int _cmd_handler(sid_event_source *es, void *data)
{
	sid_resource_t *cmd_res = data;
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(cmd_res);
	struct connection *conn = sid_resource_get_data(sid_resource_get_parent(cmd_res));
	struct raw_command_header response_header = {0};
	struct command_exec_args exec_args = {0};

	int r = -1;

	(void) buffer_add(cmd->result_buf, &response_header, sizeof(response_header));

	if (cmd->protocol <= UBRIDGE_PROTOCOL) {
		/* If client speaks older protocol, reply using this protocol, if possible. */
		response_header.protocol = cmd->protocol;
		exec_args.cmd_res = cmd_res;
		if ((r = _command_regs[cmd->type].execute(&exec_args)) < 0)
			log_error_errno(ID(cmd_res), r, "Failed to execute command");
	}

	if (_export_kv_store(cmd_res) < 0) {
		log_error(ID(cmd_res), "Failed to synchronize key-value stores.");
		r = -1;
	}

	if (r < 0)
		response_header.status |= COMMAND_STATUS_FAILURE;

	(void) buffer_write(cmd->result_buf, conn->fd);

	return r;
}

static int _connection_cleanup(sid_resource_t *conn_res)
{
	sid_resource_t *worker_res = sid_resource_get_parent(conn_res);
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

static int _on_connection_event(sid_event_source *es, int fd, uint32_t revents, void *data)
{
	sid_resource_t *conn_res = data;
	struct connection *conn = sid_resource_get_data(conn_res);
	const char *raw_stream;
	size_t raw_stream_len;
	struct raw_command raw_cmd;
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
			(void) buffer_get_data(conn->buf, (const void **) &raw_stream, &raw_stream_len);
			raw_cmd.header = (struct raw_command_header *) raw_stream;
			raw_cmd.len = raw_stream_len;

			/* Sanitize command number - map all out of range command numbers to CMD_UNKNOWN. */
			if (raw_cmd.header->cmd_number <= __CMD_START || raw_cmd.header->cmd_number >= __CMD_END)
				raw_cmd.header->cmd_number = CMD_UNKNOWN;

			snprintf(id, sizeof(id) - 1, "%d/%s", getpid(), _command_regs[raw_cmd.header->cmd_number].name);

			if (!sid_resource_create(conn_res, &sid_resource_reg_ubridge_command, 0, id, &raw_cmd))
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

	if (sid_resource_create_io_event_source(res, &conn->es, conn->fd, _on_connection_event, NULL, res) < 0) {
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
		if (conn->es)
			(void) sid_resource_destroy_event_source(res, &conn->es);
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

	if (conn->es)
		(void) sid_resource_destroy_event_source(res, &conn->es);

	if (conn->buf)
		buffer_destroy(conn->buf);

	free(conn);
	return 0;
}

static int _init_command(sid_resource_t *res, const void *kickstart_data, void **data)
{
	const struct raw_command *raw_cmd = kickstart_data;
	struct sid_ubridge_cmd_context *cmd = NULL;
	int r;

	if (!(cmd = zalloc(sizeof(*cmd)))) {
		log_error(ID(res), "Failed to allocate new command structure.");
		return -1;
	}

	if (!(cmd->result_buf = buffer_create(BUFFER_TYPE_VECTOR, BUFFER_MODE_SIZE_PREFIX, 0, 1))) {
		log_error(ID(res), "Failed to create response buffer.");
		goto fail;
	}

	cmd->protocol = raw_cmd->header->protocol;
	cmd->type = raw_cmd->header->cmd_number;
	cmd->status = raw_cmd->header->status;

	if (!(cmd->gen_buf = buffer_create(BUFFER_TYPE_LINEAR, BUFFER_MODE_PLAIN, 0, PATH_MAX))) {
		log_error(ID(res), "Failed to create generic buffer.");
		goto fail;
	}

	if (!(cmd->kv_store_res = sid_resource_get_child(sid_resource_get_top_level(res), &sid_resource_reg_kv_store, MAIN_KV_STORE_NAME))) {
		log_error(ID(res), INTERNAL_ERROR "%s: Failed to find key-value store.", __func__);
		goto fail;
	}

	if ((r = _parse_cmd_nullstr_udev_env(raw_cmd, cmd)) < 0) {
		log_error_errno(ID(res), r, "Failed to parse udev environment variables.");
		goto fail;
	}

	if (sid_resource_create_deferred_event_source(res, &cmd->es, _cmd_handler, res) < 0) {
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

	(void) sid_resource_destroy_event_source(res, &cmd->es);
	buffer_destroy(cmd->gen_buf);
	buffer_destroy(cmd->result_buf);
	free(cmd->dev_id);
	free(cmd);
	return 0;
}

static int _master_kv_store_unset(const char *key_prefix, const char *key, struct kv_store_update_spec *spec, void *garg)
{
	struct kv_update_arg *arg = garg;
	struct iovec tmp_iov_old[_VALUE_VECTOR_IDX_COUNT];
	struct iovec *iov_old;

	if (!spec->old_data)
		return 1;

	iov_old = _get_value_vector(spec->old_flags, spec->old_data, spec->old_data_size, tmp_iov_old);

	if (_flags_indicate_mod_owned(VALUE_VECTOR_FLAGS(iov_old)) && strcmp(VALUE_VECTOR_MOD_NAME(iov_old), arg->mod_name)) {
		log_debug(ID(arg->res), "Refusing request from module %s to unset existing value for key %s (seqnum %" PRIu64
					"which belongs to module %s.",  arg->mod_name, key, VALUE_VECTOR_SEQNUM(iov_old),
					VALUE_VECTOR_MOD_NAME(iov_old));
		arg->ret_code = EBUSY;
		return 0;
	}

	return 1;
}

static int _master_kv_store_update(const char *key_prefix, const char *key, struct kv_store_update_spec *spec, void *garg)
{
	struct kv_update_arg *arg = garg;
	struct relation_spec *rel_spec = arg->custom;
	struct iovec tmp_iov_old[_VALUE_VECTOR_IDX_COUNT];
	struct iovec tmp_iov_new[_VALUE_VECTOR_IDX_COUNT];
	struct iovec *iov_old, *iov_new;
	int r;

	iov_old = _get_value_vector(spec->old_flags, spec->old_data, spec->old_data_size, tmp_iov_old);
	iov_new = _get_value_vector(spec->new_flags, spec->new_data, spec->new_data_size, tmp_iov_new);

	if (rel_spec->delta->op == DELTA_OP_DETECT)
		/* overwrite whole value */
		r = (!iov_old ||
		     ((VALUE_VECTOR_SEQNUM(iov_new) >= VALUE_VECTOR_SEQNUM(iov_old)) &&
		      _kv_overwrite(key_prefix, key, spec, arg)));
	else {
		/* resolve delta */
		r = _kv_sorted_id_set_delta_resolve(key_prefix, key, spec, garg);
		/* resolving delta might have changed new_data so get it afresh for the log_debug below */
		iov_new = _get_value_vector(spec->new_flags, spec->new_data, spec->new_data_size, tmp_iov_new);
	}

	if (r)
		log_debug(ID(arg->res), "Updating value for key %s%s%s (new seqnum %" PRIu64 " >= old seqnum %" PRIu64 ")",
			  key_prefix ? key_prefix : "", key_prefix ? KV_STORE_KEY_JOIN : "", key,
			  VALUE_VECTOR_SEQNUM(iov_new), iov_old ? VALUE_VECTOR_SEQNUM(iov_old) : 0);
	else
		log_debug(ID(arg->res), "Keeping old value for key %s%s%s (new seqnum %" PRIu64 " < old seqnum %" PRIu64 ")",
			  key_prefix ? key_prefix : "", key_prefix ? KV_STORE_KEY_JOIN : "", key,
			  VALUE_VECTOR_SEQNUM(iov_new), iov_old ? VALUE_VECTOR_SEQNUM(iov_old) : 0);

	return r;
}

static int _sync_master_kv_store(sid_resource_t *worker_proxy_res, sid_resource_t *ubridge_res, int fd)
{
	static const char syncing_msg[] = "Syncing master key-value store:  %s=%s (seqnum %" PRIu64 ")";
	struct ubridge *ubridge = sid_resource_get_data(ubridge_res);
	kv_store_value_flags_t flags;
	size_t msg_size, key_size, data_size, data_offset, i;
	char *key, *shm = NULL, *p, *end;
	struct ubridge_kv_value *value = NULL;
	struct iovec *iov = NULL;
	void *data_to_store;
	struct relation_spec rel_spec = {.delta = &((struct delta){0})};
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

		key_size = *((size_t *) p);
		p += sizeof(key_size);

		data_size = *((size_t *) p);
		p += sizeof(data_size);

		key = p;
		p += key_size;

		/*
		 * Note: if we're reserving a value, then we keep it even if it's NULL.
		 * This prevents others to use the same key. To unset the value,
		 * one needs to drop the flag explicitly.
		 */

		if (flags & KV_STORE_VALUE_VECTOR) {
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

			unset = !(VALUE_VECTOR_FLAGS(iov) & KV_MOD_RESERVED) && (data_size == VALUE_VECTOR_IDX_DATA);

			update_arg.mod_name = VALUE_VECTOR_MOD_NAME(iov);
			update_arg.res = ubridge->main_kv_store_res;
			update_arg.ret_code = 0;

			log_debug(ID(worker_proxy_res), syncing_msg, key, unset ? "NULL"
									    : "[vector]", VALUE_VECTOR_SEQNUM(iov));

			if (!strncmp(key, KV_PREFIX_OP_DELTA_PLUS, sizeof(KV_PREFIX_OP_DELTA_PLUS) - 1)) {
				key = key + sizeof(KV_PREFIX_OP_DELTA_PLUS) - 1;
				rel_spec.delta->op = DELTA_OP_PLUS;
			} else if (!strncmp(key, KV_PREFIX_OP_DELTA_MINUS, sizeof(KV_PREFIX_OP_DELTA_MINUS) - 1)) {
				key = key + sizeof(KV_PREFIX_OP_DELTA_MINUS) - 1;
				rel_spec.delta->op = DELTA_OP_MINUS;
			} else
				rel_spec.delta->op = DELTA_OP_DETECT;

			data_to_store = iov;
		} else {
			value = (struct ubridge_kv_value *) p;
			p += data_size;

			data_offset = _get_ubridge_kv_value_data_offset(value);
			unset = ((value->flags != KV_MOD_RESERVED) &&
				 ((data_size - data_offset) == (sizeof(struct ubridge_kv_value) + data_offset)));

			update_arg.mod_name = value->data;
			update_arg.res = ubridge->main_kv_store_res;
			update_arg.ret_code = 0;

			log_debug(ID(worker_proxy_res), syncing_msg, key, unset ? "NULL"
									    : data_offset ? value->data + data_offset
											  : value->data, value->seqnum);

			rel_spec.delta->op = DELTA_OP_DETECT;

			data_to_store = value;
		}

		if (unset)
			kv_store_unset_value(ubridge->main_kv_store_res, NULL, key, _master_kv_store_unset, &update_arg);
		else
			kv_store_set_value(ubridge->main_kv_store_res, NULL, key, data_to_store, data_size, flags, 0,
					   _master_kv_store_update, &update_arg);

		_destroy_delta(rel_spec.delta);
		free(iov);
		iov = NULL;
	}

	r = 0;

	_dump_kv_store(__func__, ubridge->main_kv_store_res);
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

	if (!(conn_res = sid_resource_create(worker_res, &sid_resource_reg_ubridge_connection, 0, NULL, &fd))) {
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

static int _on_ubridge_interface_event(sid_event_source *es, int fd, uint32_t revents, void *data)
{
	sid_resource_t *ubridge_res = data;
	struct ubridge *ubridge = sid_resource_get_data(ubridge_res);
	sid_resource_t *worker_proxy_res;
	int conn_fd;

	log_debug(ID(ubridge_res), "Received an event.");

	if (!(worker_proxy_res = worker_control_get_idle_worker(ubridge->worker_control_res))) {
		log_debug(ID(ubridge_res), "Idle worker not found, creating a new one.");
		if (!(worker_proxy_res = worker_control_get_new_worker(ubridge->worker_control_res, NULL, _worker_init_fn, ubridge)))
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

struct key_res_def {
	sid_ubridge_cmd_kv_namespace_t ns;
	const char *key;
};

static int _reserve_core_kvs(struct ubridge *ubridge)
{
	static const struct key_res_def r[] = { {KV_NS_DEVICE, KV_KEY_DEV_READY},
						{KV_NS_DEVICE, KV_KEY_DEV_RESERVED},
						{KV_NS_DEVICE, KV_KEY_DEV_LAYER_UP},
						{KV_NS_DEVICE, KV_KEY_DEV_LAYER_DOWN},
						{KV_NS_DEVICE, KV_KEY_DEV_MOD},
						{KV_NS_DEVICE, KV_KEY_GEN_GROUP_MEMBERS},
						{KV_NS_MODULE, KV_KEY_GEN_GROUP_MEMBERS},
						{KV_NS_GLOBAL, KV_KEY_GEN_GROUP_MEMBERS},
						{KV_NS_DEVICE, KV_KEY_GEN_GROUP_IN},
						{KV_NS_MODULE, KV_KEY_GEN_GROUP_IN},
						{KV_NS_GLOBAL, KV_KEY_GEN_GROUP_IN},
						{0, NULL} };
	unsigned i;

	for (i = 0; r[i].key; i++) {
		if (_do_sid_ubridge_cmd_mod_reserve_kv(NULL, &ubridge->cmd_mod, r[i].ns, r[i].key, 0) < 0)
			/* FIXME: Maybe we should also unreserve already reserved keys in case there's a failure? */
			return -1;
	}

	return 0;
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
										}};

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
										}};

static const struct sid_kv_store_resource_params main_kv_store_res_params = {.backend = KV_STORE_BACKEND_HASH,
									     .hash.initial_size = 32};

static int _init_ubridge(sid_resource_t *res, const void *kickstart_data, void **data)
{
	struct ubridge *ubridge = NULL;

	if (!(ubridge = zalloc(sizeof(struct ubridge)))) {
		log_error(ID(res), "Failed to allocate memory for interface structure.");
		goto fail;
	}

	if (!(ubridge->internal_res = sid_resource_create(res, &sid_resource_reg_aggregate,
							  SID_RESOURCE_RESTRICT_WALK_UP | SID_RESOURCE_RESTRICT_WALK_DOWN,
							  INTERNAL_AGGREGATE_ID, ubridge))) {
		log_error(ID(res), "Failed to create internal ubridge resource.");
		goto fail;
	}

	if (!(ubridge->main_kv_store_res = sid_resource_create(ubridge->internal_res, &sid_resource_reg_kv_store, SID_RESOURCE_RESTRICT_WALK_UP,
							       MAIN_KV_STORE_NAME, &main_kv_store_res_params))) {
		log_error(ID(res), "Failed to create main key-value store.");
		goto fail;
	}

	if (!(ubridge->worker_control_res = sid_resource_create(ubridge->internal_res, &sid_resource_reg_worker_control, 0,
							        NULL, NULL))) {
		log_error(ID(res), "Failed to create worker control.");
		goto fail;
	}

	if (!(ubridge->cmd_mod.gen_buf = buffer_create(BUFFER_TYPE_LINEAR, BUFFER_MODE_PLAIN, 0, PATH_MAX))) {
		log_error(ID(res), "Failed to create generic buffer.");
		goto fail;
	}

	ubridge->cmd_mod.kv_store_res = ubridge->main_kv_store_res;

	if (_reserve_core_kvs(ubridge) < 0) {
		log_error(ID(res), "Failed to reserve core key-value pairs.");
		goto fail;
	}

	block_res_mod_params.callback_arg = type_res_mod_params.callback_arg = &ubridge->cmd_mod;

	if (!(ubridge->modules_res = sid_resource_create(ubridge->internal_res, &sid_resource_reg_aggregate, 0, MODULES_AGGREGATE_ID, NULL))) {
		log_error(ID(res), "Failed to create aggreagete resource for module handlers.");
		goto fail;
	}

	if (!(sid_resource_create(ubridge->modules_res, &sid_resource_reg_module_registry, 0, MODULES_BLOCK_ID, &block_res_mod_params)) ||
	    !(sid_resource_create(ubridge->modules_res, &sid_resource_reg_module_registry, 0, MODULES_TYPE_ID, &type_res_mod_params))) {
		log_error(ID(res), "Failed to create module handler.");
		goto fail;
	}

	if ((ubridge->socket_fd = comms_unix_create(UBRIDGE_SOCKET_PATH, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC)) < 0) {
		log_error(ID(res), "Failed to create local server socket.");
		goto fail;
	}

	if (sid_resource_create_io_event_source(res, &ubridge->es, ubridge->socket_fd, _on_ubridge_interface_event, UBRIDGE_NAME, res) < 0) {
		log_error(ID(res), "Failed to register interface with event loop.");
		goto fail;
	}

	block_res_mod_params.callback_arg = type_res_mod_params.callback_arg = NULL;
	//sid_resource_dump_all_in_dot(sid_resource_get_top_level(res));

	*data = ubridge;
	return 0;
fail:
	if (ubridge) {
		if (ubridge->cmd_mod.gen_buf)
			buffer_destroy(ubridge->cmd_mod.gen_buf);
		block_res_mod_params.callback_arg = type_res_mod_params.callback_arg = NULL;
		if (ubridge->socket_fd != -1)
			(void) close(ubridge->socket_fd);
		if (ubridge->es)
			(void) sid_resource_destroy_event_source(res, &ubridge->es);
		free(ubridge);
	}
	return -1;
}

static int _destroy_ubridge(sid_resource_t *res)
{
	struct ubridge *ubridge = sid_resource_get_data(res);

	(void) sid_resource_destroy_event_source(res, &ubridge->es);

	if (ubridge->cmd_mod.gen_buf)
		buffer_destroy(ubridge->cmd_mod.gen_buf);

	if (ubridge->socket_fd != -1)
		(void) close(ubridge->socket_fd);

	free(ubridge);
	return 0;
}

const sid_resource_reg_t sid_resource_reg_ubridge_command = {
	.name = COMMAND_NAME,
	.init = _init_command,
	.destroy = _destroy_command,
};

const sid_resource_reg_t sid_resource_reg_ubridge_connection = {
	.name = CONNECTION_NAME,
	.init = _init_connection,
	.destroy = _destroy_connection,
};

const sid_resource_reg_t sid_resource_reg_ubridge = {
	.name = UBRIDGE_NAME,
	.init = _init_ubridge,
	.destroy = _destroy_ubridge,
};
