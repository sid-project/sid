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

#include <ctype.h>
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
#define OBSERVER_NAME                "observer"
#define WORKER_NAME                  "worker"
#define COMMAND_NAME                 "command"

#define INTERNAL_AGGREGATE_ID        "ubridge-internal"
#define OBSERVERS_AGGREGATE_ID       "observers"
#define MODULES_AGGREGATE_ID         "modules"
#define MODULES_BLOCK_ID             "block"
#define MODULES_TYPE_ID              "type"

#define WORKER_IDLE_TIMEOUT_USEC     5000000

#define INTERNAL_COMMS_BUFFER_LEN      1

#define INTERNAL_COMMS_CMD_RUNNING     1
#define INTERNAL_COMMS_CMD_IDLE        2
#define INTERNAL_COMMS_CMD_EXIT        3
#define INTERNAL_COMMS_CMD_KV_SYNC     4
#define INTERNAL_COMMS_CMD_KV_SYNC_ACK 5

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

#define KV_NS_UDEV_KEY_PREFIX   "U" KV_STORE_KEY_JOIN
#define KV_NS_DEVICE_KEY_PREFIX "D" KV_STORE_KEY_JOIN
#define KV_NS_MODULE_KEY_PREFIX "M" KV_STORE_KEY_JOIN
#define KV_NS_GLOBAL_KEY_PREFIX "G" KV_STORE_KEY_JOIN

#define KV_KEY_NULL_DEV       "0_0"
#define KV_KEY_DEV_READY      "SID_RDY"
#define KV_KEY_DEV_RESERVED   "SID_RES"
#define KV_KEY_DEV_LAYER_UP   "SID_LUP"
#define KV_KEY_DEV_LAYER_DOWN "SID_LDW"
#define KV_KEY_DEV_MOD        "SID_MOD"
#define KV_KEY_DEV_NEXT_MOD   SID_UBRIDGE_CMD_KEY_DEVICE_NEXT_MOD

#define CORE_MOD_NAME         "core"
#define DEFAULT_CORE_KV_FLAGS  KV_PERSISTENT | KV_MOD_RESERVED | KV_MOD_PRIVATE

#define UDEV_KEY_ACTION     "ACTION"
#define UDEV_KEY_DEVNAME    "DEVNAME"
#define UDEV_KEY_DEVTYPE    "DEVTYPE"
#define UDEV_KEY_MAJOR      "MAJOR"
#define UDEV_KEY_MINOR      "MINOR"
#define UDEV_KEY_SEQNUM     "SEQNUM"
#define UDEV_KEY_SYNTH_UUID "SYNTH_UUID"

/* internal resources */
const sid_resource_reg_t sid_resource_reg_ubridge_observer;
const sid_resource_reg_t sid_resource_reg_ubridge_worker;
const sid_resource_reg_t sid_resource_reg_ubridge_command;

struct sid_ubridge_cmd_mod_context {
	sid_resource_t *kv_store_res;
};

struct ubridge {
	int socket_fd;
	sid_event_source *es;
	sid_resource_t *internal_res;
	sid_resource_t *modules_res;
	sid_resource_t *observers_res;
	sid_resource_t *main_kv_store_res;
	struct sid_ubridge_cmd_mod_context cmd_mod;
};

struct kickstart {
	pid_t worker_pid;
	int comms_fd;
};

typedef enum {
	WORKER_IDLE,
	WORKER_INITIALIZING,
	WORKER_RUNNING,
	WORKER_EXITING,
	WORKER_EXITED,
} worker_state_t;

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

struct observer {
	pid_t worker_pid;
	int comms_fd;
	sid_event_source *comms_es;
	sid_event_source *child_es;
	sid_event_source *idle_timeout_es;
	worker_state_t worker_state;
};

struct worker {
	int comms_fd;
	int conn_fd;
	sid_event_source *sigint_es;
	sid_event_source *sigterm_es;
	sid_event_source *comms_es;
	sid_event_source *conn_es;
	struct buffer *buf;
};

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

struct device {
	udev_action_t action;
	int major;
	int minor;
	char *name;
	char *type;
	uint64_t seqnum;
	char *synth_uuid;
};

struct sid_ubridge_cmd_context {
	uint8_t protocol;
	command_t type;
	union {
		cmd_ident_phase_t ident_phase;
	};
	uint16_t status;
	sid_event_source *es;
	struct device dev;
	sid_resource_t *kv_store_res;
	sid_resource_t *mod_res; /* the module that is processed at the moment */
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

struct kv_store_value {
	uint64_t seqnum;
	uint64_t flags;
	char data[0];
};

#define CMD_IDENT_CAP_RDY UINT32_C(0x000000001) /* can set ready state */
#define CMD_IDENT_CAP_RES UINT32_C(0x000000002) /* can set reserved state */

static struct command_reg _cmd_ident_phase_regs[];

udev_action_t sid_ubridge_cmd_dev_get_action(struct sid_ubridge_cmd_context *cmd)
{
	return cmd->dev.action;
}

int sid_ubridge_cmd_cmd_dev_get_major(struct sid_ubridge_cmd_context *cmd)
{
	return cmd->dev.major;
}

int sid_ubridge_cmd_cmd_dev_get_minor(struct sid_ubridge_cmd_context *cmd)
{
	return cmd->dev.minor;
}

const char *sid_ubridge_cmd_dev_get_name(struct sid_ubridge_cmd_context *cmd)
{
	return cmd->dev.name;
}

const char *sid_ubridge_cmd_dev_get_type(struct sid_ubridge_cmd_context *cmd)
{
	return cmd->dev.type;
}

uint64_t sid_ubridge_cmd_dev_get_seqnum(struct sid_ubridge_cmd_context *cmd)
{
	return cmd->dev.seqnum;
}

const char *sid_ubridge_cmd_dev_get_synth_uuid(struct sid_ubridge_cmd_context *cmd)
{
	return cmd->dev.synth_uuid;
}

static const char *_get_key_prefix(sid_ubridge_cmd_kv_namespace_t ns, const char *mod_name, int major, int minor,
				   char *buf, size_t buf_size)
{
	switch (ns) {
		case KV_NS_UDEV:
			snprintf(buf, buf_size, "%s%d_%d", KV_NS_UDEV_KEY_PREFIX, major, minor);
			break;
		case KV_NS_DEVICE:
			snprintf(buf, buf_size, "%s%d_%d", KV_NS_DEVICE_KEY_PREFIX, major, minor);
			break;
		case KV_NS_MODULE:
			snprintf(buf, buf_size, "%s%s", KV_NS_MODULE_KEY_PREFIX, mod_name);
			break;
		case KV_NS_GLOBAL:
			snprintf(buf, buf_size, "%s*", KV_NS_GLOBAL_KEY_PREFIX);
			break;
	}

	return buf;
}

struct kv_conflict_arg {
	sid_resource_t *res;
	const char *mod_name; /* in */
	int ret_code;	      /* out */
};

static int _kv_overwrite(const char *key_prefix, const char *key, struct kv_store_value *old, struct kv_store_value *new, struct kv_conflict_arg *arg)
{
	const char *reason;

	if (old->flags & KV_MOD_PRIVATE) {
		if (strcmp(old->data, new->data)) {
			reason = "private";
			arg->ret_code = EACCES;
			goto keep_old;
		}
	}
	else if (old->flags & KV_MOD_PROTECTED) {
		if (strcmp(old->data, new->data)) {
			reason = "protected";
			arg->ret_code = EPERM;
			goto keep_old;
		}
	}
	else if (old->flags & KV_MOD_RESERVED) {
		if (strcmp(old->data, new->data)) {
			reason = "reserved";
			arg->ret_code = EBUSY;
			goto keep_old;
		}
	}

	arg->ret_code = 0;
	return 1;
keep_old:
	log_debug(ID(arg->res), "Module %s can't overwrite value with key %s%s%s which is %s and attached to %s module.",
		  new->data, key_prefix ? key_prefix : "", key_prefix ? KV_STORE_KEY_JOIN : "", key, reason, *old->data ? old->data : "core");
	return 0;
}

static int _flags_indicate_mod_owned(uint64_t flags)
{
	return flags & (KV_MOD_PROTECTED | KV_MOD_PRIVATE | KV_MOD_RESERVED);
}

static size_t _get_kv_store_value_data_offset(struct kv_store_value *kv_store_value)
{
	return strlen(kv_store_value->data) + 1;
}

static int _passes_global_reservation_check(sid_resource_t *kv_store_res, const char *mod_name,
					    sid_ubridge_cmd_kv_namespace_t ns, const char *key,
					    char *buf, size_t buf_size)
{
	struct kv_store_value *found;
	const char *key_prefix;

	if ((ns != KV_NS_UDEV) && (ns != KV_NS_DEVICE))
		return 1;

	if (!(key_prefix = _get_key_prefix(ns, mod_name, 0, 0, buf, buf_size))) {
		errno = ENOKEY;
		return 0;
	}

	if ((found = kv_store_get_value(kv_store_res, key_prefix, key, NULL)) && (found->flags & KV_MOD_RESERVED) && strcmp(found->data, mod_name)) {
		log_debug(ID(kv_store_res), "Module %s can't overwrite value with key %s%s%s which is reserved and attached to %s module.",
			  mod_name, key_prefix ? key_prefix : "", key_prefix ? KV_STORE_KEY_JOIN : "", key, *found->data ? found->data : "core");
		return 0;
	}

	return 1;
}

static void *_do_sid_ubridge_cmd_set_kv(struct sid_ubridge_cmd_context *cmd, sid_ubridge_cmd_kv_namespace_t ns,
					const char *key, uint64_t flags, const void *value, size_t value_size)
{
	char buf[PATH_MAX];
	const char *key_prefix;
	const char *mod_name;
	struct iovec iov[4];
	struct kv_store_value *kv_store_value;
	struct kv_conflict_arg conflict_arg;

	mod_name = cmd->mod_res ? sid_module_get_name(sid_resource_get_data(cmd->mod_res)) : CORE_MOD_NAME;

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
	    !_passes_global_reservation_check(cmd->kv_store_res, mod_name, ns, key, buf, sizeof(buf)))
		return NULL;

	if (!(key_prefix = _get_key_prefix(ns, mod_name, cmd->dev.major, cmd->dev.minor, buf, sizeof(buf)))) {
		errno = ENOKEY;
		return NULL;
	}

	iov[0].iov_base = &cmd->dev.seqnum;
	iov[0].iov_len = sizeof(cmd->dev.seqnum);

	iov[1].iov_base = &flags;
	iov[1].iov_len = sizeof(flags);

	iov[2].iov_base = (void *) mod_name;
	iov[2].iov_len = strlen(mod_name) + 1;

	iov[3].iov_base = (void *) value;
	iov[3].iov_len = value ? value_size : 0;

	conflict_arg.res = cmd->kv_store_res;
	conflict_arg.mod_name = mod_name;
	conflict_arg.ret_code = 0;

	kv_store_value = kv_store_set_value(cmd->kv_store_res, key_prefix, key, iov, 4,
					    KV_STORE_VALUE_VECTOR, KV_STORE_VALUE_OP_MERGE,
					    (kv_resolver_t) _kv_overwrite, &conflict_arg);

	if (!kv_store_value) {
		if (errno == EADV)
			errno = conflict_arg.ret_code;
		return NULL;
	}

	if (!value_size)
		return NULL;

	return kv_store_value->data + _get_kv_store_value_data_offset(kv_store_value);
}

void *sid_ubridge_cmd_set_kv(struct sid_ubridge_cmd_context *cmd, sid_ubridge_cmd_kv_namespace_t ns,
			     const char *key, const void *value, size_t value_size, uint64_t flags)
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
				   const char *key, size_t *value_size, uint64_t *flags)
{
	char buf[PATH_MAX];
	const char *key_prefix;
	struct kv_store_value *kv_store_value;
	const char *mod_name;
	size_t size, data_offset;

	if (!cmd || !key || !*key) {
		errno = EINVAL;
		return NULL;
	}

	mod_name = cmd->mod_res ? sid_module_get_name(sid_resource_get_data(cmd->mod_res)) : CORE_MOD_NAME;

	if (!(key_prefix = _get_key_prefix(ns, mod_name, cmd->dev.major, cmd->dev.minor, buf, sizeof(buf)))) {
		errno = ENOKEY;
		return NULL;
	}

	if (!(kv_store_value = kv_store_get_value(cmd->kv_store_res, key_prefix, key, &size)))
		return NULL;

	if (kv_store_value->flags & KV_MOD_PRIVATE) {
		if (strcmp(kv_store_value->data, mod_name)) {
			errno = EACCES;
			return NULL;
		}
	}

	if (flags)
		*flags = kv_store_value->flags;

	data_offset = _get_kv_store_value_data_offset(kv_store_value);
	size -= (sizeof(*kv_store_value) + data_offset);

	if (value_size)
		*value_size = size;

	if (size)
		return kv_store_value->data + data_offset;
	else
		return NULL;
}

static int _kv_reserve(const char *key_prefix, const char *key, struct kv_store_value *old, struct kv_store_value *new, struct kv_conflict_arg *arg)
{
	if (strcmp(old->data, new->data)) {
		log_debug(ID(arg->res), "Module %s can't reserve key %s%s%s which is already reserved by %s module.",
			  new->data, key_prefix ? key_prefix : "", key_prefix ? KV_STORE_KEY_JOIN : "", key, *old->data ? old->data : "core");
		arg->ret_code = EBUSY;
		return 0;
	}

	return 1;
}

static int _kv_unreserve(const char *key_prefix, const char *key, struct kv_store_value *old, struct kv_store_value *new, struct kv_conflict_arg *arg)
{
	if (strcmp(old->data, arg->mod_name)) {
		log_debug(ID(arg->res), "Module %s can't unreserve key %s%s%s which is reserved by %s module.",
			  arg->mod_name, key_prefix ? key_prefix : "", key_prefix ? KV_STORE_KEY_JOIN : "", key, *old->data ? old->data : "core");
		arg->ret_code = EBUSY;
		return 0;
	}

	return 1;
}

int _do_sid_ubridge_cmd_mod_reserve_kv(struct sid_module *mod, struct sid_ubridge_cmd_mod_context *cmd_mod,
				       sid_ubridge_cmd_kv_namespace_t ns, const char *key, int unset)
{
	char buf[PATH_MAX];
	const char *key_prefix;
	const char *mod_name;
	struct iovec iov[3];
	struct kv_store_value *kv_store_value;
	static uint64_t null_int = 0;
	uint64_t flags = unset ? 0 : KV_MOD_RESERVED;
	struct kv_conflict_arg conflict_arg;
	int is_worker;

	mod_name = mod ? sid_module_get_name(mod) : CORE_MOD_NAME;

	if (!(key_prefix = _get_key_prefix(ns, mod_name, 0, 0, buf, sizeof(buf)))) {
		errno = ENOKEY;
		return -1;
	}

	if (!(cmd_mod->kv_store_res)) {
		errno = ENOMEDIUM;
		return -1;
	}

	conflict_arg.res = cmd_mod->kv_store_res;
	conflict_arg.mod_name = mod_name;
	conflict_arg.ret_code = 0;

	if ((is_worker = sid_resource_is_registered_by(sid_resource_get_top_level(cmd_mod->kv_store_res), &sid_resource_reg_ubridge_worker)))
		flags |= KV_PERSISTENT;

	if (unset && !is_worker) {
		kv_store_unset_value(cmd_mod->kv_store_res, key_prefix, key,
				     (kv_resolver_t) _kv_unreserve, &conflict_arg);

		if (errno == EADV)
			errno = conflict_arg.ret_code;
		return -1;
	} else {
		iov[0].iov_base = &null_int;
		iov[0].iov_len = sizeof(null_int);

		iov[1].iov_base = &flags;
		iov[1].iov_len = sizeof(flags);

		iov[2].iov_base = (void *) mod_name;
		iov[2].iov_len = strlen(mod_name) + 1;

		kv_store_value = kv_store_set_value(cmd_mod->kv_store_res, key_prefix, key, iov, 3,
						    KV_STORE_VALUE_VECTOR, KV_STORE_VALUE_OP_MERGE,
						    (kv_resolver_t) _kv_reserve, &conflict_arg);

		if (!kv_store_value) {
			if (errno == EADV)
				errno = conflict_arg.ret_code;
			return -1;
		}
	}

	return 0;

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

	/* Common key=value pairs are also directly in the cmd->dev structure. */
	if (!strncmp(key, UDEV_KEY_ACTION, key_len))
		cmd->dev.action = util_get_udev_action_from_string(value);
	else if (!strncmp(key, UDEV_KEY_DEVNAME, key_len))
		cmd->dev.name = value;
	else if (!strncmp(key, UDEV_KEY_DEVTYPE, key_len))
		cmd->dev.type = value;
	else if (!strncmp(key, UDEV_KEY_MAJOR, key_len))
		cmd->dev.major = atoi(value);
	else if (!strncmp(key, UDEV_KEY_MINOR, key_len))
		cmd->dev.minor = atoi(value);
	else if (!strncmp(key, UDEV_KEY_SEQNUM, key_len))
		cmd->dev.seqnum = strtoull(value, NULL, 10);
	else if (!strncmp(key, UDEV_KEY_SYNTH_UUID, key_len))
		cmd->dev.synth_uuid = value;

	key[key_len] = KV_PAIR[0];

	return 0;
bad:
	key[key_len] = KV_PAIR[0];

	return -1;
};

static int _parse_cmd_nullstr_udev_env(const struct raw_command *raw_cmd, struct sid_ubridge_cmd_context *cmd)
{
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

	cmd->dev.major = major(devno);
	cmd->dev.minor = minor(devno);

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
		if (major == cmd->dev.major) {
			found = end + 1;
			break;
		}
	}

	if (!found) {
		log_error(ID(cmd_res), "Unable to find major number %d for device %s in %s.",
			  cmd->dev.major, cmd->dev.name, PROC_DEVICES_PATH);
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
		log_error_errno(ID(cmd_res), errno, "Failed to store device %s (%d:%d) module name.", cmd->dev.name, cmd->dev.major, cmd->dev.minor);
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
				log_error(ID(exec_args->cmd_res), INTERNAL_ERROR "Trying illegal execution of block modules in %s state.",
					  _cmd_ident_phase_regs[phase].name);
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

	sid_resource_dump_all_in_dot(sid_resource_get_top_level(exec_args->cmd_res));

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

	snprintf(umonitor->tag, sizeof(umonitor->tag), "sid_%" PRIu64, cmd->dev.seqnum);

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
		log_error(ID(exec_args->cmd_res), INTERNAL_ERROR "Failed to find modules aggregate resource.");
		goto out;
	}

	if (!(block_mod_registry_res = sid_resource_get_child(modules_aggr_res, &sid_resource_reg_module_registry, MODULES_BLOCK_ID))) {
		log_error(ID(exec_args->cmd_res), INTERNAL_ERROR "Failed to find block module registry resource.");
		goto out;
	}

	if (!(exec_args->block_mod_iter = sid_resource_iter_create(block_mod_registry_res))) {
		log_error(ID(exec_args->cmd_res), "Failed to create block module iterator.");
		goto out;
	}

	if (!(exec_args->type_mod_registry_res = sid_resource_get_child(modules_aggr_res, &sid_resource_reg_module_registry, MODULES_TYPE_ID))) {
		log_error(ID(exec_args->cmd_res), INTERNAL_ERROR "Failed to find type module registry resource.");
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

static int _send_export_fd_to_observer(sid_resource_t *cmd_res, int export_fd)
{
	struct worker *worker = sid_resource_get_data(sid_resource_get_top_level(cmd_res));
	char buf[INTERNAL_COMMS_BUFFER_LEN];

	buf[0] = INTERNAL_COMMS_CMD_KV_SYNC;

	return comms_unix_send(worker->comms_fd, buf, sizeof(buf), export_fd);
}

static int _export_kv_stores(sid_resource_t *cmd_res)
{
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(cmd_res);
	struct kv_store_value *kv_store_value;
	kv_store_iter_t *iter;
	const char *key;
	size_t size, key_size, data_offset;
	int export_fd = -1;
	size_t bytes_written = 0;
	ssize_t r;

	/*
	 * Export key-value store to udev or for sync with master kv store.
	 *
	 * For udev, we append key=value pairs to the output buffer that is sent back
	 * to udev as result of "sid identify" udev builtin command.
	 *
	 * For others, we serialize the temp key-value store to an anonymous file in memory
	 * created by memfd_create. Then we pass the file FD over to observer that reads it
	 * and it updates the "master" key-value store.
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
	while ((kv_store_value = kv_store_iter_next(iter, &size, NULL))) {
		if (!(kv_store_value->flags & KV_PERSISTENT))
			continue;

		kv_store_value->flags &= ~KV_PERSISTENT;

		key = kv_store_iter_current_key(iter);
		key_size = strlen(key) + 1;

		if (!strncmp(key, KV_NS_UDEV_KEY_PREFIX, strlen(KV_NS_UDEV_KEY_PREFIX))) {
			/* Export to udev. */
			if (strcmp(key + sizeof(KV_NS_UDEV_KEY_PREFIX) - 1, KV_KEY_NULL_DEV)) {
				buffer_add(cmd->result_buf, (void *) key, key_size - 1);
				buffer_add(cmd->result_buf, KV_PAIR, 1);
				data_offset = _get_kv_store_value_data_offset(kv_store_value);
				buffer_add(cmd->result_buf, kv_store_value->data + data_offset, strlen(kv_store_value->data + data_offset));
				buffer_add(cmd->result_buf, KV_END, 1);
				continue;
			}
		} 

		/*
 		 * Export to master process.
 		 *
		 * Serialization format fields:
		 *
		 *  1) overall message size (size_t)
		 *  2) key size             (size_t)
		 *  3) data size            (size_t)
		 *  4) key                  (key_size)
		 *  5) data                 (data_size)
		 *
		 *  Repeat 2) - 5) as long as there are items to send.
		 */
		// TODO: Clean up this code!
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

		if ((r = write(export_fd, kv_store_value, size)) == size)
			bytes_written += r;
		else
			goto bad;
	}

	lseek(export_fd, 0, SEEK_SET);
	write(export_fd, &bytes_written, sizeof(bytes_written));
	lseek(export_fd, 0, SEEK_SET);

	if (bytes_written)
		_send_export_fd_to_observer(cmd_res, export_fd);

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
	struct worker *worker = sid_resource_get_data(sid_resource_get_parent(cmd_res));
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

	if (_export_kv_stores(cmd_res) < 0) {
		log_error(ID(cmd_res), "Failed to synchronize key-value stores.");
		r = -1;
	}

	if (r < 0)
		response_header.status |= COMMAND_STATUS_FAILURE;

	(void) buffer_write(cmd->result_buf, worker->conn_fd);

	return r;
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

	if (!(cmd->result_buf = buffer_create(BUFFER_TYPE_VECTOR, BUFFER_MODE_SIZE_PREFIX, 0))) {
		log_error(ID(res), "Failed to create response buffer.");
		goto fail;
	}

	cmd->protocol = raw_cmd->header->protocol;
	cmd->type = raw_cmd->header->cmd_number;
	cmd->status = raw_cmd->header->status;

	if (!(cmd->kv_store_res = sid_resource_get_child(sid_resource_get_top_level(res), &sid_resource_reg_kv_store, MAIN_KV_STORE_NAME))) {
		log_error(ID(res), INTERNAL_ERROR "Failed to find key-value store.");
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
	free(cmd);
	return -1;
}

static int _destroy_command(sid_resource_t *res)
{
	struct sid_ubridge_cmd_context *cmd = sid_resource_get_data(res);

	(void) sid_resource_destroy_event_source(res, &cmd->es);
	buffer_destroy(cmd->result_buf);
	free(cmd);
	return 0;
}

static int _worker_cleanup(sid_resource_t *worker_res)
{
	struct worker *worker = sid_resource_get_data(worker_res);
	char buf[INTERNAL_COMMS_BUFFER_LEN];
	sid_resource_iter_t *iter;
	sid_resource_t *cmd_res;

	if (!(iter = sid_resource_iter_create(worker_res)))
		return -1;

	while ((cmd_res = sid_resource_iter_next(iter))) {
		if (sid_resource_is_registered_by(cmd_res, &sid_resource_reg_ubridge_command))
			(void) sid_resource_destroy(cmd_res);
	}

	sid_resource_iter_destroy(iter);

	(void) sid_resource_destroy_event_source(worker_res, &worker->conn_es);
	(void) buffer_reset(worker->buf, 0);

	/*
	 *  FIXME: Either send INTERNAL_COMMS_CMD_IDLE or EXIT based on configuration,
	 *        take into account the KV store backend - e.g. if we're using hash,
	 *        then we can't have a pool of IDLE workers, we need to fork a new
	 *        process for each request.
	 */

	/* buf[0] = INTERNAL_COMMS_CMD_IDLE; */
	buf[0] = INTERNAL_COMMS_CMD_EXIT;
	if (!comms_unix_send(worker->comms_fd, buf, sizeof(buf), -1))
		return -1;

	return 0;
}

static int _master_kv_store_unset(const char *key_prefix, const char *key, struct kv_store_value *old, void *null_value, struct kv_conflict_arg *arg)
{
	if (_flags_indicate_mod_owned(old->flags) && strcmp(old->data, arg->mod_name)) {
		log_debug(ID(arg->res), "Refusing request from module %s to unset existing value for key %s (seqnum %" PRIu64
					"which belongs to module %s.",  arg->mod_name, key, old->seqnum, old->data);
		arg->ret_code = EBUSY;
		return 0;
	}

	return 1;
}

static int _master_kv_store_update(const char *key_prefix, const char *key, struct kv_store_value *old, struct kv_store_value *new, struct kv_conflict_arg *arg)
{
	if (new->seqnum >= old->seqnum) {
		if (_kv_overwrite(key_prefix, key, old, new, arg)) {
			log_debug(ID(arg->res), "Updating value for key %s%s%s (new seqnum %" PRIu64 " >= old seqnum %" PRIu64 ")",
				  key_prefix ? key_prefix : "", key_prefix ? KV_STORE_KEY_JOIN : "", key, new->seqnum, old->seqnum);
			return 1;
		}

		return 0;
	}

	log_debug(ID(arg->res), "Keeping old value for key %s%s%s (new seqnum %" PRIu64 " < old seqnum %" PRIu64 ")",
		  key_prefix ? key_prefix : "", key_prefix ? KV_STORE_KEY_JOIN : "", key, new->seqnum, old->seqnum);
	return 0;
}

static int _sync_master_kv_store(sid_resource_t *observer_res, int fd)
{
	struct ubridge *ubridge = sid_resource_get_data(sid_resource_get_parent(observer_res));

	size_t msg_size, key_size, data_size, data_offset;
	char *key, *shm, *p, *end;
	struct kv_store_value *data;
	struct kv_conflict_arg conflict_arg;
	int unset;

	if (read(fd, &msg_size, sizeof(msg_size)) != sizeof(msg_size)) {
		log_error_errno(ID(observer_res), errno, "Failed to read shared memory size");
		return -1;
	}

	if ((p = shm = mmap(NULL, msg_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED) {
		log_error_errno(ID(observer_res), errno, "Failed to map memory with key-value store");
		return -1;
	}

	p += sizeof(msg_size);
	end = p + msg_size;

	while (p < end) {
		key_size = *((size_t *) p);
		p += sizeof(key_size);
		data_size = *((size_t *) p);
		p += sizeof(data_size);
		key = p;
		p += key_size;
		data = (struct kv_store_value *) p;
		p += data_size;

		data_offset = _get_kv_store_value_data_offset(data);
		/*
		 * Note: if we're reserving a value, then we keep it even if it's NULL.
		 * This prevents others to use the same key. To unset the value,
		 * one needs to drop the flag explicitly.
		 */
		unset = ((data->flags != KV_MOD_RESERVED) &&
			 ((data_size - data_offset) == (sizeof(struct kv_store_value) + _get_kv_store_value_data_offset(data))));

		log_debug(ID(observer_res), "Syncing master key-value store:  %s=%s (seqnum %" PRIu64 ")", key,
			  unset ? "NULL" : data_offset ? data->data + data_offset : data->data, data->seqnum);

		conflict_arg.res = ubridge->main_kv_store_res;
		conflict_arg.mod_name = data->data;
		conflict_arg.ret_code = 0;

		if (unset)
			kv_store_unset_value(ubridge->main_kv_store_res, NULL, key,
					     (kv_resolver_t) _master_kv_store_unset, &conflict_arg);
		else
			kv_store_set_value(ubridge->main_kv_store_res, NULL, key, data, data_size, 0, 0,
					   (kv_resolver_t) _master_kv_store_update, &conflict_arg);
	}

	if (munmap(shm, msg_size) < 0) {
		log_error_errno(ID(observer_res), errno, "Failed to unmap memory with key-value store");
		return -1;
	}

	return 0;
}

static int _on_worker_conn_event(sid_event_source *es, int fd, uint32_t revents, void *data)
{
	sid_resource_t *worker_res = data;
	struct worker *worker = sid_resource_get_data(worker_res);
	const char *raw_stream;
	size_t raw_stream_len;
	struct raw_command raw_cmd;
	char id[32];
	ssize_t n;
	int r = 0;

	if (revents & EPOLLERR) {
		if (revents & EPOLLHUP)
			log_error(ID(worker_res), "Peer connection closed prematurely.");
		else
			log_error(ID(worker_res), "Connection error.");
		
		(void) _worker_cleanup(worker_res);
		return -1;
	}

	n = buffer_read(worker->buf, fd);
	if (n > 0) {
		if (buffer_is_complete(worker->buf)) {
			(void) buffer_get_data(worker->buf, (const void **) &raw_stream, &raw_stream_len);
			raw_cmd.header = (struct raw_command_header *) raw_stream;
			raw_cmd.len = raw_stream_len;

			/* Sanitize command number - map all out of range command numbers to CMD_UNKNOWN. */
			if (raw_cmd.header->cmd_number <= __CMD_START || raw_cmd.header->cmd_number >= __CMD_END)
				raw_cmd.header->cmd_number = CMD_UNKNOWN;

			snprintf(id, sizeof(id) - 1, "%d/%s", getpid(), _command_regs[raw_cmd.header->cmd_number].name);

			if (!sid_resource_create(worker_res, &sid_resource_reg_ubridge_command, 0, id, &raw_cmd))
				log_error(ID(worker_res), "Failed to register command for processing.");

			(void) buffer_reset(worker->buf, 0);
		}
	} else {
		if (n < 0) {
			if (errno == EAGAIN || errno == EINTR)
				return 0;
			log_sys_error(ID(worker_res), "buffer_read_msg", "");
			r = -1;
		}

		if (_worker_cleanup(worker_res) < 0)
			r = -1;	
	}

	return r;
}

static int _on_worker_comms_event(sid_event_source *es, int fd, uint32_t revents, void *data)
{
	sid_resource_t *worker_res = data;
	struct worker *worker = sid_resource_get_data(worker_res);
	char buf[INTERNAL_COMMS_BUFFER_LEN];
	int fd_received;

	if (comms_unix_recv(worker->comms_fd, buf, sizeof(buf), &fd_received) < 0)
		return -1;

	if (fd_received != -1) {
		worker->conn_fd = fd_received;

		if (sid_resource_create_io_event_source(worker_res, &worker->conn_es, fd_received,
							_on_worker_conn_event, NULL, worker_res) < 0) {
			log_error(ID(worker_res), "Failed to register new connection.");
			return -1;
		}

		buf[0] = INTERNAL_COMMS_CMD_RUNNING;
		if (!comms_unix_send(worker->comms_fd, buf, sizeof(buf), -1))
			return -1;
	}

	return 0;
}

#define WORKER_STATE_CHANGED_TO_MSG "Worker state changed to "

static int _make_worker_exit(sid_resource_t *observer_res)
{
	struct observer *observer = sid_resource_get_data(observer_res);

	observer->worker_state = WORKER_EXITING;
	log_debug(ID(observer_res), WORKER_STATE_CHANGED_TO_MSG "WORKER_EXITING.");

	return kill(observer->worker_pid, SIGTERM);
}

static int _on_idle_task_timeout_event(sid_event_source *es, uint64_t usec, void *data)
{
	sid_resource_t *observer_res = data;

	log_debug(ID(observer_res), "Idle timeout expired.");
	_make_worker_exit(observer_res);

	return 0;
}

static int _on_observer_comms_event(sid_event_source *es, int fd, uint32_t revents, void *data)
{
	sid_resource_t *observer_res = data;
	struct observer *observer = sid_resource_get_data(observer_res);
	char buf[INTERNAL_COMMS_BUFFER_LEN];
	int fd_received;
	uint64_t timeout_usec;

	if (comms_unix_recv(observer->comms_fd, buf, sizeof(buf), &fd_received) < 0)
		return -1;

	if (buf[0] == INTERNAL_COMMS_CMD_RUNNING) {
		observer->worker_state = WORKER_RUNNING;
		log_debug(ID(observer_res), WORKER_STATE_CHANGED_TO_MSG "WORKER_RUNNING.");
	} else if (buf[0] == INTERNAL_COMMS_CMD_IDLE) {
		timeout_usec = util_get_now_usec(CLOCK_MONOTONIC) + WORKER_IDLE_TIMEOUT_USEC;
		sid_resource_create_time_event_source(observer_res, &observer->idle_timeout_es, CLOCK_MONOTONIC,
						      timeout_usec, 0, _on_idle_task_timeout_event, NULL, observer_res);
		observer->worker_state = WORKER_IDLE;
		log_debug(ID(observer_res), WORKER_STATE_CHANGED_TO_MSG "WORKER_IDLE.");
	} else if (buf[0] == INTERNAL_COMMS_CMD_EXIT) {
		_make_worker_exit(observer_res);
	} else if (buf[0] == INTERNAL_COMMS_CMD_KV_SYNC) {
		log_debug(ID(observer_res), "Received worker's key-value store to sync with master key-value store (fd %d).", fd_received);
		_sync_master_kv_store(observer_res, fd_received);
		close(fd_received);
	}

	return 0;
}

static int _on_observer_child_event(sid_event_source *es, const siginfo_t *si, void *data)
{
	static const char worker_exited_msg[] = WORKER_STATE_CHANGED_TO_MSG "WORKER_EXITED";
	sid_resource_t *observer_res = data;
	struct observer *observer = sid_resource_get_data(observer_res);

	observer->worker_state = WORKER_EXITED;

	switch (si->si_code) {
		case CLD_EXITED:
			log_debug(ID(observer_res), "%s (exited with exit code %d).", worker_exited_msg, si->si_status);
			break;
		case CLD_KILLED:
		case CLD_DUMPED:
			log_debug(ID(observer_res), "%s (terminated by signal %d).", worker_exited_msg, si->si_status);
			break;
		default:
			log_debug(ID(observer_res), "%s (failed unexpectedly).", worker_exited_msg);
	}

	(void) sid_resource_destroy(observer_res);
	return 0;
}

static int _on_signal_event(sid_event_source *es, const struct signalfd_siginfo *si, void *userdata)
{
	sid_resource_t *res = userdata;

	log_print(ID(res), "Received signal %d from %d.", si->ssi_signo, si->ssi_pid);
	sid_resource_exit_event_loop(res);

	return 0;
}

static int _init_observer(sid_resource_t *res, const void *kickstart_data, void **data)
{
	const struct kickstart *kickstart = kickstart_data;
	struct observer *observer = NULL;

	if (!(observer = zalloc(sizeof(*observer)))) {
		log_error(ID(res), "Failed to allocate new observer structure.");
		goto fail;
	}

	observer->worker_pid = kickstart->worker_pid;
	observer->comms_fd = kickstart->comms_fd;
	observer->worker_state = WORKER_IDLE;

	/* TEST: try sleeping here for a while here to check for races. */
	if (sid_resource_create_child_event_source(res, &observer->child_es, observer->worker_pid, WEXITED, _on_observer_child_event, NULL, res) < 0) {
		log_error(ID(res), "Failed to register child process monitoring.");
		goto fail;
	}

	/* TEST: try sleeping here for a while here to check for races. */
	if (sid_resource_create_io_event_source(res, &observer->comms_es, observer->comms_fd, _on_observer_comms_event, NULL, res) < 0) {
		log_error(ID(res), "Failed to register worker <-> observer channel.");
		goto fail;
	}

	*data = observer;
	return 0;
fail:
	if (observer) {
		if (observer->child_es)
			(void) sid_resource_destroy_event_source(res, &observer->child_es);
		if (observer->comms_es)
			(void) sid_resource_destroy_event_source(res, &observer->comms_es);
		free(observer);
	}
	return -1;

}

static int _destroy_observer(sid_resource_t *res)
{
	struct observer *observer = sid_resource_get_data(res);

	if (observer->idle_timeout_es)
		(void) sid_resource_destroy_event_source(res, &observer->idle_timeout_es);
	(void) sid_resource_destroy_event_source(res, &observer->child_es);
	(void) sid_resource_destroy_event_source(res, &observer->comms_es);
	(void) close(observer->comms_fd);

	free(observer);
	return 0;
}

static int _init_worker(sid_resource_t *res, const void *kickstart_data, void **data)
{
	const struct kickstart *kickstart = kickstart_data;
	struct worker *worker = NULL;

	if (!(worker = zalloc(sizeof(*worker)))) {
		log_error(ID(res), "Failed to allocate new worker structure.");
		goto fail;
	}

	worker->conn_fd = -1;
	worker->comms_fd = kickstart->comms_fd;

	if (sid_resource_create_signal_event_source(res, &worker->sigterm_es, SIGTERM, _on_signal_event, NULL, res) < 0 ||
	    sid_resource_create_signal_event_source(res, &worker->sigint_es, SIGINT, _on_signal_event, NULL, res) < 0) {
		log_error(ID(res), "Failed to create signal handlers.");
		goto fail;
	}

	if (sid_resource_create_io_event_source(res, &worker->comms_es, worker->comms_fd, _on_worker_comms_event, NULL, res) < 0) {
		log_error(ID(res), "Failed to register worker <-> observer channel.");
		goto fail;
	}

	if (!(worker->buf = buffer_create(BUFFER_TYPE_LINEAR, BUFFER_MODE_SIZE_PREFIX, 0))) {
		log_error(ID(res), "Failed to create buffer for connection.");
		goto fail;
	}

	*data = worker;
	return 0;
fail:
	if (worker) {
		if (worker->sigterm_es)
			(void) sid_resource_destroy_event_source(res, &worker->sigterm_es);
		if (worker->sigint_es)
			(void) sid_resource_destroy_event_source(res, &worker->sigint_es);
		if (worker->conn_es)
			(void) sid_resource_destroy_event_source(res, &worker->conn_es);
		if (worker->comms_es)
			(void) sid_resource_destroy_event_source(res, &worker->comms_es);
		if (worker->conn_fd != -1)
			(void) close(worker->conn_fd);
		if (worker->buf)
			buffer_destroy(worker->buf);
		free(worker);
	}
	return -1;

}

static int _destroy_worker(sid_resource_t *res)
{
	struct worker *worker = sid_resource_get_data(res);

	if (worker->conn_es)
		(void) sid_resource_destroy_event_source(res, &worker->conn_es);
	(void) sid_resource_destroy_event_source(res, &worker->comms_es);
	(void) sid_resource_destroy_event_source(res, &worker->sigterm_es);
	(void) sid_resource_destroy_event_source(res, &worker->sigint_es);

	(void) close(worker->comms_fd);
	if (worker->conn_fd != -1)
		(void) close(worker->conn_fd);
	buffer_destroy(worker->buf);

	free(worker);
	return 0;
}

static sid_resource_t *_spawn_worker(sid_resource_t *ubridge_res, int *is_worker)
{
	struct ubridge *ubridge;
	struct kickstart kickstart = {0};
	sigset_t original_sigmask, new_sigmask;
	sid_resource_t *res = NULL;
	sid_resource_t *modules_res;
	sid_resource_t *main_kv_store_res;
	int signals_blocked = 0;
	int comms_fd[2];
	pid_t pid = -1;
	char id[16];

	/*
	 * Create socket pair for worker and observer
	 * to communicate with each other.
	 */
	if (socketpair(AF_LOCAL, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, comms_fd) < 0) {
		log_sys_error(ID(ubridge_res), "socketpair", "");
		goto out;
	}

	if (sigfillset(&new_sigmask) < 0) {
		log_sys_error(ID(ubridge_res), "sigfillset", "");
		goto out;
	}

	if (sigprocmask(SIG_SETMASK, &new_sigmask, &original_sigmask) < 0) {
		log_sys_error(ID(ubridge_res), "sigprocmask", "blocking signals before fork");
		goto out;
	}
	signals_blocked = 1;

	if ((pid = fork()) < 0) {
		log_sys_error(ID(ubridge_res), "fork", "");
		goto out;
	}

	ubridge = sid_resource_get_data(ubridge_res);

	if (pid == 0) {
		/* Child is a worker. */
		*is_worker = 1;
		kickstart.worker_pid = getpid();
		kickstart.comms_fd = comms_fd[1];
		(void) close(comms_fd[0]);

		modules_res = ubridge->modules_res;
		main_kv_store_res = ubridge->main_kv_store_res;

		(void) sid_resource_isolate_with_children(modules_res);
		(void) sid_resource_isolate_with_children(main_kv_store_res);

		if (sid_resource_destroy(sid_resource_get_top_level(ubridge_res)) < 0)
			log_error(ID(ubridge_res), "Failed to clean resource tree after forking a new worker.");

		(void) util_pid_to_string(kickstart.worker_pid, id, sizeof(id));
		if (!(res = sid_resource_create(NULL, &sid_resource_reg_ubridge_worker, 0, id, &kickstart))) {
			(void) sid_resource_destroy(modules_res);
			exit(EXIT_FAILURE);
		}

		(void) sid_resource_add_child(res, modules_res);
		(void) sid_resource_add_child(res, main_kv_store_res);
	} else {
		/* Parent is a child observer. */
		log_debug(ID(ubridge_res), "Spawned new worker process with PID %d.", pid);
		*is_worker = 0;
		kickstart.worker_pid = pid;
		kickstart.comms_fd = comms_fd[0];
		(void) close(comms_fd[1]);

		(void) util_pid_to_string(kickstart.worker_pid, id, sizeof(id));
		res = sid_resource_create(ubridge->observers_res, &sid_resource_reg_ubridge_observer, 0, id, &kickstart);
	}
out:
	if (signals_blocked && pid) {
		if (sigprocmask(SIG_SETMASK, &original_sigmask, NULL) < 0)
			log_sys_error(ID(ubridge_res), "sigprocmask", "after forking process");
	}

	return res;
}

static int _accept_connection_and_pass_to_worker(sid_resource_t *ubridge_res, sid_resource_t *observer_res)
{
	struct ubridge *ubridge;
	struct observer *observer;
	int conn_fd;

	if (!ubridge_res || !observer_res)
		return -1;

	ubridge = sid_resource_get_data(ubridge_res);
	observer = sid_resource_get_data(observer_res);

	if ((conn_fd = accept4(ubridge->socket_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC)) < 0) {
		log_sys_error(ID(ubridge_res), "accept", "");
		return -1;
	}

	if (comms_unix_send(observer->comms_fd, NULL, 0, conn_fd) < 0) {
		log_sys_error(ID(ubridge_res), "comms_unix_send", "");
		(void) close(conn_fd);
		return -1;
	}

	(void) close(conn_fd);
	(void) sid_resource_destroy_event_source(observer_res, &observer->idle_timeout_es);
	observer->worker_state = WORKER_INITIALIZING;
	log_debug(ID(observer_res), WORKER_STATE_CHANGED_TO_MSG "WORKER_INITIALIZING.");

	return 0;
}

static sid_resource_t *_find_observer_for_idle_worker(sid_resource_t *observers_res)
{
	sid_resource_iter_t *iter;
	sid_resource_t *res;

	if (!(iter = sid_resource_iter_create(observers_res)))
		return NULL;

	while ((res = sid_resource_iter_next(iter))) {
		if (((struct observer *) sid_resource_get_data(res))->worker_state == WORKER_IDLE)
			break;
	}

	sid_resource_iter_destroy(iter);
	return res;
}

static int _on_ubridge_interface_event(sid_event_source *es, int fd, uint32_t revents, void *data)
{
	sid_resource_t *ubridge_res = data;
	struct ubridge *ubridge = sid_resource_get_data(ubridge_res);
	sid_resource_t *res = NULL;
	int is_worker = 0;
	int r;

	log_debug(ID(ubridge_res), "Received an event.");

	if (!(res = _find_observer_for_idle_worker(ubridge->observers_res))) {
		log_debug(ID(ubridge_res), "Idle worker not found, spawning a new one.");
		if (!(res = _spawn_worker(ubridge_res, &is_worker)))
			return -1;
	}

	if (is_worker) {
		r = sid_resource_run_event_loop(res);
		(void) sid_resource_destroy(sid_resource_get_top_level(res));
		exit(-r);
	} else {
		r = _accept_connection_and_pass_to_worker(ubridge_res, res);
		return r;
	}
}

static int _reserve_core_kvs(struct ubridge *ubridge)
{
	struct sid_ubridge_cmd_mod_context cmd_mod = {.kv_store_res = ubridge->main_kv_store_res};

	if (_do_sid_ubridge_cmd_mod_reserve_kv(NULL, &cmd_mod, KV_NS_DEVICE, KV_KEY_DEV_READY, 0) < 0 ||
	    _do_sid_ubridge_cmd_mod_reserve_kv(NULL, &cmd_mod, KV_NS_DEVICE, KV_KEY_DEV_RESERVED, 0) < 0 ||
	    _do_sid_ubridge_cmd_mod_reserve_kv(NULL, &cmd_mod, KV_NS_DEVICE, KV_KEY_DEV_LAYER_UP, 0) < 0 ||
	    _do_sid_ubridge_cmd_mod_reserve_kv(NULL, &cmd_mod, KV_NS_DEVICE, KV_KEY_DEV_LAYER_DOWN, 0) < 0 ||
	    _do_sid_ubridge_cmd_mod_reserve_kv(NULL, &cmd_mod, KV_NS_DEVICE, KV_KEY_DEV_MOD, 0))
		return -1;

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

	if (!(ubridge->observers_res = sid_resource_create(ubridge->internal_res, &sid_resource_reg_aggregate, 0, OBSERVERS_AGGREGATE_ID, ubridge))) {
		log_error(ID(res), "Failed to create aggregate resource for ubridge observers.");
		goto fail;
	}

	if (!(ubridge->main_kv_store_res = sid_resource_create(ubridge->internal_res, &sid_resource_reg_kv_store, SID_RESOURCE_RESTRICT_WALK_UP,
							       MAIN_KV_STORE_NAME, &main_kv_store_res_params))) {
		log_error(ID(res), "Failed to create main key-value store.");
		goto fail;
	}

	if (_reserve_core_kvs(ubridge) < 0) {
		log_error(ID(res), "Failed to reserve core key-value pairs.");
		goto fail;
	}

	ubridge->cmd_mod.kv_store_res = ubridge->main_kv_store_res;
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
	sid_resource_dump_all_in_dot(sid_resource_get_top_level(res));

	*data = ubridge;
	return 0;
fail:
	if (ubridge) {
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

const sid_resource_reg_t sid_resource_reg_ubridge_observer = {
	.name = OBSERVER_NAME,
	.init = _init_observer,
	.destroy = _destroy_observer,
};

const sid_resource_reg_t sid_resource_reg_ubridge_worker = {
	.name = WORKER_NAME,
	.init = _init_worker,
	.destroy = _destroy_worker,
	.with_event_loop = 1,
};

const sid_resource_reg_t sid_resource_reg_ubridge = {
	.name = UBRIDGE_NAME,
	.init = _init_ubridge,
	.destroy = _destroy_ubridge,
};
