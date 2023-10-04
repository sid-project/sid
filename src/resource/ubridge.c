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

#include "internal/comp-attrs.h"

#include "internal/common.h"

#include "resource/ubridge.h"

#include "base/buffer.h"
#include "base/comms.h"
#include "base/util.h"
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

#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <libudev.h>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define INTERNAL_AGGREGATE_ID                       "ubr-int"
#define COMMON_ID                                   "common"
#define MODULES_AGGREGATE_ID                        "mods"
#define MODULES_BLOCK_ID                            "block"
#define MODULES_TYPE_ID                             "type"

#define UDEV_TAG_SID                                "sid"
#define KV_KEY_UDEV_SID_SESSION_ID                  "SID_SESSION_ID"
#define KV_KEY_UDEV_SID_DEV_ID                      "SID_DEV_ID"

// TODO: once trigger-action is settled down, move this to ucmd-module.h
#define SID_UCMD_MOD_FN_NAME_TRIGGER_ACTION_CURRENT "sid_ucmd_trigger_action_current"
#define SID_UCMD_MOD_FN_NAME_TRIGGER_ACTION_NEXT    "sid_ucmd_trigger_action_next"

#define MAIN_KV_STORE_NAME                          "main"
#define MAIN_WORKER_CHANNEL_ID                      "main"

#define SYSTEM_PROC_DEVICES_PATH                    SYSTEM_PROC_PATH "/devices"
#define MAIN_KV_STORE_FILE_PATH                     "/run/sid.db"

#define KV_PAIR_C                                   "="
#define KV_END_C                                    ""

#define ID_NULL                                     ""
#define KV_KEY_NULL                                 ID_NULL

#define KV_INDEX_NOOP                               0
#define KV_INDEX_ADD                                1
#define KV_INDEX_REMOVE                             2

#define KV_PREFIX_OP_SYNC_C                         ">"
#define KV_PREFIX_OP_SYNC_END_C                     "?" /* right after '>' */
#define KV_PREFIX_OP_ARCHIVE_C                      "~"
#define KV_PREFIX_OP_BLANK_C                        " "
#define KV_PREFIX_OP_ILLEGAL_C                      "X"
#define KV_PREFIX_OP_SET_C                          ""
#define KV_PREFIX_OP_PLUS_C                         "+"
#define KV_PREFIX_OP_MINUS_C                        "-"

#define KV_PREFIX_NS_UNDEFINED_C                    ""
#define KV_PREFIX_NS_UDEV_C                         "U"
#define KV_PREFIX_NS_DEVICE_C                       "D"
#define KV_PREFIX_NS_MODULE_C                       "M"
#define KV_PREFIX_NS_DEVMOD_C                       "X"
#define KV_PREFIX_NS_GLOBAL_C                       "G"

#define KV_PREFIX_KEY_SYS_C                         "#"

#define KV_KEY_DB_GENERATION                        KV_PREFIX_KEY_SYS_C "DBGEN"
#define KV_KEY_BOOT_ID                              KV_PREFIX_KEY_SYS_C "BOOTID"
#define KV_KEY_DEV_READY                            KV_PREFIX_KEY_SYS_C "RDY"
#define KV_KEY_DEV_RESERVED                         KV_PREFIX_KEY_SYS_C "RES"
#define KV_KEY_DEV_MOD                              KV_PREFIX_KEY_SYS_C "MOD"

#define KV_KEY_DOM_ALIAS                            "ALS"
#define KV_KEY_DOM_GROUP                            "GRP"
#define KV_KEY_DOM_USER                             "USR"

#define KV_KEY_GEN_GROUP_MEMBERS                    KV_PREFIX_KEY_SYS_C "GMB"
#define KV_KEY_GEN_GROUP_IN                         KV_PREFIX_KEY_SYS_C "GIN"

#define MOD_NAME_CORE                               MODULE_NAME_DELIM
#define MOD_NAME_BLKEXT                             "blkext"
#define MOD_NAME_NVME                               "nvme"

#define DEV_NAME_PREFIX_NVME                        "nvme"

#define OWNER_CORE                                  MOD_NAME_CORE
#define DEFAULT_VALUE_FLAGS_CORE                    KV_SYNC_P | KV_RS

#define CMD_DEV_NAME_NUM_FMT                        "%s (%d:%d)"
#define CMD_DEV_NAME_NUM(ucmd_ctx)                                                                                                 \
	ucmd_ctx->req_env.dev.udev.name, ucmd_ctx->req_env.dev.udev.major, ucmd_ctx->req_env.dev.udev.minor

const sid_resource_type_t sid_resource_type_ubridge;
const sid_resource_type_t sid_resource_type_ubridge_common;
const sid_resource_type_t sid_resource_type_ubridge_connection;
const sid_resource_type_t sid_resource_type_ubridge_command;

struct sid_ucmd_common_ctx {
	sid_resource_t    *res;          /* resource representing this common ctx */
	sid_resource_t    *modules_res;  /* top-level resource for all ucmd module registries */
	sid_resource_t    *kv_store_res; /* main KV store or KV store snapshot */
	uint16_t           gennum;       /* current KV store generation number */
	struct sid_buffer *gen_buf;      /* generic buffer */
};

struct umonitor {
	struct udev         *udev;
	struct udev_monitor *mon;
};

struct ubridge {
	sid_resource_t *internal_res;
	int             socket_fd;
	struct umonitor umonitor;
};

typedef enum {
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
	const char    *path;
	const char    *name; /* just a pointer to devpath's last element */
	int            major;
	int            minor;
	uint64_t       seqnum;
	uint64_t       diskseq;
	const char    *synth_uuid;
};

struct connection {
	int                fd;
	struct sid_buffer *buf;
};

typedef enum {
	MSG_CATEGORY_SYSTEM, /* system message */
	MSG_CATEGORY_SELF,   /* self-induced message */
	MSG_CATEGORY_CLIENT, /* message coming from a client */
} msg_category_t;

typedef enum {
	CMD_INITIALIZING,         /* initializing context for cmd */
	CMD_EXEC_SCHEDULED,       /* cmd handler execution scheduled */
	CMD_EXECUTING,            /* executing cmd handler */
	CMD_EXPECTING_DATA,       /* expecting more data for further cmd processing */
	CMD_EXEC_FINISHED,        /* cmd finished and ready for building and sending out results */
	CMD_EXPECTING_EXPBUF_ACK, /* expecting ack of export buffer reception */
	CMD_EXPBUF_ACKED,         /* export buffer ack received (cmd handler also scheduled) */
	CMD_OK,                   /* cmd completely executed and results successfully sent (and ackowledged) */
	CMD_ERROR,                /* cmd error */
} cmd_state_t;

static const char *cmd_state_str[]        = {[CMD_INITIALIZING]         = "CMD_INITIALIZING",
                                             [CMD_EXEC_SCHEDULED]       = "CMD_EXEC_SCHEDULED",
                                             [CMD_EXECUTING]            = "CMD_EXECUTING",
                                             [CMD_EXPECTING_DATA]       = "CMD_EXPECTING_DATA",
                                             [CMD_EXEC_FINISHED]        = "CMD_EXEC_FINISHED",
                                             [CMD_EXPECTING_EXPBUF_ACK] = "CMD_EXPECTING_EXPBUF_ACK",
                                             [CMD_EXPBUF_ACKED]         = "CMD_EXPBUF_ACKED",
                                             [CMD_OK]                   = "CMD_OK",
                                             [CMD_ERROR]                = "CMD_ERROR"};

static const char * const dev_ready_str[] = {
	[DEV_RDY_UNDEFINED]     = "undefined",
	[DEV_RDY_UNPROCESSED]   = "unprocessed",
	[DEV_RDY_UNCONFIGURED]  = "unconfigured",
	[DEV_RDY_UNINITIALIZED] = "uninitialized",
	[DEV_RDY_UNAVAILABLE]   = "unavailable",
	[DEV_RDY_PRIVATE]       = "private",
	[DEV_RDY_PUBLIC]        = "public",
};

struct sid_ucmd_ctx {
	/* request */
	msg_category_t        req_cat; /* request category */
	struct sid_msg_header req_hdr; /* request header */

	/* request environment */
	union {
		struct {
			char          *uid_s; /* device identifier string */
			char          *num_s; /* device number string (in "major_minor" format) */
			struct udevice udev;
		} dev;

		const char *exp_path; /* export path */
	} req_env;

	/* common context */
	struct sid_ucmd_common_ctx *common;

	/* cmd specific context */
	union {
		struct {
			cmd_scan_phase_t phase; /* current scan phase */
			dev_ready_t      dev_ready;
		} scan;

		struct {
			void  *main_res_mem;      /* mmap-ed memory with result from main process */
			size_t main_res_mem_size; /* overall size of main_res_mem */
		} resources;
	};

	cmd_state_t                  state;          /* current command state */
	sid_resource_event_source_t *cmd_handler_es; /* event source for deferred execution of _cmd_handler */

	/* response */
	struct sid_msg_header res_hdr; /* response header */
	struct sid_buffer    *prn_buf; /* print buffer */
	struct sid_buffer    *res_buf; /* response buffer */
	struct sid_buffer    *exp_buf; /* export buffer */
};

struct cmd_exec_arg {
	sid_resource_t      *cmd_res;
	sid_resource_t      *type_mod_registry_res;
	sid_resource_iter_t *block_mod_iter;       /* all block modules to execute */
	sid_resource_t      *type_mod_res_current; /* one type module for current layer to execute */
	sid_resource_t      *type_mod_res_next;    /* one type module for next layer to execute */
};

struct cmd_reg {
	const char *name;
	uint32_t    flags;
	int (*exec)(struct cmd_exec_arg *exec_arg);
};

typedef struct {
	uint64_t            seqnum;
	sid_ucmd_kv_flags_t flags;
	uint16_t            gennum;
	char                data[]; /* contains both internal (owner + padding) and external data (user value) */
} kv_scalar_t;

enum {
	VVALUE_IDX_SEQNUM,
	VVALUE_IDX_FLAGS,
	VVALUE_IDX_GENNUM,
	VVALUE_IDX_OWNER,
	VVALUE_IDX_PADDING,
	VVALUE_IDX_DATA = VVALUE_IDX_PADDING,
	VVALUE_IDX_DATA_ALIGNED,
};

#define SVALUE_DATA_ALIGNMENT sizeof(void *)

static char padding[SVALUE_DATA_ALIGNMENT] = {0}; /* used for referencing in vvalue[VVALUE_IDX_PADDING] */

#define SVALUE_HEADER_SIZE        (offsetof(kv_scalar_t, data))

#define VVALUE_HEADER_CNT         VVALUE_IDX_DATA
#define VVALUE_SINGLE_CNT         VVALUE_IDX_DATA + 1

#define VVALUE_HEADER_ALIGNED_CNT VVALUE_IDX_DATA_ALIGNED
#define VVALUE_SINGLE_ALIGNED_CNT VVALUE_IDX_DATA_ALIGNED + 1

typedef struct iovec kv_vector_t;

#define VVALUE_CNT(vvalue)    (sizeof(vvalue) / sizeof(kv_vector_t))

#define VVALUE_SEQNUM(vvalue) (*((uint64_t *) ((kv_vector_t *) vvalue)[VVALUE_IDX_SEQNUM].iov_base))
#define VVALUE_FLAGS(vvalue)  (*((sid_ucmd_kv_flags_t *) ((kv_vector_t *) vvalue)[VVALUE_IDX_FLAGS].iov_base))
#define VVALUE_GENNUM(vvalue) (*((uint16_t *) ((kv_vector_t *) vvalue)[VVALUE_IDX_GENNUM].iov_base))
#define VVALUE_OWNER(vvalue)  ((char *) ((kv_vector_t *) vvalue)[VVALUE_IDX_OWNER].iov_base)
#define VVALUE_DATA(vvalue)   (((kv_vector_t *) vvalue)[VVALUE_IDX_DATA].iov_base)

struct kv_update_arg {
	sid_resource_t    *res;
	struct sid_buffer *gen_buf;
	const char        *owner;    /* in */
	void              *custom;   /* in/out */
	int                ret_code; /* out */
};

typedef enum {
	MOD_NO_MATCH,  /* modules do not match */
	MOD_MATCH,     /* modules do match (1:1) */
	MOD_SUB_MATCH, /* modules do match (submod of a mod) */
	MOD_SUP_MATCH, /* modules do match (supmod of a mod) */
} mod_match_t;

typedef enum {
	KV_OP_ILLEGAL, /* illegal operation */
	KV_OP_SET,     /* set value for kv */
	KV_OP_PLUS,    /* add value to vector kv */
	KV_OP_MINUS,   /* remove value fomr vector kv */
} kv_op_t;

typedef enum {
	DELTA_NO_FLAGS  = 0x0,
	DELTA_WITH_DIFF = 0x1, /* calculate difference between old and new value, update records */
	DELTA_WITH_REL  = 0x2, /* as DELTA_WITH_DIFF, but also update referenced relatives */
} delta_flags_t;

struct kv_delta {
	kv_op_t            op;
	delta_flags_t      flags;
	struct sid_buffer *plus;
	struct sid_buffer *minus;
	struct sid_buffer *final;
};

typedef enum {
	__KEY_PART_START = 0x0,
	KEY_PART_OP      = 0x0,
	KEY_PART_DOM     = 0x1,
	KEY_PART_NS      = 0x2,
	KEY_PART_NS_PART = 0x3,
	KEY_PART_ID_CAT  = 0x4,
	KEY_PART_ID      = 0x5,
	KEY_PART_CORE    = 0x6,
	__KEY_PART_COUNT,
} key_part_t;

struct kv_key_spec {
	const char             *extra_op;
	kv_op_t                 op;
	const char             *dom;
	sid_ucmd_kv_namespace_t ns;
	const char             *ns_part;
	const char             *id_cat;
	const char             *id;
	const char             *core;
};

struct kv_rel_spec {
	struct kv_delta    *delta;
	struct kv_delta    *abs_delta;
	struct kv_key_spec *cur_key_spec;
	struct kv_key_spec *rel_key_spec;
};

struct cross_bitmap_calc_arg {
	kv_vector_t   *old_vvalue;
	size_t         old_vsize;
	struct bitmap *old_bmp;
	kv_vector_t   *new_vvalue;
	size_t         new_vsize;
	struct bitmap *new_bmp;
};

struct sid_dbstats {
	uint64_t key_size;
	uint64_t value_int_size;
	uint64_t value_int_data_size;
	uint64_t value_ext_size;
	uint64_t value_ext_data_size;
	uint64_t meta_size;
	uint32_t nr_kv_pairs;
};

typedef enum {
	_SELF_CMD_START    = 0,
	SELF_CMD_UNDEFINED = _SELF_CMD_START,
	SELF_CMD_UNKNOWN,
	SELF_CMD_DBDUMP,
	_SELF_CMD_END = SELF_CMD_DBDUMP,
} self_cmd_t;

typedef enum {
	_SYSTEM_CMD_START    = 0,
	SYSTEM_CMD_UNDEFINED = _SYSTEM_CMD_START,
	SYSTEM_CMD_UNKNOWN,
	SYSTEM_CMD_SYNC,
	SYSTEM_CMD_RESOURCES,
	_SYSTEM_CMD_END = SYSTEM_CMD_RESOURCES,
} system_cmd_t;

struct sid_msg {
	msg_category_t         cat;  /* keep this first so we can decide how to read the rest */
	size_t                 size; /* header + data */
	struct sid_msg_header *header;
};

struct internal_msg_header {
	msg_category_t        cat;    /* keep this first so we can decide how to read the rest */
	struct sid_msg_header header; /* reusing sid_msg_header here to avoid defining a new struct with subset of fields we need */
} __packed;

#define INTERNAL_MSG_HEADER_SIZE      sizeof(struct internal_msg_header)
#define INTERNAL_MSG_MAX_FD_DATA_SIZE 0x4000000 /* FIXME: make this configurable or use heuristics based on current state */

/*
 * Generic flags for all commands.
 */
#define CMD_KV_IMPORT_UDEV            UINT32_C(0x00000001) /* import udev environment as KV_NS_UDEV records */
#define CMD_KV_EXPORT_UDEV_TO_RESBUF  UINT32_C(0x00000002) /* export KV_NS_UDEV records to response buffer  */
#define CMD_KV_EXPORT_UDEV_TO_EXPBUF  UINT32_C(0x00000004) /* export KV_NS_UDEV records to export buffer */
#define CMD_KV_EXPORT_SID_TO_RESBUF   UINT32_C(0x00000008) /* export KV_NS_<!UDEV> records to response buffer */
#define CMD_KV_EXPORT_SID_TO_EXPBUF   UINT32_C(0x00000010) /* export KV_NS_<!UDEV> records to export buffer */
#define CMD_KV_EXPORT_SYNC            UINT32_C(0x00000020) /* export only KV records marked with sync flag */
#define CMD_KV_EXPORT_PERSISTENT      UINT32_C(0x00000040) /* export only KV records marked with persistent flag */
#define CMD_KV_EXPBUF_TO_FILE         UINT32_C(0x00000080) /* export KV records from export buffer to a file */
#define CMD_KV_EXPBUF_TO_MAIN         UINT32_C(0x00000100) /* export KV records from export buffer to main process */
#define CMD_KV_EXPECT_EXPBUF_ACK      UINT32_C(0x00000200) /* expect acknowledgment of expbuf reception */
#define CMD_SESSION_ID                UINT32_C(0x00000400) /* generate session ID */

/*
 * Capability flags for 'scan' command phases (phases are represented as subcommands).
 */
#define CMD_SCAN_CAP_RDY              UINT32_C(0x00000001) /* can set ready state */
#define CMD_SCAN_CAP_RES              UINT32_C(0x00000002) /* can set reserved state */
#define CMD_SCAN_CAP_ALL              UINT32_C(0xFFFFFFFF) /* can set anything */

static bool _cmd_root_only[] = {
	[SID_CMD_UNDEFINED]  = false,
	[SID_CMD_UNKNOWN]    = false,
	[SID_CMD_ACTIVE]     = false,
	[SID_CMD_CHECKPOINT] = true,
	[SID_CMD_REPLY]      = false,
	[SID_CMD_SCAN]       = true,
	[SID_CMD_VERSION]    = false,
	[SID_CMD_DBDUMP]     = true,
	[SID_CMD_DBSTATS]    = true,
	[SID_CMD_RESOURCES]  = true,
	[SID_CMD_DEVICES]    = true,
};

static struct cmd_reg      _cmd_scan_phase_regs[];
static sid_ucmd_kv_flags_t value_flags_no_sync = (DEFAULT_VALUE_FLAGS_CORE) & ~KV_SYNC;
static sid_ucmd_kv_flags_t value_flags_sync    = DEFAULT_VALUE_FLAGS_CORE;
static char               *core_owner          = OWNER_CORE;
static uint64_t            null_int            = 0;

static int        _do_kv_delta_set(char *key, kv_vector_t *vvalue, size_t vsize, struct kv_update_arg *update_arg, bool index);
static const char _key_prefix_err_msg[] =
	"Failed to get key prefix to store hierarchy records for device " CMD_DEV_NAME_NUM_FMT ".";

udev_action_t sid_ucmd_event_get_dev_action(struct sid_ucmd_ctx *ucmd_ctx)
{
	return ucmd_ctx->req_env.dev.udev.action;
}

int sid_ucmd_event_get_dev_major(struct sid_ucmd_ctx *ucmd_ctx)
{
	return ucmd_ctx->req_env.dev.udev.major;
}

int sid_ucmd_event_get_dev_minor(struct sid_ucmd_ctx *ucmd_ctx)
{
	return ucmd_ctx->req_env.dev.udev.minor;
}

const char *sid_ucmd_event_get_dev_path(struct sid_ucmd_ctx *ucmd_ctx)
{
	return ucmd_ctx->req_env.dev.udev.path;
}

const char *sid_ucmd_event_get_dev_name(struct sid_ucmd_ctx *ucmd_ctx)
{
	return ucmd_ctx->req_env.dev.udev.name;
}

udev_devtype_t sid_ucmd_event_get_dev_type(struct sid_ucmd_ctx *ucmd_ctx)
{
	return ucmd_ctx->req_env.dev.udev.type;
}

uint64_t sid_ucmd_event_get_dev_seqnum(struct sid_ucmd_ctx *ucmd_ctx)
{
	return ucmd_ctx->req_env.dev.udev.seqnum;
}

uint64_t sid_ucmd_event_get_dev_diskseq(struct sid_ucmd_ctx *ucmd_ctx)
{
	return ucmd_ctx->req_env.dev.udev.diskseq;
}

const char *sid_ucmd_event_get_dev_synth_uuid(struct sid_ucmd_ctx *ucmd_ctx)
{
	return ucmd_ctx->req_env.dev.udev.synth_uuid;
}

static char *_do_compose_key(struct sid_buffer *buf, struct kv_key_spec *key_spec, int prefix_only)
{
	static const char fmt[] = "%s"                   /* space for extra op */
				  "%s" KV_STORE_KEY_JOIN /* op */
				  "%s" KV_STORE_KEY_JOIN /* dom */
				  "%s" KV_STORE_KEY_JOIN /* ns */
				  "%s" KV_STORE_KEY_JOIN /* ns_part */
				  "%s" KV_STORE_KEY_JOIN /* id_cat */
				  "%s"
				  "%s" /* id */
				  "%s";
	char *key;

	static const char *op_to_key_prefix_map[] = {[KV_OP_ILLEGAL] = KV_PREFIX_OP_ILLEGAL_C,
	                                             [KV_OP_SET]     = KV_PREFIX_OP_SET_C,
	                                             [KV_OP_PLUS]    = KV_PREFIX_OP_PLUS_C,
	                                             [KV_OP_MINUS]   = KV_PREFIX_OP_MINUS_C};

	static const char *ns_to_key_prefix_map[] = {[KV_NS_UNDEFINED] = KV_PREFIX_NS_UNDEFINED_C,
	                                             [KV_NS_UDEV]      = KV_PREFIX_NS_UDEV_C,
	                                             [KV_NS_DEVICE]    = KV_PREFIX_NS_DEVICE_C,
	                                             [KV_NS_MODULE]    = KV_PREFIX_NS_MODULE_C,
	                                             [KV_NS_DEVMOD]    = KV_PREFIX_NS_DEVMOD_C,
	                                             [KV_NS_GLOBAL]    = KV_PREFIX_NS_GLOBAL_C};

	/* <op>:<dom>:<ns>:<ns_part>:<id_cat>:<id>[:<core>] */

	if (buf) {
		if (sid_buffer_fmt_add(buf,
		                       (const void **) &key,
		                       NULL,
		                       fmt,
		                       prefix_only ? KV_KEY_NULL : key_spec->extra_op ?: KV_PREFIX_OP_BLANK_C,
		                       op_to_key_prefix_map[key_spec->op],
		                       key_spec->dom,
		                       ns_to_key_prefix_map[key_spec->ns],
		                       key_spec->ns_part,
		                       key_spec->id_cat,
		                       key_spec->id,
		                       prefix_only ? KV_KEY_NULL : KV_STORE_KEY_JOIN,
		                       prefix_only ? KV_KEY_NULL : key_spec->core) < 0)
			key = NULL;
	} else {
		if (asprintf((char **) &key,
		             fmt,
		             prefix_only ? KV_KEY_NULL : key_spec->extra_op ?: KV_PREFIX_OP_BLANK_C,
		             op_to_key_prefix_map[key_spec->op],
		             key_spec->dom,
		             ns_to_key_prefix_map[key_spec->ns],
		             key_spec->ns_part,
		             key_spec->id_cat,
		             key_spec->id,
		             prefix_only ? KV_KEY_NULL : KV_STORE_KEY_JOIN,
		             prefix_only ? KV_KEY_NULL : key_spec->core) < 0)
			key = NULL;
	}

	return key;
}

static char *_compose_key(struct sid_buffer *buf, struct kv_key_spec *key_spec)
{
	/* <extra_op><op>:<dom>:<ns>:<ns_part>:<id_cat>:<id>:<core> */
	return _do_compose_key(buf, key_spec, 0);
}

static char *_compose_key_prefix(struct sid_buffer *buf, struct kv_key_spec *key_spec)
{
	/* <op>:<dom>:<ns>:<ns_part><id_cat>:<id> */
	return _do_compose_key(buf, key_spec, 1);
}

static void _destroy_key(struct sid_buffer *buf, const char *key)
{
	if (!key)
		return;

	if (buf)
		sid_buffer_rewind_mem(buf, key);
	else
		free((void *) key);
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
	 * <op>:<dom>:<ns>:<ns_part>:<id_cat>:<id>[:<core>]
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
	 * <op>:<dom>:<ns>:<ns_part>:<id_cat>:<id>[:<core>]
	 */

	if (!(str = _get_key_part(key, KEY_PART_NS, &len)) || len > 1)
		return KV_NS_UNDEFINED;

	if (str[0] == KV_PREFIX_NS_UDEV_C[0])
		return KV_NS_UDEV;
	else if (str[0] == KV_PREFIX_NS_DEVICE_C[0])
		return KV_NS_DEVICE;
	else if (str[0] == KV_PREFIX_NS_MODULE_C[0])
		return KV_NS_MODULE;
	else if (str[0] == KV_PREFIX_NS_DEVMOD_C[0])
		return KV_NS_DEVMOD;
	else if (str[0] == KV_PREFIX_NS_GLOBAL_C[0])
		return KV_NS_GLOBAL;
	else
		return KV_NS_UNDEFINED;
}

static const char *_copy_ns_part_from_key(const char *key, char *buf, size_t buf_size)
{
	const char *str, *ns;
	size_t      len;

	/*                 |<----->|
	   <op>:<dom>:<ns>:<ns_part><id_cat>:<id>[:<core>]
	*/

	if (!(str = _get_key_part(key, KEY_PART_NS_PART, &len)))
		return NULL;

	// FIXME: check '(int) len' cast is safe

	if (buf) {
		if (snprintf(buf, buf_size, "%.*s", (int) len, str) < 0)
			ns = NULL;
		else
			ns = buf;
	} else {
		if (asprintf((char **) &ns, "%.*s", (int) len, str) < 0)
			ns = NULL;
	}

	return ns;
}

static void _vvalue_header_prep(kv_vector_t         *vvalue,
                                size_t               vvalue_size,
                                uint64_t            *seqnum,
                                sid_ucmd_kv_flags_t *flags,
                                uint16_t            *gennum,
                                char                *owner)
{
	size_t owner_size = strlen(owner) + 1;

	if (*flags & KV_ALIGN) {
		assert(vvalue_size >= VVALUE_HEADER_ALIGNED_CNT);
		vvalue[VVALUE_IDX_PADDING] =
			(kv_vector_t) {padding, MEM_ALIGN_UP_PAD(SVALUE_HEADER_SIZE + owner_size, SVALUE_DATA_ALIGNMENT)};
	} else
		assert(vvalue_size >= VVALUE_HEADER_CNT);

	vvalue[VVALUE_IDX_SEQNUM] = (kv_vector_t) {seqnum, sizeof(*seqnum)};
	vvalue[VVALUE_IDX_FLAGS]  = (kv_vector_t) {flags, sizeof(*flags)};
	vvalue[VVALUE_IDX_GENNUM] = (kv_vector_t) {gennum, sizeof(*gennum)};
	vvalue[VVALUE_IDX_OWNER]  = (kv_vector_t) {owner, owner_size};
}

static void _vvalue_data_prep(kv_vector_t *vvalue, size_t vvalue_size, size_t idx, void *data, size_t data_size)
{
	if (VVALUE_FLAGS(vvalue) & KV_ALIGN) {
		assert(vvalue_size >= VVALUE_IDX_DATA_ALIGNED + idx);
		vvalue[VVALUE_IDX_DATA_ALIGNED + idx] = (kv_vector_t) {data, data_size};
	} else {
		assert(vvalue_size >= VVALUE_IDX_DATA + idx);
		vvalue[VVALUE_IDX_DATA + idx] = (kv_vector_t) {data, data_size};
	}
}

static kv_vector_t *_get_vvalue(kv_store_value_flags_t kv_store_value_flags,
                                void                  *value,
                                size_t                 value_size,
                                kv_vector_t           *vvalue,
                                size_t                 vvalue_size)
{
	kv_scalar_t *svalue;
	size_t       owner_size;
	size_t       padding_size;

	if (!value)
		return NULL;

	if (kv_store_value_flags & KV_STORE_VALUE_VECTOR)
		return value;

	svalue     = value;
	owner_size = strlen(svalue->data) + 1;

	if (svalue->flags & KV_ALIGN) {
		assert(vvalue_size >= VVALUE_SINGLE_ALIGNED_CNT);
		padding_size                    = MEM_ALIGN_UP_PAD(SVALUE_HEADER_SIZE + owner_size, SVALUE_DATA_ALIGNMENT);
		vvalue[VVALUE_IDX_PADDING]      = (kv_vector_t) {svalue->data + owner_size, padding_size};
		vvalue[VVALUE_IDX_DATA_ALIGNED] = (kv_vector_t) {svalue->data + owner_size + padding_size,
		                                                 value_size - SVALUE_HEADER_SIZE - owner_size - padding_size};
	} else {
		assert(vvalue_size >= VVALUE_SINGLE_CNT);
		vvalue[VVALUE_IDX_DATA] = (kv_vector_t) {svalue->data + owner_size, value_size - SVALUE_HEADER_SIZE - owner_size};
	}

	vvalue[VVALUE_IDX_SEQNUM] = (kv_vector_t) {&svalue->seqnum, sizeof(svalue->seqnum)};
	vvalue[VVALUE_IDX_FLAGS]  = (kv_vector_t) {&svalue->flags, sizeof(svalue->flags)};
	vvalue[VVALUE_IDX_GENNUM] = (kv_vector_t) {&svalue->gennum, sizeof(svalue->gennum)};
	vvalue[VVALUE_IDX_OWNER]  = (kv_vector_t) {svalue->data, owner_size};

	return vvalue;
}

static const char *_buffer_get_vvalue_str(struct sid_buffer *buf, bool unset, kv_vector_t *vvalue, size_t vvalue_size)
{
	size_t      buf_offset, start_idx, i;
	const char *str;

	if (unset) {
		if (sid_buffer_fmt_add(buf, (const void **) &str, NULL, "NULL") < 0)
			return NULL;
		return str;
	}

	buf_offset = sid_buffer_count(buf);
	start_idx  = VVALUE_FLAGS(vvalue) & KV_ALIGN ? VVALUE_IDX_DATA_ALIGNED : VVALUE_IDX_DATA;

	for (i = start_idx; i < vvalue_size; i++) {
		if ((sid_buffer_add(buf, vvalue[i].iov_base, vvalue[i].iov_len - 1, NULL, NULL) < 0) ||
		    (sid_buffer_add(buf, " ", 1, NULL, NULL) < 0))
			goto fail;
	}

	if (sid_buffer_add(buf, "\0", 1, NULL, NULL) < 0)
		goto fail;
	sid_buffer_get_data_from(buf, buf_offset, (const void **) &str, NULL);

	return str;
fail:
	sid_buffer_rewind(buf, buf_offset, SID_BUFFER_POS_ABS);
	return NULL;
}

static int _write_kv_store_stats(struct sid_dbstats *stats, sid_resource_t *kv_store_res)
{
	kv_store_iter_t *iter;
	const char      *key;
	size_t           size;
	size_t           meta_size, int_size, int_data_size, ext_size, ext_data_size;

	memset(stats, 0, sizeof(*stats));
	if (!(iter = kv_store_iter_create(kv_store_res, NULL, NULL))) {
		log_error(ID(kv_store_res), INTERNAL_ERROR "%s: failed to create record iterator", __func__);
		return -ENOMEM;
	}
	while (kv_store_iter_next(iter, &size, &key, NULL)) {
		stats->nr_kv_pairs++;
		kv_store_iter_current_size(iter, &int_size, &int_data_size, &ext_size, &ext_data_size);
		stats->key_size            += strlen(key) + 1;
		stats->value_int_size      += int_size;
		stats->value_int_data_size += int_data_size;
		stats->value_ext_size      += ext_size;
		stats->value_ext_data_size += ext_data_size;
	}
	kv_store_get_size(kv_store_res, &meta_size, &int_size);
	if (stats->value_int_size != int_size)
		log_error(ID(kv_store_res),
		          INTERNAL_ERROR "%s: kv-store size mismatch: %" PRIu64 " is not equal to %zu",
		          __func__,
		          stats->value_int_size,
		          int_size);
	stats->meta_size = meta_size;
	kv_store_iter_destroy(iter);
	return 0;
}

static int _check_kv_index_needed(kv_vector_t *vvalue_old, kv_vector_t *vvalue_new)
{
	int old_indexed, new_indexed;

	old_indexed = vvalue_old ? VVALUE_FLAGS(vvalue_old) & KV_SYNC : 0;
	new_indexed = vvalue_new ? VVALUE_FLAGS(vvalue_new) & KV_SYNC : 0;

	if (old_indexed && !new_indexed)
		return KV_INDEX_REMOVE;

	if (!old_indexed && new_indexed)
		return KV_INDEX_ADD;

	return KV_INDEX_NOOP;
}

static int _manage_kv_index(struct kv_update_arg *update_arg, char *key)
{
	int r;

	key[0] = KV_PREFIX_OP_SYNC_C[0];
	switch (update_arg->ret_code) {
		case KV_INDEX_ADD:
			r = kv_store_add_alias(update_arg->res, key + 1, key, false);
			break;
		case KV_INDEX_REMOVE:
			r = kv_store_unset(update_arg->res, key, NULL, NULL);
			break;
		default:
			r = 0;
	}
	key[0] = ' ';

	return r;
}

static mod_match_t _mod_match(const char *mod1, const char *mod2)
{
	size_t i = 0;

	while ((mod1[i] && mod2[i]) && (mod1[i] == mod2[i]))
		i++;

	if (!mod1[i] && !mod2[i])
		/* match - same mod */
		return MOD_MATCH;

	if (i && mod2[i]) {
		if (i == MODULE_NAME_DELIM_LEN || !strncmp(mod2 + i, MODULE_NAME_DELIM, MODULE_NAME_DELIM_LEN))
			/* match - mod2 is submnod of mod1 */
			return MOD_SUB_MATCH;
		else
			/* no match */
			return MOD_NO_MATCH;
	} else if (i && mod1[i]) {
		if (i == MODULE_NAME_DELIM_LEN || !strncmp(mod1 + i, MODULE_NAME_DELIM, MODULE_NAME_DELIM_LEN))
			/* match - mod2 is supermod of mod1 */
			return MOD_SUP_MATCH;
	}

	/* no match */
	return MOD_NO_MATCH;
}

static int _check_kv_wr_allowed(struct kv_update_arg *update_arg, const char *key, kv_vector_t *vvalue_old, kv_vector_t *vvalue_new)
{
	static const char   reason_reserved[] = "reserved";
	static const char   reason_readonly[] = "read-only";
	static const char   reason_private[]  = "private";
	sid_ucmd_kv_flags_t old_flags;
	const char         *old_owner;
	const char         *new_owner;
	const char         *reason;
	int                 r = 0;

	if (!vvalue_old)
		return 0;

	old_flags = VVALUE_FLAGS(vvalue_old);
	old_owner = VVALUE_OWNER(vvalue_old);
	new_owner = vvalue_new ? VVALUE_OWNER(vvalue_new) : update_arg->owner;

	switch (_mod_match(old_owner, new_owner)) {
		case MOD_NO_MATCH:
			if (old_flags & KV_FRG_WR)
				r = 1;
			else {
				if (old_flags & KV_RS) {
					reason = reason_reserved;
					r      = -EBUSY;
				} else if (old_flags & KV_FRG_RD) {
					reason = reason_readonly;
					r      = -EPERM;
				} else {
					reason = reason_private;
					r      = -EACCES;
				}
			}
			break;
		case MOD_MATCH:
			r = 1;
			break;
		case MOD_SUB_MATCH:
			if (old_flags & KV_SUB_WR)
				r = 1;
			else {
				if (old_flags & KV_RS) {
					reason = reason_reserved;
					r      = -EBUSY;
				} else if (old_flags & KV_SUB_RD) {
					reason = reason_readonly;
					r      = -EPERM;
				} else {
					reason = reason_private;
					r      = -EACCES;
				}
			}
			break;
		case MOD_SUP_MATCH:
			if (old_flags & KV_SUP_WR)
				r = 1;
			else {
				if (old_flags & KV_RS) {
					reason = reason_reserved;
					r      = -EBUSY;
				} else if (old_flags & KV_SUP_RD) {
					reason = reason_readonly;
					r      = -EPERM;
				} else {
					reason = reason_private;
					r      = -EACCES;
				}
			}
			break;
	}

	if (r < 0)
		log_debug(ID(update_arg->res),
		          "Module %s can't write value with key %s which is %s and already attached to module %s.",
		          new_owner,
		          key,
		          reason,
		          old_owner);

	return r;
}

static int _kv_cb_write(struct kv_store_update_spec *spec)
{
	struct kv_update_arg *update_arg = spec->arg;
	kv_vector_t           tmp_vvalue_old[VVALUE_SINGLE_ALIGNED_CNT];
	kv_vector_t           tmp_vvalue_new[VVALUE_SINGLE_ALIGNED_CNT];
	kv_vector_t          *vvalue_old, *vvalue_new;

	vvalue_old = _get_vvalue(spec->old_flags, spec->old_data, spec->old_data_size, tmp_vvalue_old, VVALUE_CNT(tmp_vvalue_old));
	vvalue_new = _get_vvalue(spec->new_flags, spec->new_data, spec->new_data_size, tmp_vvalue_new, VVALUE_CNT(tmp_vvalue_old));

	if ((update_arg->ret_code = _check_kv_wr_allowed(update_arg, spec->key, vvalue_old, vvalue_new)) < 0)
		return 0;

	update_arg->ret_code = _check_kv_index_needed(vvalue_old, vvalue_new);
	return 1;
}

static int _kv_cb_reserve(struct kv_store_update_spec *spec)
{
	struct kv_update_arg *update_arg = spec->arg;
	kv_vector_t           tmp_vvalue_old[VVALUE_SINGLE_ALIGNED_CNT];
	kv_vector_t           tmp_vvalue_new[VVALUE_SINGLE_ALIGNED_CNT];
	kv_vector_t          *vvalue_old, *vvalue_new;

	if ((vvalue_old = _get_vvalue(spec->old_flags,
	                              spec->old_data,
	                              spec->old_data_size,
	                              tmp_vvalue_old,
	                              VVALUE_CNT(tmp_vvalue_old)))) {
		/* only allow the same module that reserved before to re-reserve/unreserve */
		switch (_mod_match(VVALUE_OWNER(vvalue_old), update_arg->owner)) {
			case MOD_MATCH:
				break;

			case MOD_NO_MATCH:
			case MOD_SUB_MATCH:
			case MOD_SUP_MATCH:
				log_debug(ID(update_arg->res),
				          "Module %s can't reserve key %s which is already reserved by module %s.",
				          update_arg->owner,
				          spec->key,
				          VVALUE_OWNER(vvalue_old));
				update_arg->ret_code = -EPERM;
				return 0;
		}
	}

	vvalue_new = _get_vvalue(spec->new_flags, spec->new_data, spec->new_data_size, tmp_vvalue_new, VVALUE_CNT(tmp_vvalue_new));

	update_arg->ret_code = _check_kv_index_needed(vvalue_old, vvalue_new);
	return 1;
}

static const char *_get_mod_name(struct module *mod)
{
	return mod ? module_get_full_name(mod) : MOD_NAME_CORE;
}

static size_t _svalue_ext_data_offset(kv_scalar_t *svalue)
{
	size_t owner_size = strlen(svalue->data) + 1;

	if (svalue->flags & KV_ALIGN)
		return owner_size + MEM_ALIGN_UP_PAD(SVALUE_HEADER_SIZE + owner_size, SVALUE_DATA_ALIGNMENT);

	return owner_size;
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

static void _print_vvalue(kv_vector_t       *vvalue,
                          bool               vector,
                          size_t             size,
                          const char        *name,
                          output_format_t    format,
                          struct sid_buffer *buf,
                          int                level)
{
	size_t start_idx = VVALUE_FLAGS(vvalue) & KV_ALIGN ? VVALUE_IDX_DATA_ALIGNED : VVALUE_IDX_DATA;
	int    i;

	if (vector) {
		print_start_array(format, buf, level, name, true);
		for (i = start_idx; i < size; i++) {
			if (vvalue[i].iov_len) {
				if (_is_string_data(vvalue[i].iov_base, vvalue[i].iov_len))
					print_str_array_elem(format, buf, level + 1, vvalue[i].iov_base, i > start_idx);
				else
					print_binary_array_elem(format,
					                        buf,
					                        level + 1,
					                        vvalue[i].iov_base,
					                        vvalue[i].iov_len,
					                        i + start_idx);
			} else
				print_str_array_elem(format, buf, level + 1, "", false);
		}
		print_end_array(format, buf, level);
	} else if (vvalue[start_idx].iov_len) {
		if (_is_string_data(vvalue[start_idx].iov_base, vvalue[start_idx].iov_len))
			print_str_field(format, buf, level, name, vvalue[start_idx].iov_base, true);
		else
			print_binary_field(format, buf, level, name, vvalue[start_idx].iov_base, vvalue[start_idx].iov_len, true);
	} else
		print_str_field(format, buf, level, name, "", true);
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

static int _build_cmd_kv_buffers(sid_resource_t *cmd_res, const struct cmd_reg *cmd_reg)
{
	struct sid_ucmd_ctx   *ucmd_ctx = sid_resource_get_data(cmd_res);
	output_format_t        format;
	struct sid_buffer_spec buf_spec;
	kv_scalar_t           *svalue;
	kv_store_iter_t       *iter;
	const char            *key;
	void                  *raw_value;
	bool                   vector;
	size_t                 size, vvalue_size, key_size, ext_data_offset;
	kv_store_value_flags_t kv_store_value_flags;
	kv_vector_t           *vvalue;
	unsigned               i, records = 0;
	int                    r           = -1;
	struct sid_buffer     *export_buf  = NULL;
	bool                   needs_comma = false;
	kv_vector_t            tmp_vvalue[VVALUE_SINGLE_ALIGNED_CNT];

	if (!(cmd_reg->flags & (CMD_KV_EXPORT_UDEV_TO_RESBUF | CMD_KV_EXPORT_UDEV_TO_EXPBUF | CMD_KV_EXPORT_SID_TO_RESBUF |
	                        CMD_KV_EXPORT_SID_TO_EXPBUF)))
		/* nothing to export for this command */
		return 0;

	/*
	 * Note that, right now, for commands with CMD_KV_EXPORT_PERSISTENT,
	 * we iterate through all records and match the ones with KV_SYNC_P
	 * flag set. This is because we don't expect this kind of dump to be
	 * used frequently. If this matters in the future, we can create an index
	 * just like we do for KV_SYNC records. Right now, it would not be worth
	 * the extra memory usage caused by creating the index keys.
	 */

	if (cmd_reg->flags & CMD_KV_EXPORT_SYNC)
		iter = kv_store_iter_create(ucmd_ctx->common->kv_store_res, KV_PREFIX_OP_SYNC_C, KV_PREFIX_OP_SYNC_END_C);
	else
		iter = kv_store_iter_create(ucmd_ctx->common->kv_store_res, NULL, NULL);

	if (!iter) {
		// TODO: Discard udev kv-store we've already appended to the output buffer!
		log_error(ID(cmd_res), "Failed to create iterator for temp key-value store.");
		goto fail;
	}

	if (cmd_reg->flags & CMD_KV_EXPBUF_TO_FILE)
		buf_spec = (struct sid_buffer_spec) {.backend  = SID_BUFFER_BACKEND_FILE,
		                                     .type     = SID_BUFFER_TYPE_LINEAR,
		                                     .mode     = SID_BUFFER_MODE_SIZE_PREFIX,
		                                     .ext.file = {ucmd_ctx->req_env.exp_path ?: MAIN_KV_STORE_FILE_PATH}};
	else
		buf_spec = (struct sid_buffer_spec) {.backend = SID_BUFFER_BACKEND_MEMFD,
		                                     .type    = SID_BUFFER_TYPE_LINEAR,
		                                     .mode    = SID_BUFFER_MODE_SIZE_PREFIX};

	if (!(export_buf = sid_buffer_create(&buf_spec,
	                                     &((struct sid_buffer_init) {.size = 0, .alloc_step = PATH_MAX, .limit = 0}),
	                                     &r))) {
		log_error(ID(cmd_res), "Failed to create export buffer.");
		goto fail;
	}

	/*
	 * For exporting the KV store internally, that is MSG_CATEGORY_SELF commands and
	 * commands exporting buffer to main process, we always use the raw NO_FORMAT.
	 * For external clients, we export in format which is requested.
	 */
	if ((ucmd_ctx->req_cat == MSG_CATEGORY_SELF) || (cmd_reg->flags & CMD_KV_EXPBUF_TO_MAIN))
		format = NO_FORMAT;
	else
		format = flags_to_format(ucmd_ctx->req_hdr.flags);

	if (format != NO_FORMAT) {
		print_start_document(format, export_buf, 0);
		print_start_array(format, export_buf, 1, "siddb", false);
	}

	while ((raw_value = kv_store_iter_next(iter, &size, &key, &kv_store_value_flags))) {
		vector = kv_store_value_flags & KV_STORE_VALUE_VECTOR;

		if (vector) {
			vvalue               = raw_value;
			vvalue_size          = size;
			svalue               = NULL;
			VVALUE_FLAGS(vvalue) &= ~KV_SYNC;
			if (cmd_reg->flags & CMD_KV_EXPORT_PERSISTENT) {
				if (!(VVALUE_FLAGS(vvalue) & KV_PERSIST))
					continue;
			}
		} else {
			vvalue        = NULL;
			vvalue_size   = 0;
			svalue        = raw_value;
			svalue->flags &= ~KV_SYNC;
			if (cmd_reg->flags & CMD_KV_EXPORT_PERSISTENT) {
				if (!(svalue->flags & KV_PERSIST))
					continue;
			}
		}

		key_size = strlen(key) + 1;

		/* remove leading KV_PREFIX_OP_SYNC_C if present */
		if (*key == KV_PREFIX_OP_SYNC_C[0]) {
			key      += 1;
			key_size -= 1;
		}

		// TODO: Also deal with situation if the udev namespace values are defined as vectors by chance.
		if (_get_ns_from_key(key) == KV_NS_UDEV) {
			if (!(cmd_reg->flags & (CMD_KV_EXPORT_UDEV_TO_RESBUF | CMD_KV_EXPORT_UDEV_TO_EXPBUF))) {
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

			if (cmd_reg->flags & CMD_KV_EXPORT_UDEV_TO_RESBUF) {
				ext_data_offset = _svalue_ext_data_offset(svalue);

				/* only export if there's a value assigned and the value is not an empty string */
				if ((size > (SVALUE_HEADER_SIZE + ext_data_offset + 1)) &&
				    ((svalue->data + ext_data_offset)[0] != '\0')) {
					key = _get_key_part(key, KEY_PART_CORE, NULL);

					if (((r = sid_buffer_add(ucmd_ctx->res_buf, (void *) key, strlen(key), NULL, NULL)) < 0) ||
					    ((r = sid_buffer_add(ucmd_ctx->res_buf, KV_PAIR_C, 1, NULL, NULL)) < 0) ||
					    ((r = sid_buffer_add(ucmd_ctx->res_buf,
					                         svalue->data + ext_data_offset,
					                         strlen(svalue->data + ext_data_offset),
					                         NULL,
					                         NULL)) < 0) ||
					    ((r = sid_buffer_add(ucmd_ctx->res_buf, KV_END_C, 1, NULL, NULL)) < 0))
						goto fail;

					log_debug(ID(ucmd_ctx->common->kv_store_res),
					          "Exported udev property %s=%s",
					          key,
					          svalue->data + ext_data_offset);
				}
			}

			if (!(cmd_reg->flags & CMD_KV_EXPORT_UDEV_TO_EXPBUF))
				continue;
		} else { /* _get_ns_from_key(key) != KV_NS_UDEV */
			if (!(cmd_reg->flags & (CMD_KV_EXPORT_SID_TO_RESBUF | CMD_KV_EXPORT_SID_TO_EXPBUF))) {
				log_debug(ID(cmd_res), "Ignoring request to export record with key %s to SID main KV store.", key);
				continue;
			}
		}

		if (format == NO_FORMAT) {
			/*
			 * Export keys with data to main process.
			 *
			 * Serialization format fields (message size is implicitly set
			 * when using SID_BUFFER_MODE_SIZE_PREFIX):
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

			if (((r = sid_buffer_add(export_buf, &kv_store_value_flags, sizeof(kv_store_value_flags), NULL, NULL)) <
			     0) ||
			    ((r = sid_buffer_add(export_buf, &key_size, sizeof(key_size), NULL, NULL)) < 0) ||
			    ((r = sid_buffer_add(export_buf, &size, sizeof(size), NULL, NULL)) < 0) ||
			    ((r = sid_buffer_add(export_buf, (char *) key, strlen(key) + 1, NULL, NULL)) < 0)) {
				log_error_errno(ID(cmd_res), errno, "sid_buffer_add failed");
				goto fail;
			}

			if (vector) {
				for (i = 0, size = 0; i < vvalue_size; i++) {
					size += vvalue[i].iov_len;

					if (((r = sid_buffer_add(export_buf,
					                         &vvalue[i].iov_len,
					                         sizeof(vvalue->iov_len),
					                         NULL,
					                         NULL)) < 0) ||
					    ((r = sid_buffer_add(export_buf, vvalue[i].iov_base, vvalue[i].iov_len, NULL, NULL)) <
					     0)) {
						log_error_errno(ID(cmd_res), errno, "sid_buffer_add failed");
						goto fail;
					}
				}
			} else if ((r = sid_buffer_add(export_buf, svalue, size, NULL, NULL)) < 0) {
				log_error_errno(ID(cmd_res), errno, "sid_buffer_add failed");
				goto fail;
			}
		} else {
			print_start_elem(format, export_buf, 2, needs_comma);
			print_uint_field(format, export_buf, 3, "RECORD", records, false);
			print_str_field(format, export_buf, 3, "key", key, true);
			vvalue = _get_vvalue(kv_store_value_flags, raw_value, size, tmp_vvalue, VVALUE_CNT(tmp_vvalue));
			print_uint_field(format, export_buf, 3, "gennum", VVALUE_GENNUM(vvalue), true);
			print_uint64_field(format, export_buf, 3, "seqnum", VVALUE_SEQNUM(vvalue), true);
			print_start_array(format, export_buf, 3, "flags", true);
			print_bool_array_elem(format, export_buf, 4, "AL", VVALUE_FLAGS(vvalue) & KV_ALIGN, false);
			print_bool_array_elem(format, export_buf, 4, "SC", VVALUE_FLAGS(vvalue) & KV_SYNC, true);
			print_bool_array_elem(format, export_buf, 4, "PS", VVALUE_FLAGS(vvalue) & KV_PERSIST, true);
			print_bool_array_elem(format, export_buf, 4, "AR", VVALUE_FLAGS(vvalue) & KV_AR, true);
			print_bool_array_elem(format, export_buf, 4, "RS", VVALUE_FLAGS(vvalue) & KV_RS, true);
			print_bool_array_elem(format, export_buf, 4, "FR_RD", VVALUE_FLAGS(vvalue) & KV_FRG_RD, true);
			print_bool_array_elem(format, export_buf, 4, "SB_RD", VVALUE_FLAGS(vvalue) & KV_SUB_RD, true);
			print_bool_array_elem(format, export_buf, 4, "SP_RD", VVALUE_FLAGS(vvalue) & KV_SUP_RD, true);
			print_bool_array_elem(format, export_buf, 4, "FR_WR", VVALUE_FLAGS(vvalue) & KV_FRG_WR, true);
			print_bool_array_elem(format, export_buf, 4, "SB_WR", VVALUE_FLAGS(vvalue) & KV_SUB_WR, true);
			print_bool_array_elem(format, export_buf, 4, "SP_WR", VVALUE_FLAGS(vvalue) & KV_SUP_WR, true);
			print_end_array(format, export_buf, 3);
			print_str_field(format, export_buf, 3, "owner", VVALUE_OWNER(vvalue), true);
			_print_vvalue(vvalue, vector, size, vector ? "values" : "value", format, export_buf, 3);
			print_end_elem(format, export_buf, 2);
			needs_comma = true;
		}
		records++;
	}

	if (format != NO_FORMAT) {
		print_end_array(format, export_buf, 1);
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

static int _check_global_kv_rs_for_wr(struct sid_ucmd_ctx    *ucmd_ctx,
                                      const char             *owner,
                                      const char             *dom,
                                      sid_ucmd_kv_namespace_t ns,
                                      const char             *key_core)
{
	kv_vector_t            tmp_vvalue[VVALUE_SINGLE_CNT];
	kv_vector_t           *vvalue;
	const char            *key = NULL;
	void                  *found;
	size_t                 value_size;
	kv_store_value_flags_t kv_store_value_flags;
	struct kv_key_spec     key_spec = {.extra_op = NULL,
	                                   .op       = KV_OP_SET,
	                                   .dom      = dom ?: ID_NULL,
	                                   .ns       = ns,
	                                   .ns_part  = ID_NULL,
	                                   .id_cat   = ID_NULL,
	                                   .id       = ID_NULL,
	                                   .core     = key_core};
	int                    r        = 1;

	if ((ns != KV_NS_UDEV) && (ns != KV_NS_DEVICE))
		goto out;

	if (!(key = _compose_key(ucmd_ctx->common->gen_buf, &key_spec))) {
		r = -ENOMEM;
		goto out;
	}

	if (!(found = kv_store_get_value(ucmd_ctx->common->kv_store_res, key, &value_size, &kv_store_value_flags)))
		goto out;

	vvalue = _get_vvalue(kv_store_value_flags, found, value_size, tmp_vvalue, VVALUE_CNT(tmp_vvalue));

	if (!(VVALUE_FLAGS(vvalue) & KV_RS))
		goto out;

	switch (_mod_match(VVALUE_OWNER(vvalue), owner)) {
		case MOD_NO_MATCH:
			r = VVALUE_FLAGS(vvalue) & KV_FRG_WR;
			break;
		case MOD_MATCH:
			r = 1;
			break;
		case MOD_SUB_MATCH:
			r = VVALUE_FLAGS(vvalue) & KV_SUB_WR;
			break;
		case MOD_SUP_MATCH:
			r = VVALUE_FLAGS(vvalue) & KV_SUP_WR;
			break;
	}

	if (!r)
		log_debug(ID(ucmd_ctx->common->kv_store_res),
		          "Module %s can't overwrite value with key %s which is reserved and attached to %s module.",
		          owner,
		          key,
		          VVALUE_OWNER(vvalue));
out:
	_destroy_key(ucmd_ctx->common->gen_buf, key);
	return r;
}

static const char *_get_ns_part(struct module *mod, struct sid_ucmd_ctx *ucmd_ctx, sid_ucmd_kv_namespace_t ns)
{
	switch (ns) {
		case KV_NS_UDEV:
			return ucmd_ctx->req_env.dev.num_s ?: ID_NULL;
		case KV_NS_DEVICE:
		case KV_NS_DEVMOD:
			return ucmd_ctx->req_env.dev.uid_s ?: ID_NULL;
		case KV_NS_MODULE:
			return _get_mod_name(mod);
		case KV_NS_GLOBAL:
		case KV_NS_UNDEFINED:
			break;
	}

	return ID_NULL;
}

static const char *_get_foreign_ns_part(struct module          *mod,
                                        struct sid_ucmd_ctx    *ucmd_ctx,
                                        const char             *foreign_mod_name,
                                        const char             *foreign_dev_id,
                                        sid_ucmd_kv_namespace_t ns)
{
	switch (ns) {
		case KV_NS_UDEV:
			return ucmd_ctx->req_env.dev.num_s ?: ID_NULL;
		case KV_NS_DEVICE:
		case KV_NS_DEVMOD:
			return foreign_dev_id ?: ucmd_ctx->req_env.dev.uid_s ?: ID_NULL;
		case KV_NS_MODULE:
			return foreign_mod_name ?: _get_mod_name(mod);
		case KV_NS_GLOBAL:
		case KV_NS_UNDEFINED:
			break;
	}

	return ID_NULL;
}

static void _destroy_delta_buffers(struct kv_delta *delta)
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

static void _destroy_unused_delta_buffers(struct kv_delta *delta)
{
	if (delta->plus) {
		if (sid_buffer_count(delta->plus) < VVALUE_SINGLE_CNT) {
			sid_buffer_destroy(delta->plus);
			delta->plus = NULL;
		}
	}

	if (delta->minus) {
		if (sid_buffer_count(delta->minus) < VVALUE_SINGLE_CNT) {
			sid_buffer_destroy(delta->minus);
			delta->minus = NULL;
		}
	}
}

static int _init_delta_buffer(kv_vector_t *vheader, struct sid_buffer **delta_buf, size_t size)
{
	struct sid_buffer *buf = NULL;
	size_t             i;
	int                r = 0;

	if (!size)
		return 0;

	if (size < VVALUE_HEADER_CNT) {
		r = -EINVAL;
		goto out;
	}

	if (!(buf = sid_buffer_create(&((struct sid_buffer_spec) {.backend = SID_BUFFER_BACKEND_MALLOC,
	                                                          .type    = SID_BUFFER_TYPE_VECTOR,
	                                                          .mode    = SID_BUFFER_MODE_PLAIN}),
	                              &((struct sid_buffer_init) {.size = size, .alloc_step = 0, .limit = 0}),
	                              &r)))
		goto out;

	for (i = 0; i < VVALUE_HEADER_CNT; i++) {
		if ((r = sid_buffer_add(buf, vheader[i].iov_base, vheader[i].iov_len, NULL, NULL)) < 0)
			goto out;
	}
out:
	if (r < 0) {
		if (buf)
			sid_buffer_destroy(buf);
	} else
		*delta_buf = buf;
	return r;
}

static int _init_delta_buffers(struct kv_delta *delta, kv_vector_t *vheader, size_t minus_size, size_t plus_size, size_t final_size)
{
	if (_init_delta_buffer(vheader, &delta->plus, plus_size) < 0 ||
	    _init_delta_buffer(vheader, &delta->minus, minus_size) < 0 ||
	    _init_delta_buffer(vheader, &delta->final, final_size) < 0) {
		_destroy_delta_buffers(delta);
		return -1;
	}

	return 0;
}

static int _delta_step_calc(struct kv_store_update_spec *spec)
{
	struct kv_update_arg *update_arg = spec->arg;
	struct kv_delta      *delta      = ((struct kv_rel_spec *) update_arg->custom)->delta;
	kv_vector_t          *old_vvalue = spec->old_data;
	size_t                old_vsize  = spec->old_data_size;
	kv_vector_t          *new_vvalue = spec->new_data;
	size_t                new_vsize  = spec->new_data_size;
	size_t                i_old, i_new;
	int                   cmp_result;
	int                   r = -1;

	if (_init_delta_buffers(delta, new_vvalue, old_vsize, new_vsize, old_vsize + new_vsize) < 0)
		goto out;

	if (!old_vsize)
		old_vsize = VVALUE_HEADER_CNT;

	if (!new_vsize)
		new_vsize = VVALUE_HEADER_CNT;

	/* start right beyond the header */
	i_old = i_new = VVALUE_HEADER_CNT;

	/* look for differences between old_vvalue and new_vvalue vector */
	while (1) {
		if ((i_old < old_vsize) && (i_new < new_vsize)) {
			/* both vectors still still have items to handle */
			cmp_result = strcmp(old_vvalue[i_old].iov_base, new_vvalue[i_new].iov_base);
			if (cmp_result < 0) {
				/* the old vector has item the new one doesn't have */
				switch (delta->op) {
					case KV_OP_SET:
						/* we have detected removed item: add it to delta->minus */
						if ((r = sid_buffer_add(delta->minus,
						                        old_vvalue[i_old].iov_base,
						                        old_vvalue[i_old].iov_len,
						                        NULL,
						                        NULL)) < 0)
							goto out;
						break;
					case KV_OP_PLUS:
					/* we're keeping old item: add it to delta->final */
					/* no break here intentionally! */
					case KV_OP_MINUS:
						/* we're keeping old item: add it to delta->final */
						if ((r = sid_buffer_add(delta->final,
						                        old_vvalue[i_old].iov_base,
						                        old_vvalue[i_old].iov_len,
						                        NULL,
						                        NULL)) < 0)
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
						if (((r = sid_buffer_add(delta->plus,
						                         new_vvalue[i_new].iov_base,
						                         new_vvalue[i_new].iov_len,
						                         NULL,
						                         NULL)) < 0) ||
						    ((r = sid_buffer_add(delta->final,
						                         new_vvalue[i_new].iov_base,
						                         new_vvalue[i_new].iov_len,
						                         NULL,
						                         NULL)) < 0))
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
						if ((r = sid_buffer_add(delta->final,
						                        new_vvalue[i_new].iov_base,
						                        new_vvalue[i_new].iov_len,
						                        NULL,
						                        NULL)) < 0)
							goto out;
						break;
					case KV_OP_MINUS:
						/* we're removing item: add it to delta->minus */
						if ((r = sid_buffer_add(delta->minus,
						                        new_vvalue[i_new].iov_base,
						                        new_vvalue[i_new].iov_len,
						                        NULL,
						                        NULL)) < 0)
							goto out;
						break;
					case KV_OP_ILLEGAL:
						goto out;
				}
				i_old++;
				i_new++;
			}
			continue;
		} else if (i_old == old_vsize) {
			/* only new vector still has items to handle */
			while (i_new < new_vsize) {
				switch (delta->op) {
					case KV_OP_SET:
					/* we have detected new item: add it to delta->final */
					/* no break here intentionally! */
					case KV_OP_PLUS:
						/* we're adding new item: add it to delta->plus and delta->final */
						if (((r = sid_buffer_add(delta->plus,
						                         new_vvalue[i_new].iov_base,
						                         new_vvalue[i_new].iov_len,
						                         NULL,
						                         NULL)) < 0) ||
						    ((r = sid_buffer_add(delta->final,
						                         new_vvalue[i_new].iov_base,
						                         new_vvalue[i_new].iov_len,
						                         NULL,
						                         NULL)) < 0))
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
		} else if (i_new == new_vsize) {
			/* only old vector still has items to handle */
			while (i_old < old_vsize) {
				switch (delta->op) {
					case KV_OP_SET:
						/* we have detected removed item: add it to delta->minus */
						if ((r = sid_buffer_add(delta->minus,
						                        old_vvalue[i_old].iov_base,
						                        old_vvalue[i_old].iov_len,
						                        NULL,
						                        NULL)) < 0)
							goto out;
						break;
					case KV_OP_PLUS:
					/* we're keeping old item: add it to delta->final */
					/* no break here intentionally! */
					case KV_OP_MINUS:
						/* we're not changing the old item so add it to delta->final */
						if ((r = sid_buffer_add(delta->final,
						                        old_vvalue[i_old].iov_base,
						                        old_vvalue[i_old].iov_len,
						                        NULL,
						                        NULL)) < 0)
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
		_destroy_delta_buffers(delta);
	else
		_destroy_unused_delta_buffers(delta);

	return r;
}

static void _delta_cross_bitmap_calc(struct cross_bitmap_calc_arg *cross)
{
	size_t old_vsize, new_vsize;
	size_t i_old, i_new;
	int    cmp_result;

	if ((old_vsize = cross->old_vsize) < VVALUE_HEADER_CNT)
		old_vsize = VVALUE_HEADER_CNT;

	if ((new_vsize = cross->new_vsize) < VVALUE_HEADER_CNT)
		new_vsize = VVALUE_HEADER_CNT;

	i_old = i_new = VVALUE_HEADER_CNT;

	while (1) {
		if ((i_old < old_vsize) && (i_new < new_vsize)) {
			/* both vectors still have items to handle */
			cmp_result = strcmp(cross->old_vvalue[i_old].iov_base, cross->new_vvalue[i_new].iov_base);
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
		} else if (i_old == old_vsize) {
			/* only new vector still has items to handle: nothing else to compare */
			break;
		} else if (i_new == new_vsize) {
			/* only old vector still has items to handle: nothing else to compare */
			break;
		}
	}
}

static int _vvalue_str_cmp(const void *a, const void *b)
{
	const kv_vector_t *vvalue_a = (kv_vector_t *) a;
	const kv_vector_t *vvalue_b = (kv_vector_t *) b;

	return strcmp((const char *) vvalue_a->iov_base, (const char *) vvalue_b->iov_base);
}

static int _delta_abs_calc(kv_vector_t *vheader, struct kv_update_arg *update_arg)
{
	struct cross_bitmap_calc_arg cross1   = {0};
	struct cross_bitmap_calc_arg cross2   = {0};
	struct kv_rel_spec          *rel_spec = update_arg->custom;
	kv_op_t                      orig_op  = rel_spec->cur_key_spec->op;
	const char                  *delta_key;
	kv_vector_t                 *abs_plus_v, *abs_minus_v;
	size_t                       i, abs_plus_vsize, abs_minus_vsize;
	int                          r = -1;

	if (!rel_spec->delta->plus && !rel_spec->delta->minus)
		return 0;

	rel_spec->cur_key_spec->op = KV_OP_PLUS;
	if (!(delta_key = _compose_key(update_arg->gen_buf, rel_spec->cur_key_spec)))
		goto out;
	cross1.old_vvalue = kv_store_get_value(update_arg->res, delta_key, &cross1.old_vsize, NULL);
	_destroy_key(update_arg->gen_buf, delta_key);
	if (cross1.old_vvalue && !(cross1.old_bmp = bitmap_create(cross1.old_vsize, true, NULL)))
		goto out;

	rel_spec->cur_key_spec->op = KV_OP_MINUS;
	if (!(delta_key = _compose_key(update_arg->gen_buf, rel_spec->cur_key_spec)))
		goto out;
	cross2.old_vvalue = kv_store_get_value(update_arg->res, delta_key, &cross2.old_vsize, NULL);
	_destroy_key(update_arg->gen_buf, delta_key);
	if (cross2.old_vvalue && !(cross2.old_bmp = bitmap_create(cross2.old_vsize, true, NULL)))
		goto out;

	/*
	 * set up cross1 - old plus vs. new minus
	 *
	 * OLD              NEW
	 *
	 * plus  <----|     plus
	 * minus      |---> minus
	 */
	if (rel_spec->delta->minus) {
		sid_buffer_get_data(rel_spec->delta->minus, (const void **) &cross1.new_vvalue, &cross1.new_vsize);

		if (!(cross1.new_bmp = bitmap_create(cross1.new_vsize, true, NULL)))
			goto out;

		/* cross-compare old_plus with new_minus and unset bitmap positions where we find contradiction */
		_delta_cross_bitmap_calc(&cross1);
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
		sid_buffer_get_data(rel_spec->delta->plus, (const void **) &cross2.new_vvalue, &cross2.new_vsize);

		if (!(cross2.new_bmp = bitmap_create(cross2.new_vsize, true, NULL)))
			goto out;

		/* cross-compare old_minus with new_plus and unset bitmap positions where we find contradiction */
		_delta_cross_bitmap_calc(&cross2);
	}

	/*
	 * count overall size for both plus and minus taking only non-contradicting items
	 *
	 * OLD             NEW
	 *
	 * plus  <---+---> plus
	 * minus <---+---> minus
	 */
	abs_minus_vsize = ((cross2.old_bmp ? bitmap_get_bit_set_count(cross2.old_bmp) : 0) +
	                   (cross1.new_bmp ? bitmap_get_bit_set_count(cross1.new_bmp) : 0));
	if (cross2.old_bmp && cross1.new_bmp)
		abs_minus_vsize -= VVALUE_HEADER_CNT;

	abs_plus_vsize = ((cross1.old_bmp ? bitmap_get_bit_set_count(cross1.old_bmp) : 0) +
	                  (cross2.new_bmp ? bitmap_get_bit_set_count(cross2.new_bmp) : 0));
	if (cross1.old_bmp && cross2.new_bmp)
		abs_plus_vsize -= VVALUE_HEADER_CNT;

	/* go through the old and new plus and minus vectors and merge non-contradicting items */
	if (_init_delta_buffers(rel_spec->abs_delta, vheader, abs_minus_vsize, abs_plus_vsize, 0) < 0)
		goto out;

	if (rel_spec->delta->flags & DELTA_WITH_REL)
		rel_spec->abs_delta->flags |= DELTA_WITH_REL;

	if (cross1.old_vvalue) {
		for (i = VVALUE_IDX_DATA; i < cross1.old_vsize; i++) {
			if (bitmap_bit_is_set(cross1.old_bmp, i, NULL) && ((r = sid_buffer_add(rel_spec->abs_delta->plus,
			                                                                       cross1.old_vvalue[i].iov_base,
			                                                                       cross1.old_vvalue[i].iov_len,
			                                                                       NULL,
			                                                                       NULL)) < 0))
				goto out;
		}
	}

	if (cross1.new_vvalue) {
		for (i = VVALUE_IDX_DATA; i < cross1.new_vsize; i++) {
			if (bitmap_bit_is_set(cross1.new_bmp, i, NULL) && ((r = sid_buffer_add(rel_spec->abs_delta->minus,
			                                                                       cross1.new_vvalue[i].iov_base,
			                                                                       cross1.new_vvalue[i].iov_len,
			                                                                       NULL,
			                                                                       NULL)) < 0))
				goto out;
		}
	}

	if (cross2.old_vvalue) {
		for (i = VVALUE_IDX_DATA; i < cross2.old_vsize; i++) {
			if (bitmap_bit_is_set(cross2.old_bmp, i, NULL) && ((r = sid_buffer_add(rel_spec->abs_delta->minus,
			                                                                       cross2.old_vvalue[i].iov_base,
			                                                                       cross2.old_vvalue[i].iov_len,
			                                                                       NULL,
			                                                                       NULL)) < 0))
				goto out;
		}
	}

	if (cross2.new_vvalue) {
		for (i = VVALUE_IDX_DATA; i < cross2.new_vsize; i++) {
			if (bitmap_bit_is_set(cross2.new_bmp, i, NULL) && ((r = sid_buffer_add(rel_spec->abs_delta->plus,
			                                                                       cross2.new_vvalue[i].iov_base,
			                                                                       cross2.new_vvalue[i].iov_len,
			                                                                       NULL,
			                                                                       NULL)) < 0))
				goto out;
		}
	}

	if (rel_spec->abs_delta->plus) {
		sid_buffer_get_data(rel_spec->abs_delta->plus, (const void **) &abs_plus_v, &abs_plus_vsize);
		qsort(abs_plus_v + VVALUE_IDX_DATA, abs_plus_vsize - VVALUE_IDX_DATA, sizeof(kv_vector_t), _vvalue_str_cmp);
	}

	if (rel_spec->abs_delta->minus) {
		sid_buffer_get_data(rel_spec->abs_delta->minus, (const void **) &abs_minus_v, &abs_minus_vsize);
		qsort(abs_minus_v + VVALUE_IDX_DATA, abs_minus_vsize - VVALUE_IDX_DATA, sizeof(kv_vector_t), _vvalue_str_cmp);
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
		_destroy_delta_buffers(rel_spec->abs_delta);

	return r;
}

// TODO: Make it possible to set all flags at once or change selected flag bits.
static void _value_vector_mark_sync(kv_vector_t *vvalue, int sync)
{
	if (sync)
		vvalue[VVALUE_IDX_FLAGS] = (kv_vector_t) {&value_flags_sync, sizeof(value_flags_sync)};
	else
		vvalue[VVALUE_IDX_FLAGS] = (kv_vector_t) {&value_flags_no_sync, sizeof(value_flags_no_sync)};
}

static int _delta_update(kv_vector_t *vheader, kv_op_t op, struct kv_update_arg *update_arg, bool index)
{
	struct kv_rel_spec *rel_spec = update_arg->custom;
	kv_op_t             orig_op  = rel_spec->cur_key_spec->op;
	struct kv_delta    *orig_delta, *orig_abs_delta;
	kv_vector_t        *delta_vvalue, *abs_delta_vvalue;
	size_t              delta_vsize, abs_delta_vsize, i;
	const char         *key_prefix, *ns_part;
	char               *key;
	kv_vector_t         rel_vvalue[VVALUE_SINGLE_CNT];
	int                 r = -1;

	if (op == KV_OP_PLUS) {
		if (!rel_spec->abs_delta->plus)
			return 0;

		sid_buffer_get_data(rel_spec->abs_delta->plus, (const void **) &abs_delta_vvalue, &abs_delta_vsize);
		sid_buffer_get_data(rel_spec->delta->plus, (const void **) &delta_vvalue, &delta_vsize);
	} else if (op == KV_OP_MINUS) {
		if (!rel_spec->abs_delta->minus)
			return 0;

		sid_buffer_get_data(rel_spec->abs_delta->minus, (const void **) &abs_delta_vvalue, &abs_delta_vsize);
		sid_buffer_get_data(rel_spec->delta->minus, (const void **) &delta_vvalue, &delta_vsize);
	} else {
		log_error(ID(update_arg->res), INTERNAL_ERROR "%s: incorrect delta operation requested.", __func__);
		return -1;
	}

	/* store absolute delta for current item - persistent */
	rel_spec->cur_key_spec->op = op;
	key                        = _compose_key(update_arg->gen_buf, rel_spec->cur_key_spec);
	rel_spec->cur_key_spec->op = orig_op;
	if (!key)
		return -1;
	_value_vector_mark_sync(abs_delta_vvalue, 1);

	kv_store_set_value(update_arg->res,
	                   key,
	                   abs_delta_vvalue,
	                   abs_delta_vsize,
	                   KV_STORE_VALUE_VECTOR,
	                   KV_STORE_VALUE_NO_OP,
	                   _kv_cb_write,
	                   update_arg);

	if (index)
		(void) _manage_kv_index(update_arg, key);

	_value_vector_mark_sync(abs_delta_vvalue, 0);
	_destroy_key(update_arg->gen_buf, key);

	/* the other way round now - store final and absolute delta for each relative */
	if (delta_vsize && rel_spec->delta->flags & DELTA_WITH_REL) {
		orig_delta             = rel_spec->delta;
		orig_abs_delta         = rel_spec->abs_delta;

		rel_spec->delta        = &((struct kv_delta) {0});
		rel_spec->abs_delta    = &((struct kv_delta) {0});
		rel_spec->delta->op    = op;
		/*
		 * WARNING: Mind that at this point, we're in _delta_update which is
		 *          already called from _do_kv_delta_set outside. If we called
		 *          the _do_kv_delta_set from here with DELTA_WITH_REL, we'd
		 *          get into infinite loop:
		 *
		 *          _do_kv_delta_set -> _delta_update -> _do_kv_delta_set -> _delta_update ...
		 */
		rel_spec->delta->flags = DELTA_WITH_DIFF;

		UTIL_SWAP(rel_spec->cur_key_spec, rel_spec->rel_key_spec);

		if (!(key_prefix = _compose_key_prefix(NULL, rel_spec->rel_key_spec)))
			goto out;

		_vvalue_header_prep(rel_vvalue,
		                    VVALUE_CNT(rel_vvalue),
		                    &VVALUE_SEQNUM(vheader),
		                    &value_flags_no_sync,
		                    &VVALUE_GENNUM(vheader),
		                    (char *) update_arg->owner);
		_vvalue_data_prep(rel_vvalue, VVALUE_CNT(rel_vvalue), 0, (void *) key_prefix, strlen(key_prefix) + 1);

		for (i = VVALUE_IDX_DATA; i < delta_vsize; i++) {
			if (!(ns_part = _copy_ns_part_from_key(delta_vvalue[i].iov_base, NULL, 0)))
				goto out;

			rel_spec->cur_key_spec->ns_part = ns_part;

			if (!(key = _compose_key(NULL, rel_spec->cur_key_spec))) {
				_destroy_key(NULL, ns_part);
				goto out;
			}

			_do_kv_delta_set(key, rel_vvalue, VVALUE_SINGLE_CNT, update_arg, index);

			rel_spec->cur_key_spec->ns_part = NULL;
			_destroy_key(NULL, key);
			_destroy_key(NULL, ns_part);
		}

		r = 0;
out:
		_destroy_key(NULL, key_prefix);
		rel_spec->abs_delta = orig_abs_delta;
		rel_spec->delta     = orig_delta;
		UTIL_SWAP(rel_spec->rel_key_spec, rel_spec->cur_key_spec);
	}

	rel_spec->cur_key_spec->op = orig_op;
	return r;
}

static int _do_kv_cb_delta_step(struct kv_store_update_spec *spec, bool is_sync)
{
	struct kv_update_arg *update_arg = spec->arg;
	struct kv_rel_spec   *rel_spec   = update_arg->custom;
	int                   r;

	if ((r = _check_kv_wr_allowed(update_arg, spec->key, spec->old_data, spec->new_data)) < 0) {
		update_arg->ret_code = is_sync ? 0 : r;
		return 0;
	}

	if ((update_arg->ret_code = _delta_step_calc(spec)) < 0)
		return 0;

	if (rel_spec->delta->final) {
		sid_buffer_get_data(rel_spec->delta->final, (const void **) &spec->new_data, &spec->new_data_size);
		spec->new_flags &= ~KV_STORE_VALUE_REF;
		return 1;
	}

	return 0;
}

static int _kv_cb_delta_step(struct kv_store_update_spec *spec)
{
	return _do_kv_cb_delta_step(spec, false);
}

static int _kv_cb_main_delta_step(struct kv_store_update_spec *spec)
{
	return _do_kv_cb_delta_step(spec, true);
}

static int _do_kv_delta_set(char *key, kv_vector_t *vvalue, size_t vsize, struct kv_update_arg *update_arg, bool index)
{
	struct kv_rel_spec *rel_spec = update_arg->custom;
	int                 r        = -1;

	// TODO: assign proper return code, including update_arg->ret_code

	/*
	 * First, we calculate the difference between currently stored (old) vvalue
	 * and provided (new) vvalue with _kv_cb_delta_step/_delta_step_calc,
	 * taking into account requested operation (update_arg->delta->op):
	 *   KV_OP_SET overwrites old vvalue with new vvalue
	 *   KV_OP_PLUS adds items listed in new vvalue to old vvalue
	 *   KV_OP_MINUS remove items listed in new vvalue from old vvalue
	 *
	 * The result of _delta_step_calc is stored in rel_spec->delta:
	 *   delta->final contains the final new vvalue to be stored in db snapshot
	 *   delta->plus contains list of items which have been added to the old vvalue (not stored in db)
	 *   delta->minus contains list of items which have been remove from the old vvalue (not stored in db)
	 */
	if (!kv_store_set_value(update_arg->res,
	                        key,
	                        vvalue,
	                        vsize,
	                        KV_STORE_VALUE_VECTOR | KV_STORE_VALUE_REF,
	                        KV_STORE_VALUE_NO_OP,
	                        _kv_cb_delta_step,
	                        update_arg) ||
	    update_arg->ret_code < 0)
		goto out;

	if (index)
		(void) _manage_kv_index(update_arg, key);

	/*
	 * Next, depending on further requested handling based on rel_spec->delta->flags,
	 * we calculate absolute delta (_delta_abs_calc) which is a cummulative difference
	 * with respect to the old vvalue from the very beginning of db snapshot (original vvalue).
	 *
	 * The results of _delta_abs_calc are stored in rel_spec->abs_delta:
	 *  (delta->final unused here)
	 *  abs_delta->plus contains list of items which have been added to the original vvalue since db snapshot started
	 *  abs_delta->minus contains list of items which have been added to the original vvalue since db snapshot started
	 *
	 * Then:
	 *   DELTA_WITH_DIFF will cause the abs_delta->plus and abs_delta->minus to be stored in db snapshot
	 *   DELTA_WITH_REL will cause relation changes to be calculated and stored.
	 *
	 *   Note: the relation changes mean that we take each item of delta->plus and delta->minus as key to construct
	 *   relation records.
	 *
	 *   For example, if we change the vvalue for a key 'K':
	 *      K: old vvalue = {A}
	 *      K: new vvalue = {B}
	 *      op = KV_OP_PLUS
	 *   which results in:
	 *      delta->final = {A, B}
	 *      delta->plus  = {B}
	 *      delta->minus = {}
	 *   then this will result in this db state in turn for related 'A' and 'B' keys:
	 *      K: vvalue = {A, B}  ('B' has been added to vvalue under key 'K')
	 *      A: vvalue = {K}     (already stored in db)
	 *      B: new vvalue = {K} (newly stored record in db)
	 */
	if (rel_spec->delta->flags & (DELTA_WITH_DIFF | DELTA_WITH_REL)) {
		if (_delta_abs_calc(vvalue, update_arg) < 0)
			goto out;

		if (_delta_update(vvalue, KV_OP_PLUS, update_arg, index) < 0)
			goto out;

		if (_delta_update(vvalue, KV_OP_MINUS, update_arg, index) < 0)
			goto out;
	}

	r = 0;
out:
	_destroy_delta_buffers(rel_spec->abs_delta);
	_destroy_delta_buffers(rel_spec->delta);
	return r;
}

static int _kv_delta_set(char *key, kv_vector_t *vvalue, size_t vsize, struct kv_update_arg *update_arg, bool index)
{
	struct kv_rel_spec *rel_spec = update_arg->custom;
	int                 r;

	if ((r = kv_store_transaction_begin(update_arg->res)) < 0) {
		if (r == -EBUSY)
			log_error(ID(update_arg->res), INTERNAL_ERROR "%s: kv_store already in a transaction", __func__);
		return r;
	}
	r = _do_kv_delta_set(key, vvalue, vsize, update_arg, index);
	kv_store_transaction_end(update_arg->res, false);

	return r;
}

static void *_do_sid_ucmd_set_kv(struct module          *mod,
                                 struct sid_ucmd_ctx    *ucmd_ctx,
                                 const char             *dom,
                                 sid_ucmd_kv_namespace_t ns,
                                 const char             *key_core,
                                 sid_ucmd_kv_flags_t     flags,
                                 const void             *value,
                                 size_t                  value_size)
{
	const char          *owner      = _get_mod_name(mod);
	char                *key        = NULL;
	size_t               vvalue_cnt = flags & KV_ALIGN ? VVALUE_SINGLE_ALIGNED_CNT : VVALUE_SINGLE_CNT;
	kv_vector_t          vvalue[vvalue_cnt];
	kv_scalar_t         *svalue;
	struct kv_update_arg update_arg;
	struct kv_key_spec   key_spec = {.extra_op = NULL,
	                                 .op       = KV_OP_SET,
	                                 .dom      = dom ?: ID_NULL,
	                                 .ns       = ns,
	                                 .ns_part  = _get_ns_part(mod, ucmd_ctx, ns),
	                                 .id_cat   = ns == KV_NS_DEVMOD ? KV_PREFIX_NS_MODULE_C : ID_NULL,
	                                 .id       = ns == KV_NS_DEVMOD ? _get_ns_part(mod, ucmd_ctx, KV_NS_MODULE) : ID_NULL,
	                                 .core     = key_core};
	int                  r;
	void                *ret = NULL;

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
	/*
	 * FIXME: So we have two KV store lookups here - one to check the global reservation
	 *        and the other one inside kv_store_set_value. Can we come up with a better
	 *        scheme so there's only one lookup?
	 */
	if (!((ns == KV_NS_UDEV) && !strcmp(owner, OWNER_CORE))) {
		r = _check_global_kv_rs_for_wr(ucmd_ctx, owner, dom, ns, key_core);
		if (r <= 0)
			return NULL;
	}

	if (!(key = _compose_key(ucmd_ctx->common->gen_buf, &key_spec)))
		return NULL;

	if (value == SID_UCMD_KV_UNSET)
		value = NULL;

	if (!value)
		value_size = 0;

	_vvalue_header_prep(vvalue,
	                    vvalue_cnt,
	                    &ucmd_ctx->req_env.dev.udev.seqnum,
	                    &flags,
	                    &ucmd_ctx->common->gennum,
	                    (char *) owner);
	_vvalue_data_prep(vvalue, vvalue_cnt, 0, (void *) value, value_size);

	update_arg = (struct kv_update_arg) {.res      = ucmd_ctx->common->kv_store_res,
	                                     .owner    = owner,
	                                     .gen_buf  = ucmd_ctx->common->gen_buf,
	                                     .custom   = NULL,
	                                     .ret_code = -EREMOTEIO};

	if (flags & KV_AR) {
		key[0] = KV_PREFIX_OP_ARCHIVE_C[0];
		if (!(svalue = kv_store_set_value_with_archive(ucmd_ctx->common->kv_store_res,
		                                               key + 1,
		                                               vvalue,
		                                               vvalue_cnt,
		                                               KV_STORE_VALUE_VECTOR,
		                                               KV_STORE_VALUE_OP_MERGE,
		                                               _kv_cb_write,
		                                               &update_arg,
		                                               key)))
			goto out;
	} else {
		if (!(svalue = kv_store_set_value(ucmd_ctx->common->kv_store_res,
		                                  key,
		                                  vvalue,
		                                  vvalue_cnt,
		                                  KV_STORE_VALUE_VECTOR,
		                                  KV_STORE_VALUE_OP_MERGE,
		                                  _kv_cb_write,
		                                  &update_arg)))
			goto out;
	}

	if (value)
		ret = svalue->data + _svalue_ext_data_offset(svalue);
	else
		ret = SID_UCMD_KV_UNSET;
out:
	(void) _manage_kv_index(&update_arg, key);
	_destroy_key(ucmd_ctx->common->gen_buf, key);
	return ret;
}

void *sid_ucmd_set_kv(struct module          *mod,
                      struct sid_ucmd_ctx    *ucmd_ctx,
                      sid_ucmd_kv_namespace_t ns,
                      const char             *key,
                      const void             *value,
                      size_t                  value_size,
                      sid_ucmd_kv_flags_t     flags)
{
	const char *dom;

	if (!mod || !ucmd_ctx || (ns == KV_NS_UNDEFINED) || !key || !*key || (key[0] == KV_PREFIX_KEY_SYS_C[0]))
		return NULL;

	if (ns == KV_NS_UDEV) {
		dom   = NULL;
		flags |= KV_SYNC_P;
	} else
		dom = KV_KEY_DOM_USER;

	return _do_sid_ucmd_set_kv(mod, ucmd_ctx, dom, ns, key, flags, value, value_size);
}

static const void *_cmd_get_key_spec_value(struct module       *mod,
                                           struct sid_ucmd_ctx *ucmd_ctx,
                                           struct kv_key_spec  *key_spec,
                                           size_t              *value_size,
                                           sid_ucmd_kv_flags_t *flags)
{
	const char  *owner = _get_mod_name(mod);
	const char  *key   = NULL;
	kv_scalar_t *svalue;
	size_t       size, ext_data_offset;
	void        *ret = NULL;

	if (!(key = _compose_key(ucmd_ctx->common->gen_buf, key_spec)))
		goto out;

	if (!(svalue = kv_store_get_value(ucmd_ctx->common->kv_store_res, key, &size, NULL)))
		goto out;

	switch (_mod_match(svalue->data, owner)) {
		case MOD_NO_MATCH:
			if (!(svalue->flags & KV_FRG_RD))
				goto out;
			break;
		case MOD_MATCH:
			/* nothing to do here */
			break;
		case MOD_SUB_MATCH:
			if (!(svalue->flags & KV_SUB_RD))
				goto out;
			break;
		case MOD_SUP_MATCH:
			if (!(svalue->flags & KV_SUP_RD))
				goto out;
			break;
	}

	if (flags)
		*flags = svalue->flags;

	ext_data_offset = _svalue_ext_data_offset(svalue);
	size            -= (SVALUE_HEADER_SIZE + ext_data_offset);

	if (value_size)
		*value_size = size;

	if (size)
		ret = svalue->data + ext_data_offset;
out:
	_destroy_key(ucmd_ctx->common->gen_buf, key);
	return ret;
}

static const void *_do_sid_ucmd_get_kv(struct module          *mod,
                                       struct sid_ucmd_ctx    *ucmd_ctx,
                                       const char             *dom,
                                       sid_ucmd_kv_namespace_t ns,
                                       const char             *key,
                                       size_t                 *value_size,
                                       sid_ucmd_kv_flags_t    *flags,
                                       unsigned int            archive)
{
	struct kv_key_spec key_spec = {.extra_op = archive == 1 ? KV_PREFIX_OP_ARCHIVE_C : KV_PREFIX_OP_BLANK_C,
	                               .op       = KV_OP_SET,
	                               .dom      = dom ?: ID_NULL,
	                               .ns       = ns,
	                               .ns_part  = _get_ns_part(mod, ucmd_ctx, ns),
	                               .id_cat   = ns == KV_NS_DEVMOD ? KV_PREFIX_NS_MODULE_C : ID_NULL,
	                               .id       = ns == KV_NS_DEVMOD ? _get_ns_part(mod, ucmd_ctx, KV_NS_MODULE) : ID_NULL,
	                               .core     = key};
	return _cmd_get_key_spec_value(mod, ucmd_ctx, &key_spec, value_size, flags);
}

const void *sid_ucmd_get_kv(struct module          *mod,
                            struct sid_ucmd_ctx    *ucmd_ctx,
                            sid_ucmd_kv_namespace_t ns,
                            const char             *key,
                            size_t                 *value_size,
                            sid_ucmd_kv_flags_t    *flags,
                            unsigned int            archive)
{
	const char *dom;

	if (!mod || !ucmd_ctx || (ns == KV_NS_UNDEFINED) || !key || !*key || (key[0] == KV_PREFIX_KEY_SYS_C[0]))
		return NULL;

	if (ns == KV_NS_UDEV)
		dom = NULL;
	else
		dom = KV_KEY_DOM_USER;

	return _do_sid_ucmd_get_kv(mod, ucmd_ctx, dom, ns, key, value_size, flags, archive);
}

static const void *_do_sid_ucmd_get_foreign_kv(struct module          *mod,
                                               struct sid_ucmd_ctx    *ucmd_ctx,
                                               const char             *foreign_mod_name,
                                               const char             *foreign_dev_id,
                                               const char             *dom,
                                               sid_ucmd_kv_namespace_t ns,
                                               const char             *key,
                                               size_t                 *value_size,
                                               sid_ucmd_kv_flags_t    *flags,
                                               unsigned int            archive)
{
	struct kv_key_spec key_spec = {.extra_op = archive ? KV_PREFIX_OP_ARCHIVE_C : KV_PREFIX_OP_BLANK_C,
	                               .op       = KV_OP_SET,
	                               .dom      = dom ?: ID_NULL,
	                               .ns       = ns,
	                               .ns_part  = _get_foreign_ns_part(mod, ucmd_ctx, foreign_mod_name, foreign_dev_id, ns),
	                               .id_cat   = ns == KV_NS_DEVMOD ? KV_PREFIX_NS_MODULE_C : ID_NULL,
	                               .id       = ns == KV_NS_DEVMOD ? foreign_mod_name : ID_NULL,
	                               .core     = key};

	return _cmd_get_key_spec_value(mod, ucmd_ctx, &key_spec, value_size, flags);
}

const void *sid_ucmd_get_foreign_mod_kv(struct module          *mod,
                                        struct sid_ucmd_ctx    *ucmd_ctx,
                                        const char             *foreign_mod_name,
                                        sid_ucmd_kv_namespace_t ns,
                                        const char             *key,
                                        size_t                 *value_size,
                                        sid_ucmd_kv_flags_t    *flags,
                                        unsigned int            archive)
{
	const char *dom;

	if (!mod || !ucmd_ctx || !foreign_mod_name || !*foreign_mod_name || (ns == KV_NS_UNDEFINED) || !key || !*key ||
	    (key[0] == KV_PREFIX_KEY_SYS_C[0]))
		return NULL;

	dom = ns == KV_NS_UDEV ? NULL : KV_KEY_DOM_USER;

	return _do_sid_ucmd_get_foreign_kv(mod, ucmd_ctx, foreign_mod_name, NULL, dom, ns, key, value_size, flags, archive);
}

const void *sid_ucmd_get_foreign_dev_kv(struct module          *mod,
                                        struct sid_ucmd_ctx    *ucmd_ctx,
                                        const char             *foreign_dev_id,
                                        sid_ucmd_kv_namespace_t ns,
                                        const char             *key,
                                        size_t                 *value_size,
                                        sid_ucmd_kv_flags_t    *flags,
                                        unsigned int            archive)
{
	const char *dom;

	if (!mod || !ucmd_ctx || !foreign_dev_id || !*foreign_dev_id || (ns == KV_NS_UNDEFINED) || !key || !*key ||
	    (key[0] == KV_PREFIX_KEY_SYS_C[0]))
		return NULL;

	dom = ns == KV_NS_UDEV ? NULL : KV_KEY_DOM_USER;

	return _do_sid_ucmd_get_foreign_kv(mod, ucmd_ctx, NULL, foreign_dev_id, dom, ns, key, value_size, flags, archive);
}

const void *sid_ucmd_get_foreign_dev_mod_kv(struct module          *mod,
                                            struct sid_ucmd_ctx    *ucmd_ctx,
                                            const char             *foreign_dev_id,
                                            const char             *foreign_mod_name,
                                            sid_ucmd_kv_namespace_t ns,
                                            const char             *key,
                                            size_t                 *value_size,
                                            sid_ucmd_kv_flags_t    *flags,
                                            unsigned int            archive)
{
	const char *dom;

	if (!mod || !ucmd_ctx || !foreign_dev_id || !*foreign_dev_id || !foreign_mod_name || !*foreign_mod_name ||
	    (ns == KV_NS_UNDEFINED) || !key || !*key || (key[0] == KV_PREFIX_KEY_SYS_C[0]))
		return NULL;

	dom = ns == KV_NS_UDEV ? NULL : KV_KEY_DOM_USER;

	return _do_sid_ucmd_get_foreign_kv(mod,
	                                   ucmd_ctx,
	                                   foreign_mod_name,
	                                   foreign_dev_id,
	                                   dom,
	                                   ns,
	                                   key,
	                                   value_size,
	                                   flags,
	                                   archive);
}

int _do_sid_ucmd_mod_reserve_kv(struct module              *mod,
                                struct sid_ucmd_common_ctx *common,
                                const char                 *dom,
                                sid_ucmd_kv_namespace_t     ns,
                                const char                 *key_core,
                                sid_ucmd_kv_flags_t         flags,
                                int                         unset)
{
	const char          *owner = _get_mod_name(mod);
	char                *key   = NULL;
	kv_vector_t          vvalue[VVALUE_HEADER_CNT]; /* only header */
	struct kv_update_arg update_arg;
	int                  is_worker;
	struct kv_key_spec   key_spec = {.extra_op = NULL,
	                                 .op       = KV_OP_SET,
	                                 .dom      = dom ?: ID_NULL,
	                                 .ns       = ns,
	                                 .ns_part  = ID_NULL,
	                                 .id_cat   = ID_NULL,
	                                 .id       = ID_NULL,
	                                 .core     = key_core};
	int                  r        = -1;

	if (!(key = _compose_key(common->gen_buf, &key_spec)))
		goto out;

	if (!(common->kv_store_res))
		goto out;

	update_arg = (struct kv_update_arg) {.res      = common->kv_store_res,
	                                     .gen_buf  = NULL,
	                                     .owner    = owner,
	                                     .custom   = NULL,
	                                     .ret_code = -EREMOTEIO};

	/*
	 * FIXME: If possible, try to find out a way without calling worker_control_is_worker here.
	 *        Otherwise, this code assumes that we always have main process with main KV store
	 *        and worker processes with snapshots to sync. This doesn't necessarily need to
	 *        be true in all cases in the future!
	 */
	is_worker  = worker_control_is_worker(common->kv_store_res);

	if (!unset)
		flags |= KV_RS | KV_SYNC_P;

	if (unset && !is_worker) {
		if (kv_store_unset(common->kv_store_res, key, _kv_cb_reserve, &update_arg) < 0 || update_arg.ret_code < 0)
			goto out;
	} else {
		_vvalue_header_prep(vvalue, VVALUE_CNT(vvalue), &null_int, &flags, &common->gennum, (char *) owner);
		if (!kv_store_set_value(common->kv_store_res,
		                        key,
		                        vvalue,
		                        VVALUE_HEADER_CNT,
		                        KV_STORE_VALUE_VECTOR,
		                        KV_STORE_VALUE_OP_MERGE,
		                        _kv_cb_reserve,
		                        &update_arg))
			goto out;

		(void) _manage_kv_index(&update_arg, key);
	}

	r = 0;
out:
	_destroy_key(common->gen_buf, key);
	return r;
}

int sid_ucmd_mod_reserve_kv(struct module              *mod,
                            struct sid_ucmd_common_ctx *common,
                            sid_ucmd_kv_namespace_t     ns,
                            const char                 *key,
                            sid_ucmd_kv_flags_t         flags)
{
	const char *dom;

	if (!mod || !common || !key || !*key || (key[0] == KV_PREFIX_KEY_SYS_C[0]))
		return -EINVAL;

	dom = ns == KV_NS_UDEV ? NULL : KV_KEY_DOM_USER;

	return _do_sid_ucmd_mod_reserve_kv(mod, common, dom, ns, key, flags, 0);
}

int sid_ucmd_mod_unreserve_kv(struct module *mod, struct sid_ucmd_common_ctx *common, sid_ucmd_kv_namespace_t ns, const char *key)
{
	const char *dom;

	if (!mod || !common || !key || !*key || (key[0] == KV_PREFIX_KEY_SYS_C[0]))
		return -EINVAL;

	dom = ns == KV_NS_UDEV ? NULL : KV_KEY_DOM_USER;

	return _do_sid_ucmd_mod_reserve_kv(mod, common, dom, ns, key, KV_FLAGS_UNSET, 1);
}

static sid_resource_t *_get_mod_res_from_mod(struct module *mod, sid_resource_t *modules_res, int *ret_code)
{
	sid_resource_t *res   = NULL;
	char          **pathv = NULL, **name;
	int             r     = 0;

	if (!(pathv = util_str_comb_to_strv(NULL, NULL, module_get_full_name(mod), NULL, MODULE_NAME_DELIM, NULL))) {
		r = -ENOMEM;
		goto out;
	}

	for (res = modules_res, name = pathv; *name; name++) {
		if (!(res = sid_resource_search(res, SID_RESOURCE_SEARCH_IMM_DESC, NULL, *name))) {
			r = -ENOLINK;
			goto out;
		}
	}
out:
	free(pathv);

	if (ret_code)
		*ret_code = r;
	return res;
}

int sid_ucmd_mod_add_subresource(struct module *mod, struct sid_ucmd_common_ctx *common, sid_resource_t *mod_subresource)
{
	sid_resource_t *res;
	int             r;

	if (!mod || !common || !mod_subresource)
		return -EINVAL;

	if (!(res = _get_mod_res_from_mod(mod, common->modules_res, &r)))
		return r;

	if (sid_resource_match(mod_subresource, &sid_resource_type_module_registry, NULL))
		return module_registry_add_module_subregistry(res, mod_subresource);

	return sid_resource_add_child(res, mod_subresource, SID_RESOURCE_RESTRICT_WALK_UP);
}

const char *sid_ucmd_dev_ready_to_str(dev_ready_t ready)
{
	return dev_ready_str[ready];
}

int sid_ucmd_dev_set_ready(struct module *mod, struct sid_ucmd_ctx *ucmd_ctx, dev_ready_t ready)
{
	dev_ready_t old_ready;

	if (!ucmd_ctx)
		return -EINVAL;

	if (!(_cmd_scan_phase_regs[ucmd_ctx->scan.phase].flags & CMD_SCAN_CAP_RDY))
		return -EPERM;

	if ((old_ready = ucmd_ctx->scan.dev_ready) == ready)
		return 0;

	switch (ready) {
		case DEV_RDY_UNDEFINED:
			return -EBADRQC;

		case DEV_RDY_UNPROCESSED:
			if (old_ready != DEV_RDY_UNDEFINED)
				return -EBADRQC;
			break;

		case DEV_RDY_UNCONFIGURED:
			if (old_ready != DEV_RDY_UNPROCESSED)
				return -EBADRQC;
			break;

		case DEV_RDY_UNINITIALIZED:
			if (old_ready != DEV_RDY_UNPROCESSED && old_ready != DEV_RDY_UNCONFIGURED)
				return -EBADRQC;
			break;

		case DEV_RDY_UNAVAILABLE:
			if (old_ready != DEV_RDY_PUBLIC && old_ready != DEV_RDY_PRIVATE)
				return -EBADRQC;
			break;

		case DEV_RDY_PRIVATE:
		case DEV_RDY_PUBLIC:
			if (old_ready != DEV_RDY_UNPROCESSED && old_ready != DEV_RDY_UNCONFIGURED &&
			    old_ready != DEV_RDY_UNINITIALIZED && old_ready != DEV_RDY_UNAVAILABLE)
				return -EBADRQC;
			break;
	}

	if (!_do_sid_ucmd_set_kv(mod,
	                         ucmd_ctx,
	                         NULL,
	                         KV_NS_DEVICE,
	                         KV_KEY_DEV_READY,
	                         KV_SYNC | KV_AR | KV_RD | KV_SUB_WR | KV_SUP_WR,
	                         &ready,
	                         sizeof(ready)))
		return -1;

	ucmd_ctx->scan.dev_ready = ready;
	return 0;
}

dev_ready_t sid_ucmd_dev_get_ready(struct module *mod, struct sid_ucmd_ctx *ucmd_ctx, unsigned int archive)
{
	const void *val;
	dev_ready_t ready_arch;

	if (!ucmd_ctx)
		return DEV_RDY_UNDEFINED;

	if (archive) {
		if ((val = _do_sid_ucmd_get_kv(mod, ucmd_ctx, NULL, KV_NS_DEVICE, KV_KEY_DEV_READY, NULL, NULL, archive)))
			memcpy(&ready_arch, val, sizeof(dev_ready_t));
		else
			ready_arch = DEV_RDY_UNDEFINED;

		return ready_arch;
	}

	if (ucmd_ctx->scan.dev_ready == DEV_RDY_UNDEFINED) {
		if ((val = _do_sid_ucmd_get_kv(mod, ucmd_ctx, NULL, KV_NS_DEVICE, KV_KEY_DEV_READY, NULL, NULL, 0)))
			memcpy(&ucmd_ctx->scan.dev_ready, val, sizeof(dev_ready_t));
	}

	return ucmd_ctx->scan.dev_ready;
}

int sid_ucmd_dev_set_reserved(struct module *mod, struct sid_ucmd_ctx *ucmd_ctx, dev_reserved_t reserved)
{
	if (!mod || !ucmd_ctx || (reserved == DEV_RES_UNDEFINED))
		return -EINVAL;

	if (!(_cmd_scan_phase_regs[ucmd_ctx->scan.phase].flags & CMD_SCAN_CAP_RES))
		return -EPERM;

	_do_sid_ucmd_set_kv(NULL,
	                    ucmd_ctx,
	                    NULL,
	                    KV_NS_DEVICE,
	                    KV_KEY_DEV_RESERVED,
	                    DEFAULT_VALUE_FLAGS_CORE,
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

	if (!(p_reserved = _do_sid_ucmd_get_kv(NULL, ucmd_ctx, NULL, KV_NS_DEVICE, KV_KEY_DEV_RESERVED, NULL, NULL, 0)))
		result = DEV_RES_UNPROCESSED;
	else
		result = *p_reserved;

	return result;
}

static int _handle_dev_for_group(struct module          *mod,
                                 struct sid_ucmd_ctx    *ucmd_ctx,
                                 const char             *dev_id,
                                 const char             *dom,
                                 sid_ucmd_kv_namespace_t group_ns,
                                 const char             *group_cat,
                                 const char             *group_id,
                                 kv_op_t                 op)
{
	char       *key            = NULL;
	const char *rel_key_prefix = NULL;
	kv_vector_t vvalue[VVALUE_SINGLE_CNT];
	int         r               = -1;

	struct kv_rel_spec rel_spec = {
		.delta        = &((struct kv_delta) {.op = op, .flags = DELTA_WITH_DIFF | DELTA_WITH_REL}),

		.abs_delta    = &((struct kv_delta) {0}),

		.cur_key_spec = &((struct kv_key_spec) {.extra_op = NULL,
	                                                .op       = KV_OP_SET,
	                                                .dom      = dom ?: ID_NULL,
	                                                .ns       = group_ns,
	                                                .ns_part  = _get_ns_part(mod, ucmd_ctx, KV_NS_MODULE),
	                                                .id_cat   = group_cat,
	                                                .id       = group_id,
	                                                .core     = KV_KEY_GEN_GROUP_MEMBERS}),

		.rel_key_spec = &((struct kv_key_spec) {.extra_op = NULL,
	                                                .op       = KV_OP_SET,
	                                                .dom      = ID_NULL,
	                                                .ns       = KV_NS_DEVICE,
	                                                .ns_part  = dev_id ?: _get_ns_part(mod, ucmd_ctx, KV_NS_DEVICE),
	                                                .id_cat   = ID_NULL,
	                                                .id       = ID_NULL,
	                                                .core     = KV_KEY_GEN_GROUP_IN})};

	struct kv_update_arg update_arg = {.res     = ucmd_ctx->common->kv_store_res,
	                                   .owner   = OWNER_CORE,
	                                   .gen_buf = ucmd_ctx->common->gen_buf,
	                                   .custom  = &rel_spec};

	// TODO: check return values / maybe also pass flags / use proper owner

	if (!(key = _compose_key(NULL, rel_spec.cur_key_spec)))
		goto out;

	if (!(rel_key_prefix = _compose_key_prefix(NULL, rel_spec.rel_key_spec)))
		goto out;

	_vvalue_header_prep(vvalue,
	                    VVALUE_CNT(vvalue),
	                    &ucmd_ctx->req_env.dev.udev.seqnum,
	                    &value_flags_no_sync,
	                    &ucmd_ctx->common->gennum,
	                    core_owner);
	_vvalue_data_prep(vvalue, VVALUE_CNT(vvalue), 0, (void *) rel_key_prefix, strlen(rel_key_prefix) + 1);

	if (_kv_delta_set(key, vvalue, VVALUE_SINGLE_CNT, &update_arg, true) < 0)
		goto out;

	r = 0;
out:
	_destroy_key(NULL, key);
	_destroy_key(NULL, rel_key_prefix);
	return r;
}

int sid_ucmd_dev_add_alias(struct module *mod, struct sid_ucmd_ctx *ucmd_ctx, const char *alias_cat, const char *alias_id)
{
	if (!mod || !ucmd_ctx || !alias_cat || !*alias_cat || !alias_id || !*alias_id)
		return -EINVAL;

	return _handle_dev_for_group(mod, ucmd_ctx, NULL, KV_KEY_DOM_ALIAS, KV_NS_MODULE, alias_cat, alias_id, KV_OP_PLUS);
}

int sid_ucmd_dev_remove_alias(struct module *mod, struct sid_ucmd_ctx *ucmd_ctx, const char *alias_cat, const char *alias_id)
{
	if (!mod || !ucmd_ctx || !alias_cat || !*alias_cat || !alias_id || !*alias_id)
		return -EINVAL;

	return _handle_dev_for_group(mod, ucmd_ctx, NULL, KV_KEY_DOM_ALIAS, KV_NS_MODULE, alias_cat, alias_id, KV_OP_MINUS);
}

static int _kv_cb_write_new_only(struct kv_store_update_spec *spec)
{
	if (spec->old_data)
		return 0;

	return _kv_cb_write(spec);
}

static int _do_sid_ucmd_group_create(struct module          *mod,
                                     struct sid_ucmd_ctx    *ucmd_ctx,
                                     const char             *dom,
                                     sid_ucmd_kv_namespace_t group_ns,
                                     sid_ucmd_kv_flags_t     group_flags,
                                     const char             *group_cat,
                                     const char             *group_id)
{
	const char *owner = _get_mod_name(mod);
	char       *key   = NULL;
	kv_vector_t vvalue[VVALUE_HEADER_CNT];
	int         r                   = -1;

	struct kv_key_spec key_spec     = {.extra_op = NULL,
	                                   .op       = KV_OP_SET,
	                                   .dom      = dom ?: ID_NULL,
	                                   .ns       = group_ns,
	                                   .ns_part  = _get_ns_part(mod, ucmd_ctx, group_ns),
	                                   .id_cat   = group_cat,
	                                   .id       = group_id,
	                                   .core     = KV_KEY_GEN_GROUP_MEMBERS};

	struct kv_update_arg update_arg = {.res      = ucmd_ctx->common->kv_store_res,
	                                   .owner    = owner,
	                                   .gen_buf  = ucmd_ctx->common->gen_buf,
	                                   .custom   = NULL,
	                                   .ret_code = 0};

	if (!(key = _compose_key(ucmd_ctx->common->gen_buf, &key_spec)))
		goto out;

	_vvalue_header_prep(vvalue,
	                    VVALUE_CNT(vvalue),
	                    &ucmd_ctx->req_env.dev.udev.seqnum,
	                    &group_flags,
	                    &ucmd_ctx->common->gennum,
	                    (char *) owner);

	if (!kv_store_set_value(ucmd_ctx->common->kv_store_res,
	                        key,
	                        vvalue,
	                        VVALUE_HEADER_CNT,
	                        KV_STORE_VALUE_VECTOR,
	                        KV_STORE_VALUE_NO_OP,
	                        _kv_cb_write_new_only,
	                        &update_arg))
		goto out;

	(void) _manage_kv_index(&update_arg, key);

	r = 0;
out:
	_destroy_key(ucmd_ctx->common->gen_buf, key);
	return r;
}

int sid_ucmd_group_create(struct module          *mod,
                          struct sid_ucmd_ctx    *ucmd_ctx,
                          sid_ucmd_kv_namespace_t group_ns,
                          sid_ucmd_kv_flags_t     group_flags,
                          const char             *group_cat,
                          const char             *group_id)
{
	if (!mod || !ucmd_ctx || (group_ns == KV_NS_UNDEFINED) || !group_id || !*group_id)
		return -EINVAL;

	group_flags &= ~KV_ALIGN;

	return _do_sid_ucmd_group_create(mod, ucmd_ctx, KV_KEY_DOM_GROUP, group_ns, group_flags, group_cat, group_id);
}

int sid_ucmd_group_add_current_dev(struct module          *mod,
                                   struct sid_ucmd_ctx    *ucmd_ctx,
                                   sid_ucmd_kv_namespace_t group_ns,
                                   const char             *group_cat,
                                   const char             *group_id)
{
	if (!mod || !ucmd_ctx || (group_ns == KV_NS_UNDEFINED) || !group_cat || !*group_cat || !group_id || !*group_id)
		return -EINVAL;

	return _handle_dev_for_group(mod, ucmd_ctx, NULL, KV_KEY_DOM_GROUP, group_ns, group_cat, group_id, KV_OP_PLUS);
}

int sid_ucmd_group_remove_current_dev(struct module          *mod,
                                      struct sid_ucmd_ctx    *ucmd_ctx,
                                      sid_ucmd_kv_namespace_t group_ns,
                                      const char             *group_cat,
                                      const char             *group_id)
{
	if (!mod || !ucmd_ctx || (group_ns == KV_NS_UNDEFINED) || !group_cat || !*group_cat || !group_id || !*group_id)
		return -EINVAL;

	return _handle_dev_for_group(mod, ucmd_ctx, NULL, KV_KEY_DOM_GROUP, group_ns, group_cat, group_id, KV_OP_MINUS);
}

static int _do_sid_ucmd_group_destroy(struct module          *mod,
                                      struct sid_ucmd_ctx    *ucmd_ctx,
                                      const char             *dom,
                                      sid_ucmd_kv_namespace_t group_ns,
                                      const char             *group_cat,
                                      const char             *group_id,
                                      int                     force)
{
	static sid_ucmd_kv_flags_t kv_flags_sync_no_reserved = (DEFAULT_VALUE_FLAGS_CORE) & ~KV_RS;
	char                      *key                       = NULL;
	size_t                     size;
	kv_vector_t                vvalue[VVALUE_HEADER_CNT];
	int                        r = -1;

	struct kv_rel_spec rel_spec  = {.delta = &((struct kv_delta) {.op = KV_OP_SET, .flags = DELTA_WITH_DIFF | DELTA_WITH_REL}),
	                                .abs_delta    = &((struct kv_delta) {0}),

	                                .cur_key_spec = &((struct kv_key_spec) {.extra_op = NULL,
	                                                                        .op       = KV_OP_SET,
	                                                                        .dom      = dom ?: ID_NULL,
	                                                                        .ns       = group_ns,
	                                                                        .ns_part  = _get_ns_part(mod, ucmd_ctx, group_ns),
	                                                                        .id_cat   = group_cat,
	                                                                        .id       = group_id,
	                                                                        .core     = KV_KEY_GEN_GROUP_MEMBERS}),

	                                .rel_key_spec = &((struct kv_key_spec) {.extra_op = NULL,
	                                                                        .op       = KV_OP_SET,
	                                                                        .dom      = ID_NULL,
	                                                                        .ns       = 0,
	                                                                        .ns_part  = ID_NULL,
	                                                                        .id_cat   = ID_NULL,
	                                                                        .id       = ID_NULL,
	                                                                        .core     = KV_KEY_GEN_GROUP_IN})};

	struct kv_update_arg update_arg = {.res     = ucmd_ctx->common->kv_store_res,
	                                   .owner   = OWNER_CORE,
	                                   .gen_buf = ucmd_ctx->common->gen_buf,
	                                   .custom  = &rel_spec};

	// TODO: do not call kv_store_get_value, only kv_store_set_value and provide _kv_cb_delta wrapper
	//       to do the "is empty?" check before the actual _kv_cb_delta operation

	if (!(key = _compose_key(ucmd_ctx->common->gen_buf, rel_spec.cur_key_spec)))
		goto out;

	if (!kv_store_get_value(ucmd_ctx->common->kv_store_res, key, &size, NULL))
		goto out;

	if (size > VVALUE_HEADER_CNT && !force) {
		r = -ENOTEMPTY;
		goto out;
	}

	_vvalue_header_prep(vvalue,
	                    VVALUE_CNT(vvalue),
	                    &ucmd_ctx->req_env.dev.udev.seqnum,
	                    &kv_flags_sync_no_reserved,
	                    &ucmd_ctx->common->gennum,
	                    core_owner);

	if ((r = _kv_delta_set(key, vvalue, VVALUE_HEADER_CNT, &update_arg, true)) < 0)
		goto out;

	r = 0;
out:
	_destroy_key(ucmd_ctx->common->gen_buf, key);
	return r;
}

int sid_ucmd_group_destroy(struct module          *mod,
                           struct sid_ucmd_ctx    *ucmd_ctx,
                           sid_ucmd_kv_namespace_t group_ns,
                           const char             *group_cat,
                           const char             *group_id,
                           int                     force)
{
	if (!mod || !ucmd_ctx || (group_ns == KV_NS_UNDEFINED) || !group_id || !*group_id)
		return -EINVAL;

	return _do_sid_ucmd_group_destroy(mod, ucmd_ctx, KV_KEY_DOM_GROUP, group_ns, group_cat, group_id, force);
}

static int _device_add_field(struct sid_ucmd_ctx *ucmd_ctx, const char *start)
{
	const char *key;
	const char *value;

	if (!(value = strchr(start, KV_PAIR_C[0])) || !*(++value))
		return -1;

	if (asprintf((char **) &key, "%.*s", (int) (value - start - 1), start) < 0)
		return -1;

	if (!(value = _do_sid_ucmd_set_kv(NULL, ucmd_ctx, NULL, KV_NS_UDEV, key, KV_RD | KV_WR, value, strlen(value) + 1)))
		return -1;

	log_debug(ID(ucmd_ctx->common->kv_store_res), "Imported udev property %s=%s", key, value);

	/* Common key=value pairs are also directly in the ucmd_ctx->udev_dev structure. */
	if (!strcmp(key, UDEV_KEY_ACTION))
		ucmd_ctx->req_env.dev.udev.action = util_udev_str_to_udev_action(value);
	else if (!strcmp(key, UDEV_KEY_DEVPATH)) {
		ucmd_ctx->req_env.dev.udev.path = value;
		ucmd_ctx->req_env.dev.udev.name = util_str_rstr(value, "/");
		ucmd_ctx->req_env.dev.udev.name++;
	} else if (!strcmp(key, UDEV_KEY_DEVTYPE))
		ucmd_ctx->req_env.dev.udev.type = util_udev_str_to_udev_devtype(value);
	else if (!strcmp(key, UDEV_KEY_SEQNUM))
		ucmd_ctx->req_env.dev.udev.seqnum = strtoull(value, NULL, 10);
	else if (!strcmp(key, UDEV_KEY_DISKSEQ))
		ucmd_ctx->req_env.dev.udev.diskseq = strtoull(value, NULL, 10);
	else if (!strcmp(key, UDEV_KEY_SYNTH_UUID))
		ucmd_ctx->req_env.dev.udev.synth_uuid = value;

	free((void *) key);
	return 0;
};

static int _parse_cmd_udev_env(struct sid_ucmd_ctx *ucmd_ctx, const char *env, size_t env_size)
{
	dev_t       devno;
	const char *end;
	int         r = 0;

	if (env_size <= sizeof(devno)) {
		r = -EINVAL;
		goto out;
	}

	memcpy(&devno, env, sizeof(devno));
	ucmd_ctx->req_env.dev.udev.major = major(devno);
	ucmd_ctx->req_env.dev.udev.minor = minor(devno);

	if (asprintf(&ucmd_ctx->req_env.dev.num_s, "%d_%d", ucmd_ctx->req_env.dev.udev.major, ucmd_ctx->req_env.dev.udev.minor) <
	    0) {
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

static char *_canonicalize_kv_key(char *id)
{
	char *p = id;

	while (*p) {
		if (*p == ':')
			*p = '_';
		p++;
	}

	return id;
}

int _part_get_whole_disk(struct module *mod, struct sid_ucmd_ctx *ucmd_ctx, char *devno_buf, size_t devno_buf_size)
{
	const char *s;
	int         r;

	if ((r = sid_buffer_fmt_add(ucmd_ctx->common->gen_buf,
	                            (const void **) &s,
	                            NULL,
	                            "%s%s/../dev",
	                            SYSTEM_SYSFS_PATH,
	                            ucmd_ctx->req_env.dev.udev.path)) < 0) {
		log_error_errno(_get_mod_name(mod),
		                r,
		                "Failed to compose sysfs path for whole device of partition device " CMD_DEV_NAME_NUM_FMT,
		                CMD_DEV_NAME_NUM(ucmd_ctx));
		return r;
	}

	if ((r = sid_util_sysfs_get_value(s, devno_buf, devno_buf_size)) < 0 || !*devno_buf)
		log_error_errno(_get_mod_name(mod), r, "Failed to read whole disk device number from sysfs file %s.", s);

	sid_buffer_rewind_mem(ucmd_ctx->common->gen_buf, s);
	return r;
}

static int _dev_is_nvme(struct sid_ucmd_ctx *ucmd_ctx)
{
	/*
	 * FIXME: Is there any better and quick way of detecting we have
	 * 	  an NVMe device than just looking at its kernel name?
	 */
	return !strncmp(sid_ucmd_event_get_dev_name(ucmd_ctx), DEV_NAME_PREFIX_NVME, sizeof(DEV_NAME_PREFIX_NVME) - 1);
}

static char *_lookup_mod_name(sid_resource_t *cmd_res, const int dev_major, const char *dev_name, char *buf, size_t buf_size);

static char *_get_mod_name_from_blkext(sid_resource_t *cmd_res, char *buf, size_t buf_size)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_resource_get_data(cmd_res);
	char                 devno_buf[16];
	int                  dev_major;
	char                *p;
	char                *mod_name;

	switch (sid_ucmd_event_get_dev_type(ucmd_ctx)) {
		case UDEV_DEVTYPE_PARTITION:
			/*
			 * First, check if this is a partition on top of an NVMe device.
			 * If this is the case, then we directly return MOD_NAME_NVME
			 * because whole device for an NVMe blkext partition is a device
			 * of blkext type again so _lookup_mod_name wouldn't work here.
			 */
			if (_dev_is_nvme(ucmd_ctx))
				return MOD_NAME_NVME;

			/* Otherwise, get whole disk device and then lookup its module name. */
			if (_part_get_whole_disk(NULL, ucmd_ctx, devno_buf, sizeof(devno_buf)) < 0)
				return NULL;

			if (!(p = index(devno_buf, ':')))
				return NULL;

			*p = '\0';
			if (!(dev_major = atoi(devno_buf)))
				return NULL;
			*p = ':';

			if (!(mod_name = _lookup_mod_name(cmd_res, dev_major, devno_buf, buf, buf_size)))
				return NULL;

			if (strncmp(mod_name, MOD_NAME_BLKEXT, sizeof(MOD_NAME_BLKEXT)))
				/*
				 * Something's wrong - we got blkext again!
				 * Looks like we're missing special treatment for a device which has
				 * blkext for both partitions and whole devices (like it is with NVMe).
				 */
				return NULL;

			return mod_name;

		case UDEV_DEVTYPE_DISK:
			/* NVMe whole disk is of blkext type. */
			return _dev_is_nvme(ucmd_ctx) ? MOD_NAME_NVME : NULL;

		case UDEV_DEVTYPE_UNKNOWN:
			break;
	}

	return NULL;
}

/*
 *  Module name is equal to the name as exposed in SYSTEM_PROC_DEVICES_PATH.
 */
static char *_lookup_mod_name(sid_resource_t *cmd_res, const int dev_major, const char *dev_name, char *buf, size_t buf_size)
{
	char  *p, *end, *found = NULL, *mod_name = NULL;
	FILE  *f = NULL;
	char   line[80];
	int    in_block_section = 0;
	int    major;
	size_t len;

	if (!(f = fopen(SYSTEM_PROC_DEVICES_PATH, "r"))) {
		log_sys_error(ID(cmd_res), "fopen", SYSTEM_PROC_DEVICES_PATH);
		goto out;
	}

	/*
	 *  FIXME: Maybe cache this so we don't need to parse the file again
	 *  	   on next lookup and reread the file/refresh the cache only
	 *  	   if we don't find the device in the cache.
	 */
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
		if (major == dev_major) {
			found = end + 1;
			break;
		}
	}

	if (!found) {
		log_error(ID(cmd_res),
		          "Unable to find major number %d for device %s in %s.",
		          dev_major,
		          dev_name,
		          SYSTEM_PROC_DEVICES_PATH);
		goto out;
	}

	p = found;
	while (isprint(*p))
		p++;
	p[0] = '\0';

	if (!strncmp(found, MOD_NAME_BLKEXT, sizeof(MOD_NAME_BLKEXT))) {
		if (!(found = _get_mod_name_from_blkext(cmd_res, buf, buf_size))) {
			log_error(ID(cmd_res), "Failed to get module name for blkext device.");
			goto out;
		}
		len = strlen(found);
	} else
		len = p - found;

	if (len >= buf_size) {
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
	mod_name = buf;
out:
	if (f)
		fclose(f);

	return mod_name;
}

static int _connection_cleanup(sid_resource_t *conn_res)
{
	sid_resource_t *worker_res = sid_resource_search(conn_res, SID_RESOURCE_SEARCH_IMM_ANC, NULL, NULL);

	sid_resource_unref(conn_res);

	// TODO: If there are more connections per worker used,
	// 	 then check if this is the last connection.
	// 	 If it's not the last one, then do not yield the worker.

	(void) worker_control_worker_yield(worker_res);

	return 0;
}

static void _change_cmd_state(sid_resource_t *cmd_res, cmd_state_t state)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_resource_get_data(cmd_res);

	ucmd_ctx->state               = state;
	log_debug(ID(cmd_res), "Command state changed to %s.", cmd_state_str[state]);
}

static int _cmd_exec_version(struct cmd_exec_arg *exec_arg)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_resource_get_data(exec_arg->cmd_res);
	struct sid_buffer   *prn_buf  = ucmd_ctx->prn_buf;
	char                *version_data;
	size_t               size;
	output_format_t      format = flags_to_format(ucmd_ctx->req_hdr.flags);

	print_start_document(format, prn_buf, 0);
	print_uint_field(format, prn_buf, 1, "SID_PROTOCOL", SID_PROTOCOL, false);
	print_uint_field(format, prn_buf, 1, "SID_MAJOR", SID_VERSION_MAJOR, true);
	print_uint_field(format, prn_buf, 1, "SID_MINOR", SID_VERSION_MINOR, true);
	print_uint_field(format, prn_buf, 1, "SID_RELEASE", SID_VERSION_RELEASE, true);
	print_end_document(format, prn_buf, 0);
	print_null_byte(prn_buf);

	sid_buffer_get_data(prn_buf, (const void **) &version_data, &size);

	return sid_buffer_add(ucmd_ctx->res_buf, version_data, size, NULL, NULL);
}

static int _cmd_exec_resources(struct cmd_exec_arg *exec_arg)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_resource_get_data(exec_arg->cmd_res);
	struct sid_buffer   *gen_buf  = ucmd_ctx->common->gen_buf;
	struct sid_buffer   *prn_buf  = ucmd_ctx->prn_buf;
	output_format_t      format;
	const char          *id;
	size_t               buf_pos0, buf_pos1, buf_pos2;
	char                *data;
	size_t               size;
	int                  r = -1;

	// TODO: check return values from all sid_buffer_* and error out properly on error

	/*
	 * This handler is scheduled twice:
	 * 	- right after we received the request to process the command from client
	 * 	  (resources.main_res_mem is not set yet)
	 *
	 * 	- after we received the result of resource dump from main process
	 * 	  (resources.main_res_mem is set already)
	 */
	if (ucmd_ctx->resources.main_res_mem == NULL) {
		/*
		 * We don't have the result from main process yet - send request to
		 * the main process to dump and send back its resources tree.
		 *
		 * We will receive response in _worker_recv_fn/_worker_recv_system_cmd_resources.
		 * For us to be able to lookup the cmd resource the original request came from,
		 * we also need to send this cmd resource's id withing the request - it is sent
		 * right after the struct internal_msg_header.
		 */
		id = sid_resource_get_id(exec_arg->cmd_res);

		sid_buffer_add(gen_buf,
		               &(struct internal_msg_header) {.cat = MSG_CATEGORY_SYSTEM,
		                                              .header =
		                                                      (struct sid_msg_header) {
									      .status = 0,
									      .prot   = 0,
									      .cmd    = SYSTEM_CMD_RESOURCES,
									      .flags  = ucmd_ctx->req_hdr.flags,
								      }},
		               INTERNAL_MSG_HEADER_SIZE,
		               NULL,
		               &buf_pos0);
		sid_buffer_add(gen_buf, (void *) id, strlen(id) + 1, NULL, NULL);
		sid_buffer_get_data_from(gen_buf, buf_pos0, (const void **) &data, &size);

		if ((r = worker_control_channel_send(exec_arg->cmd_res,
		                                     MAIN_WORKER_CHANNEL_ID,
		                                     &(struct worker_data_spec) {
							     .data      = data,
							     .data_size = size,
							     .ext.used  = false,
						     })) < 0) {
			log_error_errno(ID(exec_arg->cmd_res),
			                r,
			                "Failed to sent request to main process to write its resource tree.");
			r = -1;
		} else
			_change_cmd_state(exec_arg->cmd_res, CMD_EXPECTING_DATA);

		sid_buffer_rewind(gen_buf, buf_pos0, SID_BUFFER_POS_ABS);
		return r;
	}

	if (ucmd_ctx->resources.main_res_mem == MAP_FAILED)
		goto out;

	/*
	 * At this point, we already have received resource tree dump from
	 * main process and so we are able to add both the resource tree from
	 * main process as well as this process' resource tree to result buffer.
	 *
	 * The resulting output is composed of 3 parts:
	 *   - start element + start array                                             (in prn_buf)
	 *   - the resource tree from main process                                     (in mmap'd memfd sent from main process)
	 *   - the resource tree from current worker process + array end + end element (in prn_buf)
	 */
	format   = flags_to_format(ucmd_ctx->req_hdr.flags);

	buf_pos0 = sid_buffer_count(prn_buf);
	print_start_elem(format, prn_buf, 0, false);
	print_start_array(format, prn_buf, 1, "sidresources", false);
	buf_pos1 = sid_buffer_count(prn_buf);

	sid_resource_write_tree_recursively(sid_resource_search(exec_arg->cmd_res, SID_RESOURCE_SEARCH_TOP, NULL, NULL),
	                                    format,
	                                    prn_buf,
	                                    2,
	                                    true);

	print_end_array(format, prn_buf, 1);
	print_end_elem(format, prn_buf, 0);
	print_null_byte(prn_buf);
	buf_pos2 = sid_buffer_count(prn_buf);

	sid_buffer_get_data(prn_buf, (const void **) &data, &size);

	sid_buffer_add(ucmd_ctx->res_buf, data + buf_pos0, buf_pos1 - buf_pos0, NULL, NULL);
	sid_buffer_add(ucmd_ctx->res_buf,
	               ucmd_ctx->resources.main_res_mem + SID_BUFFER_SIZE_PREFIX_LEN,
	               ucmd_ctx->resources.main_res_mem_size - SID_BUFFER_SIZE_PREFIX_LEN,
	               NULL,
	               NULL);
	sid_buffer_add(ucmd_ctx->res_buf, data + buf_pos1, buf_pos2 - buf_pos1, NULL, NULL);

	r = 0;
out:
	ucmd_ctx->resources.main_res_mem      = NULL;
	ucmd_ctx->resources.main_res_mem_size = 0;
	_change_cmd_state(exec_arg->cmd_res, CMD_EXEC_FINISHED);
	return r;
}

static const char *_sval_to_dev_ready_str(kv_scalar_t *val)
{
	dev_ready_t ready;

	memcpy(&ready, val->data + _svalue_ext_data_offset(val), sizeof(ready));
	return dev_ready_str[ready];
}

static int _cmd_exec_devices(struct cmd_exec_arg *exec_arg)
{
	char                   uuid_buf1[UTIL_UUID_STR_SIZE];
	char                   uuid_buf2[UTIL_UUID_STR_SIZE];
	struct sid_ucmd_ctx   *ucmd_ctx = sid_resource_get_data(exec_arg->cmd_res);
	output_format_t        format   = flags_to_format(ucmd_ctx->req_hdr.flags);
	struct sid_buffer     *prn_buf  = ucmd_ctx->prn_buf;
	kv_vector_t            tmp_vvalue[VVALUE_SINGLE_CNT];
	kv_store_iter_t       *iter;
	void                  *data;
	size_t                 size;
	kv_store_value_flags_t kv_store_value_flags;
	const char            *key, *key_core;
	char                  *prev_uuid, *uuid;
	kv_vector_t           *vvalue;
	bool                   with_comma = false;
	int                    r          = 0;

	prev_uuid                         = uuid_buf1;
	uuid                              = uuid_buf2;

	if (!(iter = kv_store_iter_create(ucmd_ctx->common->kv_store_res, "::D:", "::E:")))
		goto out;

	print_start_document(format, prn_buf, 0);
	print_start_array(format, prn_buf, 1, "siddevices", false);

	prev_uuid[0] = 0;

	while ((data = kv_store_iter_next(iter, &size, &key, &kv_store_value_flags))) {
		if (!_copy_ns_part_from_key(key, uuid, sizeof(uuid_buf1)))
			continue;

		if (!(key_core = _get_key_part(key, KEY_PART_CORE, NULL)))
			continue;

		if (strcmp(prev_uuid, uuid)) {
			if (prev_uuid[0] != 0)
				print_end_elem(format, prn_buf, 2);
			print_start_elem(format, prn_buf, 2, with_comma);
			print_str_field(format, prn_buf, 3, "DEVID", uuid, false);
		}

		if (!strcmp(key_core, KV_KEY_GEN_GROUP_IN) || !strcmp(key_core, KV_KEY_GEN_GROUP_MEMBERS) ||
		    !strcmp(key_core, KV_KEY_DEV_RESERVED)) {
			vvalue = _get_vvalue(kv_store_value_flags, data, size, tmp_vvalue, VVALUE_CNT(tmp_vvalue));
			_print_vvalue(vvalue, kv_store_value_flags & KV_STORE_VALUE_VECTOR, size, key_core, format, prn_buf, 3);
		} else if (!strcmp(key_core, KV_KEY_DEV_READY)) {
			print_str_field(format, prn_buf, 3, KV_KEY_DEV_READY, _sval_to_dev_ready_str(data), with_comma);
		}

		UTIL_SWAP(uuid, prev_uuid);
		with_comma = true;
	}

	if (prev_uuid[0] != 0)
		print_end_elem(format, prn_buf, 2);

	print_end_array(format, prn_buf, 1);
	print_end_document(format, prn_buf, 0);
	print_null_byte(prn_buf);

	sid_buffer_get_data(prn_buf, (const void **) &data, &size);
	r = sid_buffer_add(ucmd_ctx->res_buf, data, size, NULL, NULL);
out:
	if (iter)
		kv_store_iter_destroy(iter);

	return r;
}

static int _cmd_exec_dbstats(struct cmd_exec_arg *exec_arg)
{
	int                  r;
	struct sid_ucmd_ctx *ucmd_ctx = sid_resource_get_data(exec_arg->cmd_res);
	struct sid_buffer   *prn_buf  = ucmd_ctx->prn_buf;
	struct sid_dbstats   stats;
	char                *stats_data;
	size_t               size;
	output_format_t      format = flags_to_format(ucmd_ctx->req_hdr.flags);

	if ((r = _write_kv_store_stats(&stats, ucmd_ctx->common->kv_store_res)) == 0) {
		print_start_document(format, prn_buf, 0);

		print_uint64_field(format, prn_buf, 1, "KEYS_SIZE", stats.key_size, false);
		print_uint64_field(format, prn_buf, 1, "VALUES_INTERNAL_SIZE", stats.value_int_size, true);
		print_uint64_field(format, prn_buf, 1, "VALUES_INTERNAL_DATA_SIZE", stats.value_int_data_size, true);
		print_uint64_field(format, prn_buf, 1, "VALUES_EXTERNAL_SIZE", stats.value_ext_size, true);
		print_uint64_field(format, prn_buf, 1, "VALUES_EXTERNAL_DATA_SIZE", stats.value_ext_data_size, true);
		print_uint64_field(format, prn_buf, 1, "METADATA_SIZE", stats.meta_size, true);
		print_uint_field(format, prn_buf, 1, "NR_KEY_VALUE_PAIRS", stats.nr_kv_pairs, true);

		print_end_document(format, prn_buf, 0);
		print_null_byte(prn_buf);

		sid_buffer_get_data(prn_buf, (const void **) &stats_data, &size);
		r = sid_buffer_add(ucmd_ctx->res_buf, stats_data, size, NULL, NULL);
	}
	return r;
}

const void *sid_ucmd_part_get_disk_kv(struct module       *mod,
                                      struct sid_ucmd_ctx *ucmd_ctx,
                                      const char          *key_core,
                                      size_t              *value_size,
                                      sid_ucmd_kv_flags_t *flags)
{
	char               devno_buf[16];
	struct kv_key_spec key_spec = {.extra_op = NULL,
	                               .op       = KV_OP_SET,
	                               .dom      = KV_KEY_DOM_USER,
	                               .ns       = KV_NS_DEVICE,
	                               .ns_part  = ID_NULL, /* will be calculated later */
	                               .id_cat   = ID_NULL,
	                               .id       = ID_NULL,
	                               .core     = key_core};

	if (!mod || !ucmd_ctx || !key_core || !*key_core || (key_core[0] == KV_PREFIX_KEY_SYS_C[0]))
		return NULL;

	if (_part_get_whole_disk(mod, ucmd_ctx, devno_buf, sizeof(devno_buf)) < 0)
		return NULL;

	key_spec.ns_part = _canonicalize_kv_key(devno_buf);

	return _cmd_get_key_spec_value(mod, ucmd_ctx, &key_spec, value_size, flags);
}

static const char *_devno_to_devid(struct sid_ucmd_ctx *ucmd_ctx, const char *devno, char *devid_buf, size_t devid_buf_size)
{
	const char        *devid = NULL;
	const char        *key;
	kv_vector_t       *vvalue;
	size_t             value_size;
	struct kv_key_spec key_spec = {.extra_op = NULL,
	                               .op       = KV_OP_SET,
	                               .dom      = KV_KEY_DOM_ALIAS,
	                               .ns       = KV_NS_MODULE,
	                               .ns_part  = _get_ns_part(NULL, ucmd_ctx, KV_NS_MODULE),
	                               .id_cat   = "devno",
	                               .id       = devno,
	                               .core     = KV_KEY_GEN_GROUP_MEMBERS};

	if (!(key = _compose_key(ucmd_ctx->common->gen_buf, &key_spec)))
		goto out;

	if (!(vvalue = kv_store_get_value(ucmd_ctx->common->kv_store_res, key, &value_size, NULL)))
		goto out;

	/* It must be a single value! */
	if (value_size != VVALUE_SINGLE_CNT)
		goto out;

	/* It must be current generation record! */
	if (VVALUE_GENNUM(vvalue) != ucmd_ctx->common->gennum)
		goto out;

	devid = _copy_ns_part_from_key(VVALUE_DATA(vvalue), devid_buf, devid_buf_size);
out:
	_destroy_key(ucmd_ctx->common->gen_buf, key);
	return devid;
}

static int _refresh_device_disk_hierarchy_from_sysfs(sid_resource_t *cmd_res)
{
	/* FIXME: ...fail completely here, discarding any changes made to DB so far if any of the steps below fail? */
	struct sid_ucmd_ctx *ucmd_ctx = sid_resource_get_data(cmd_res);
	char                *s;
	struct dirent      **dirent  = NULL;
	struct sid_buffer   *vec_buf = NULL;
	char                 devno_buf[16];
	char                 devid_buf[UTIL_UUID_STR_SIZE];
	kv_vector_t         *vvalue;
	size_t               vsize = 0;
	int                  count = 0, i = 0;
	util_mem_t           mem;
	int                  r      = -1;

	struct kv_rel_spec rel_spec = {.delta = &((struct kv_delta) {.op = KV_OP_SET, .flags = DELTA_WITH_DIFF | DELTA_WITH_REL}),

	                               .abs_delta = &((struct kv_delta) {0}),

	                               .cur_key_spec =
	                                       &((struct kv_key_spec) {.extra_op = NULL,
	                                                               .op       = KV_OP_SET,
	                                                               .dom      = ID_NULL,
	                                                               .ns       = KV_NS_DEVICE,
	                                                               .ns_part  = _get_ns_part(NULL, ucmd_ctx, KV_NS_DEVICE),
	                                                               .id_cat   = ID_NULL,
	                                                               .id       = ID_NULL,
	                                                               .core     = KV_KEY_GEN_GROUP_MEMBERS}),

	                               .rel_key_spec = &((struct kv_key_spec) {.extra_op = NULL,
	                                                                       .op       = KV_OP_SET,
	                                                                       .dom      = ID_NULL,
	                                                                       .ns       = KV_NS_DEVICE,
	                                                                       .ns_part  = ID_NULL, /* will be calculated later */
	                                                                       .id_cat   = ID_NULL,
	                                                                       .id       = ID_NULL,
	                                                                       .core     = KV_KEY_GEN_GROUP_IN})};

	struct kv_update_arg update_arg = {.res     = ucmd_ctx->common->kv_store_res,
	                                   .owner   = OWNER_CORE,
	                                   .gen_buf = ucmd_ctx->common->gen_buf,
	                                   .custom  = &rel_spec};

	if (ucmd_ctx->req_env.dev.udev.action != UDEV_ACTION_REMOVE) {
		if ((r = sid_buffer_fmt_add(ucmd_ctx->common->gen_buf,
		                            (const void **) &s,
		                            NULL,
		                            "%s%s/%s",
		                            SYSTEM_SYSFS_PATH,
		                            ucmd_ctx->req_env.dev.udev.path,
		                            SYSTEM_SYSFS_SLAVES)) < 0) {
			log_error_errno(ID(cmd_res),
			                r,
			                "Failed to compose sysfs %s path for device " CMD_DEV_NAME_NUM_FMT,
			                SYSTEM_SYSFS_SLAVES,
			                CMD_DEV_NAME_NUM(ucmd_ctx));
			goto out;
		}

		if ((count = scandir(s, &dirent, NULL, NULL)) < 0) {
			/*
			 * FIXME: Add code to deal with/warn about: (errno == ENOENT) && (ucmd_ctx->req_env.dev.udev.action !=
			 * UDEV_ACTION_REMOVE). That means we don't have REMOVE uevent, but at the same time, we don't have sysfs
			 * content, e.g. because we're processing this uevent too late: the device has already been removed right
			 * after this uevent was triggered. For now, error out even in this case.
			 */
			log_sys_error(ID(cmd_res), "scandir", s);
			sid_buffer_rewind_mem(ucmd_ctx->common->gen_buf, s);
			goto out;
		}

		sid_buffer_rewind_mem(ucmd_ctx->common->gen_buf, s);
	}

	/*
	 * Create vec_buf used to set up database records.
	 * The size of the vec_buf is:
	 *   +VVALUE_HEADER_CNT to include record header
	 *   -2 to subtract "." and ".." directory which we're not interested in
	 */
	if (!(vec_buf = sid_buffer_create(&((struct sid_buffer_spec) {.backend = SID_BUFFER_BACKEND_MALLOC,
	                                                              .type    = SID_BUFFER_TYPE_VECTOR,
	                                                              .mode    = SID_BUFFER_MODE_PLAIN}),
	                                  &((struct sid_buffer_init) {.size = VVALUE_HEADER_CNT + (count >= 2 ? count - 2 : 0),
	                                                              .alloc_step = 1,
	                                                              .limit      = 0}),
	                                  &r))) {
		log_error_errno(ID(cmd_res),
		                r,
		                "Failed to create buffer to record hierarchy for device " CMD_DEV_NAME_NUM_FMT,
		                CMD_DEV_NAME_NUM(ucmd_ctx));
		goto out;
	}

	vsize = VVALUE_HEADER_CNT;
	if (sid_buffer_add(vec_buf, NULL, vsize, (const void **) &vvalue, NULL) < 0)
		goto out;

	_vvalue_header_prep(vvalue,
	                    vsize,
	                    &ucmd_ctx->req_env.dev.udev.seqnum,
	                    &value_flags_no_sync,
	                    &ucmd_ctx->common->gennum,
	                    core_owner);
	sid_buffer_unbind_mem(vec_buf, vvalue);

	/* Read relatives from sysfs into vec_buf. */
	if (ucmd_ctx->req_env.dev.udev.action != UDEV_ACTION_REMOVE) {
		for (i = 0; i < count; i++) {
			if (dirent[i]->d_name[0] == '.')
				goto next;

			if (sid_buffer_fmt_add(ucmd_ctx->common->gen_buf,
			                       (const void **) &s,
			                       NULL,
			                       "%s%s/%s/%s/dev",
			                       SYSTEM_SYSFS_PATH,
			                       ucmd_ctx->req_env.dev.udev.path,
			                       SYSTEM_SYSFS_SLAVES,
			                       dirent[i]->d_name) < 0) {
				log_error_errno(ID(cmd_res),
				                r,
				                "Failed to compose sysfs path for device %s which is relative of "
				                "device " CMD_DEV_NAME_NUM_FMT,
				                dirent[i]->d_name,
				                CMD_DEV_NAME_NUM(ucmd_ctx));
			} else {
				if ((r = sid_util_sysfs_get_value(s, devno_buf, sizeof(devno_buf))) < 0 || !*devno_buf) {
					log_error_errno(ID(cmd_res),
					                r,
					                "Failed to read related disk device number from sysfs file %s.",
					                s);
					sid_buffer_rewind_mem(ucmd_ctx->common->gen_buf, s);
					goto next;
				}
				sid_buffer_rewind_mem(ucmd_ctx->common->gen_buf, s);

				_canonicalize_kv_key(devno_buf);
				if (!(rel_spec.rel_key_spec->ns_part =
				              _devno_to_devid(ucmd_ctx, devno_buf, devid_buf, sizeof(devid_buf)))) {
					mem = (util_mem_t) {.base = devid_buf, .size = sizeof(devid_buf)};
					if (!util_uuid_gen_str(&mem)) {
						log_error(ID(cmd_res),
						          "Failed to generate UUID for device " CMD_DEV_NAME_NUM_FMT ".",
						          CMD_DEV_NAME_NUM(ucmd_ctx));
						goto next;
					}
					rel_spec.rel_key_spec->ns_part = mem.base;

					if (_handle_dev_for_group(NULL,
					                          ucmd_ctx,
					                          mem.base,
					                          KV_KEY_DOM_ALIAS,
					                          KV_NS_MODULE,
					                          "devno",
					                          devno_buf,
					                          KV_OP_PLUS) < 0) {
						log_error(ID(cmd_res),
						          "Failed to add devno alias for device " CMD_DEV_NAME_NUM_FMT,
						          CMD_DEV_NAME_NUM(ucmd_ctx));
						goto next;
					}
				}

				s = _compose_key_prefix(NULL, rel_spec.rel_key_spec);
				if (!s || ((r = sid_buffer_add(vec_buf, (void *) s, strlen(s) + 1, NULL, NULL)) < 0)) {
					_destroy_key(NULL, s);
					goto out;
				}
			}
next:
			free(dirent[i]);
		}
		free(dirent);
		dirent                         = NULL;
		rel_spec.rel_key_spec->ns_part = ID_NULL;
	}

	/* Get the actual vector with relatives and sort it. */
	sid_buffer_get_data(vec_buf, (const void **) (&vvalue), &vsize);
	qsort(vvalue + VVALUE_HEADER_CNT, vsize - VVALUE_HEADER_CNT, sizeof(kv_vector_t), _vvalue_str_cmp);

	if (!(s = _compose_key(NULL, rel_spec.cur_key_spec))) {
		log_error(ID(cmd_res),
		          _key_prefix_err_msg,
		          ucmd_ctx->req_env.dev.udev.name,
		          ucmd_ctx->req_env.dev.udev.major,
		          ucmd_ctx->req_env.dev.udev.minor);
		goto out;
	}

	_kv_delta_set(s, vvalue, vsize, &update_arg, true);

	_destroy_key(NULL, s);
	r = 0;
out:
	if (dirent) {
		for (; i < count; i++)
			free(dirent[i]);
		free(dirent);
	}
	if (vec_buf) {
		if (!vsize)
			sid_buffer_get_data(vec_buf, (const void **) (&vvalue), &vsize);

		for (i = VVALUE_HEADER_CNT; i < vsize; i++)
			_destroy_key(NULL, vvalue[i].iov_base);

		sid_buffer_destroy(vec_buf);
	}
	return r;
}

static int _refresh_device_partition_hierarchy_from_sysfs(sid_resource_t *cmd_res)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_resource_get_data(cmd_res);
	kv_vector_t          vvalue[VVALUE_SINGLE_CNT];
	char                 devno_buf[16];
	char                 devid_buf[UTIL_UUID_STR_SIZE];
	const char          *s   = NULL;
	char                *key = NULL;
	util_mem_t           mem;
	int                  r      = -1;

	struct kv_rel_spec rel_spec = {.delta = &((struct kv_delta) {.op = KV_OP_SET, .flags = DELTA_WITH_DIFF | DELTA_WITH_REL}),

	                               .abs_delta = &((struct kv_delta) {0}),

	                               .cur_key_spec =
	                                       &((struct kv_key_spec) {.extra_op = NULL,
	                                                               .op       = KV_OP_SET,
	                                                               .dom      = ID_NULL,
	                                                               .ns       = KV_NS_DEVICE,
	                                                               .ns_part  = _get_ns_part(NULL, ucmd_ctx, KV_NS_DEVICE),
	                                                               .id_cat   = ID_NULL,
	                                                               .id       = ID_NULL,
	                                                               .core     = KV_KEY_GEN_GROUP_MEMBERS}),

	                               .rel_key_spec = &((struct kv_key_spec) {.extra_op = NULL,
	                                                                       .op       = KV_OP_SET,
	                                                                       .dom      = ID_NULL,
	                                                                       .ns       = KV_NS_DEVICE,
	                                                                       .ns_part  = ID_NULL, /* will be calculated later */
	                                                                       .id_cat   = ID_NULL,
	                                                                       .id       = ID_NULL,
	                                                                       .core     = KV_KEY_GEN_GROUP_IN})};

	struct kv_update_arg update_arg = {.res     = ucmd_ctx->common->kv_store_res,
	                                   .owner   = OWNER_CORE,
	                                   .gen_buf = ucmd_ctx->common->gen_buf,
	                                   .custom  = &rel_spec};

	_vvalue_header_prep(vvalue,
	                    VVALUE_CNT(vvalue),
	                    &ucmd_ctx->req_env.dev.udev.seqnum,
	                    &value_flags_no_sync,
	                    &ucmd_ctx->common->gennum,
	                    core_owner);
	if (_part_get_whole_disk(NULL, ucmd_ctx, devno_buf, sizeof(devno_buf)) < 0)
		goto out;

	_canonicalize_kv_key(devno_buf);

	if (!(rel_spec.rel_key_spec->ns_part = _devno_to_devid(ucmd_ctx, devno_buf, devid_buf, sizeof(devid_buf)))) {
		mem = (util_mem_t) {.base = devid_buf, .size = sizeof(devid_buf)};
		if (!util_uuid_gen_str(&mem)) {
			log_error(ID(cmd_res),
			          "Failed to generate UUID for device " CMD_DEV_NAME_NUM_FMT ".",
			          CMD_DEV_NAME_NUM(ucmd_ctx));
			goto out;
		}
		rel_spec.rel_key_spec->ns_part = mem.base;

		_handle_dev_for_group(NULL, ucmd_ctx, mem.base, KV_KEY_DOM_ALIAS, KV_NS_MODULE, "devno", devno_buf, KV_OP_PLUS);
	}

	if (!(s = _compose_key_prefix(NULL, rel_spec.rel_key_spec)))
		goto out;

	_vvalue_data_prep(vvalue, VVALUE_CNT(vvalue), 0, (void *) s, strlen(s) + 1);
	rel_spec.rel_key_spec->ns_part = ID_NULL;

	if (!(key = _compose_key(NULL, rel_spec.cur_key_spec))) {
		log_error(ID(cmd_res),
		          _key_prefix_err_msg,
		          ucmd_ctx->req_env.dev.udev.name,
		          ucmd_ctx->req_env.dev.udev.major,
		          ucmd_ctx->req_env.dev.udev.minor);
		goto out;
	}

	/*
	 * Handle delta.final vector for this device.
	 * The delta.final is computed inside _kv_cb_delta out of vec_buf.
	 * The _kv_cb_delta also sets delta.plus and delta.minus vectors with info about changes when compared to previous record.
	 */
	_kv_delta_set(key, vvalue, VVALUE_SINGLE_CNT, &update_arg, true);

	r = 0;
out:
	_destroy_key(NULL, key);
	_destroy_key(NULL, s);
	return r;
}

static int _refresh_device_hierarchy_from_sysfs(sid_resource_t *cmd_res)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_resource_get_data(cmd_res);

	switch (ucmd_ctx->req_env.dev.udev.type) {
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
	struct sid_ucmd_ctx           *ucmd_ctx = sid_resource_get_data(exec_arg->cmd_res);
	sid_resource_t                *block_mod_res;
	struct module                 *block_mod;
	const struct sid_ucmd_mod_fns *block_mod_fns;
	int                            r = -1;

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
	const char          *uuid_p;
	char                 buf[UTIL_UUID_STR_SIZE]; /* used for both uuid and diskseq */
	util_mem_t           mem = {.base = buf, .size = sizeof(buf)};

	/* try to get current device's UUID from udev first */
	if (!(uuid_p = _do_sid_ucmd_get_kv(NULL, ucmd_ctx, NULL, KV_NS_UDEV, KV_KEY_UDEV_SID_DEV_ID, NULL, NULL, 0))) {
		/* if not in udev, check if we have set UUID for this device already */
		if (!(uuid_p = _devno_to_devid(ucmd_ctx, ucmd_ctx->req_env.dev.num_s, buf, sizeof(buf)))) {
			/* if we haven't set the UUID for this device yet, do it now */
			if (!util_uuid_gen_str(&mem)) {
				log_error(ID(cmd_res),
				          "Failed to generate UUID for device " CMD_DEV_NAME_NUM_FMT ".",
				          CMD_DEV_NAME_NUM(ucmd_ctx));
				return -1;
			}
			uuid_p = mem.base;
		}

		if (!_do_sid_ucmd_set_kv(NULL,
		                         ucmd_ctx,
		                         NULL,
		                         KV_NS_UDEV,
		                         KV_KEY_UDEV_SID_DEV_ID,
		                         KV_SYNC,
		                         uuid_p,
		                         strlen(uuid_p) + 1)) {
			log_error(ID(cmd_res), "Failed to set %s udev variable.", KV_KEY_UDEV_SID_DEV_ID);
			return -1;
		}
	}

	ucmd_ctx->req_env.dev.uid_s = strdup(uuid_p);

	if (snprintf(buf, sizeof(buf), "%" PRIu64, ucmd_ctx->req_env.dev.udev.diskseq) < 0) {
		log_error(ID(cmd_res), "Failed to convert DISKSEQ to string.");
		return -1;
	}

	if (_handle_dev_for_group(NULL, ucmd_ctx, NULL, KV_KEY_DOM_ALIAS, KV_NS_MODULE, "dseq", buf, KV_OP_PLUS) < 0 ||
	    _handle_dev_for_group(NULL,
	                          ucmd_ctx,
	                          NULL,
	                          KV_KEY_DOM_ALIAS,
	                          KV_NS_MODULE,
	                          "devno",
	                          ucmd_ctx->req_env.dev.num_s,
	                          KV_OP_PLUS) < 0 ||
	    _handle_dev_for_group(NULL,
	                          ucmd_ctx,
	                          NULL,
	                          KV_KEY_DOM_ALIAS,
	                          KV_NS_MODULE,
	                          "name",
	                          ucmd_ctx->req_env.dev.udev.name,
	                          KV_OP_PLUS) < 0) {
		log_error(ID(cmd_res), "Failed to add dseq/devno/name device alias.");
		return -1;
	}

	if (sid_ucmd_dev_get_ready(NULL, ucmd_ctx, 0) == DEV_RDY_UNDEFINED)
		sid_ucmd_dev_set_ready(NULL, ucmd_ctx, DEV_RDY_UNPROCESSED);

	return _refresh_device_hierarchy_from_sysfs(cmd_res);
}

static int _cmd_exec_scan_init(struct cmd_exec_arg *exec_arg)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_resource_get_data(exec_arg->cmd_res);
	sid_resource_t      *block_mod_registry_res;

	if (!(block_mod_registry_res = sid_resource_search(ucmd_ctx->common->modules_res,
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

	if (!(exec_arg->type_mod_registry_res = sid_resource_search(ucmd_ctx->common->modules_res,
	                                                            SID_RESOURCE_SEARCH_IMM_DESC,
	                                                            &sid_resource_type_module_registry,
	                                                            MODULES_TYPE_ID))) {
		log_error(ID(exec_arg->cmd_res), INTERNAL_ERROR "%s: Failed to find type module registry resource.", __func__);
		goto fail;
	}

	if (_set_device_kv_records(exec_arg->cmd_res) < 0)
		goto fail;

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
	char                           buf[80];
	struct sid_ucmd_ctx           *ucmd_ctx = sid_resource_get_data(exec_arg->cmd_res);
	const struct sid_ucmd_mod_fns *mod_fns;
	const char                    *mod_name;

	if (!(mod_name = _do_sid_ucmd_get_kv(NULL, ucmd_ctx, NULL, KV_NS_DEVICE, KV_KEY_DEV_MOD, NULL, NULL, 0))) {
		if (!(mod_name = _lookup_mod_name(exec_arg->cmd_res,
		                                  ucmd_ctx->req_env.dev.udev.major,
		                                  ucmd_ctx->req_env.dev.udev.name,
		                                  buf,
		                                  sizeof(buf)))) {
			log_error(ID(exec_arg->cmd_res), "Module name lookup failed.");
			return -1;
		}

		if (!_do_sid_ucmd_set_kv(NULL,
		                         ucmd_ctx,
		                         NULL,
		                         KV_NS_DEVICE,
		                         KV_KEY_DEV_MOD,
		                         DEFAULT_VALUE_FLAGS_CORE,
		                         mod_name,
		                         strlen(mod_name) + 1)) {
			log_error(ID(exec_arg->cmd_res),
			          "Failed to store device " CMD_DEV_NAME_NUM_FMT " module name",
			          CMD_DEV_NAME_NUM(ucmd_ctx));
			return -1;
		}
	}

	if (!(exec_arg->type_mod_res_current = module_registry_get_module(exec_arg->type_mod_registry_res, mod_name)))
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
	struct sid_ucmd_ctx           *ucmd_ctx = sid_resource_get_data(exec_arg->cmd_res);
	const struct sid_ucmd_mod_fns *mod_fns;

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
	struct sid_ucmd_ctx           *ucmd_ctx = sid_resource_get_data(exec_arg->cmd_res);
	const struct sid_ucmd_mod_fns *mod_fns;

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
	struct sid_ucmd_ctx           *ucmd_ctx = sid_resource_get_data(exec_arg->cmd_res);
	const struct sid_ucmd_mod_fns *mod_fns;
	const char                    *next_mod_name;

	_execute_block_modules(exec_arg, CMD_SCAN_PHASE_A_SCAN_NEXT);

	if ((next_mod_name = _do_sid_ucmd_get_kv(NULL,
	                                         ucmd_ctx,
	                                         KV_KEY_DOM_USER,
	                                         KV_NS_DEVICE,
	                                         SID_UCMD_KEY_DEVICE_NEXT_MOD,
	                                         NULL,
	                                         NULL,
	                                         0))) {
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
	struct sid_ucmd_ctx           *ucmd_ctx = sid_resource_get_data(exec_arg->cmd_res);
	const struct sid_ucmd_mod_fns *mod_fns;

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
	struct sid_ucmd_ctx           *ucmd_ctx = sid_resource_get_data(exec_arg->cmd_res);
	const struct sid_ucmd_mod_fns *mod_fns;

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
	struct sid_ucmd_ctx *ucmd_ctx = sid_resource_get_data(exec_arg->cmd_res);

	if (sid_ucmd_dev_get_ready(NULL, ucmd_ctx, 0) == DEV_RDY_UNPROCESSED)
		sid_ucmd_dev_set_ready(NULL, ucmd_ctx, DEV_RDY_PUBLIC);

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
	struct sid_ucmd_ctx           *ucmd_ctx = sid_resource_get_data(exec_arg->cmd_res);
	const struct sid_ucmd_mod_fns *mod_fns;
	int                            r = 0;

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
	[CMD_SCAN_PHASE_A_INIT]              = {.name = "init", .flags = CMD_SCAN_CAP_ALL, .exec = _cmd_exec_scan_init},

	[CMD_SCAN_PHASE_A_IDENT]             = {.name = "ident", .flags = 0, .exec = _cmd_exec_scan_ident},

	[CMD_SCAN_PHASE_A_SCAN_PRE]          = {.name = "scan-pre", .flags = CMD_SCAN_CAP_RDY, .exec = _cmd_exec_scan_pre},

	[CMD_SCAN_PHASE_A_SCAN_CURRENT]      = {.name = "scan-current", .flags = CMD_SCAN_CAP_RDY, .exec = _cmd_exec_scan_current},

	[CMD_SCAN_PHASE_A_SCAN_NEXT]         = {.name = "scan-next", .flags = CMD_SCAN_CAP_RES, .exec = _cmd_exec_scan_next},

	[CMD_SCAN_PHASE_A_SCAN_POST_CURRENT] = {.name = "scan-post-current", .flags = 0, .exec = _cmd_exec_scan_post_current},

	[CMD_SCAN_PHASE_A_SCAN_POST_NEXT]    = {.name = "scan-post-next", .flags = 0, .exec = _cmd_exec_scan_post_next},

	[CMD_SCAN_PHASE_A_WAITING]           = {.name = "waiting", .flags = 0, .exec = _cmd_exec_scan_wait},

	[CMD_SCAN_PHASE_A_EXIT]              = {.name = "exit", .flags = CMD_SCAN_CAP_ALL, .exec = _cmd_exec_scan_exit},

	[CMD_SCAN_PHASE_B_TRIGGER_ACTION_CURRENT] = {.name  = "trigger-action-current",
                                                     .flags = 0,
                                                     .exec  = _cmd_exec_trigger_action_current},

	[CMD_SCAN_PHASE_B_TRIGGER_ACTION_NEXT] = {.name = "trigger-action-next", .flags = 0, .exec = _cmd_exec_trigger_action_next},

	[CMD_SCAN_PHASE_ERROR]                 = {.name = "error", .flags = 0, .exec = _cmd_exec_scan_error},
};

static int _cmd_exec_scan(struct cmd_exec_arg *exec_arg)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_resource_get_data(exec_arg->cmd_res);
	cmd_scan_phase_t     phase;

	for (phase = CMD_SCAN_PHASE_A_INIT; phase <= CMD_SCAN_PHASE_A_EXIT; phase++) {
		log_debug(ID(exec_arg->cmd_res), "Executing %s phase.", _cmd_scan_phase_regs[phase].name);
		ucmd_ctx->scan.phase = phase;

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

static struct cmd_reg _client_cmd_regs[] = {
	[SID_CMD_UNKNOWN]    = {.name = "c-unknown", .flags = 0, .exec = NULL},
	[SID_CMD_ACTIVE]     = {.name = "c-active", .flags = 0, .exec = NULL},
	[SID_CMD_CHECKPOINT] = {.name = "c-checkpoint", .flags = CMD_KV_IMPORT_UDEV, .exec = NULL},
	[SID_CMD_REPLY]      = {.name = "c-reply", .flags = 0, .exec = NULL},
	[SID_CMD_SCAN]       = {.name  = "c-scan",
                                .flags = CMD_KV_IMPORT_UDEV | CMD_KV_EXPORT_UDEV_TO_RESBUF | CMD_KV_EXPORT_SID_TO_EXPBUF |
                                         CMD_KV_EXPBUF_TO_MAIN | CMD_KV_EXPORT_SYNC | CMD_KV_EXPECT_EXPBUF_ACK | CMD_SESSION_ID,
                                .exec = _cmd_exec_scan},
	[SID_CMD_VERSION]    = {.name = "c-version", .flags = 0, .exec = _cmd_exec_version},
	[SID_CMD_DBDUMP]  = {.name = "c-dbdump", .flags = CMD_KV_EXPORT_UDEV_TO_EXPBUF | CMD_KV_EXPORT_SID_TO_EXPBUF, .exec = NULL},
	[SID_CMD_DBSTATS] = {.name = "c-dbstats", .flags = 0, .exec = _cmd_exec_dbstats},
	[SID_CMD_RESOURCES] = {.name = "c-resource", .flags = 0, .exec = _cmd_exec_resources},
	[SID_CMD_DEVICES]   = {.name = "c-devices", .flags = 0, .exec = _cmd_exec_devices},
};

static struct cmd_reg _self_cmd_regs[] = {
	[SELF_CMD_DBDUMP] = {.name  = "s-dbdump",
                             .flags = CMD_KV_EXPORT_UDEV_TO_EXPBUF | CMD_KV_EXPORT_SID_TO_EXPBUF | CMD_KV_EXPBUF_TO_FILE |
                                      CMD_KV_EXPORT_PERSISTENT,
                             .exec = NULL},
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

static const struct cmd_reg *_get_cmd_reg(struct sid_ucmd_ctx *ucmd_ctx)
{
	switch (ucmd_ctx->req_cat) {
		case MSG_CATEGORY_SYSTEM:
			return NULL;
		case MSG_CATEGORY_SELF:
			return &_self_cmd_regs[ucmd_ctx->req_hdr.cmd];
		case MSG_CATEGORY_CLIENT:
			return &_client_cmd_regs[ucmd_ctx->req_hdr.cmd];
	}

	return NULL;
}

static int _send_out_cmd_expbuf(sid_resource_t *cmd_res)
{
	struct sid_ucmd_ctx  *ucmd_ctx = sid_resource_get_data(cmd_res);
	const struct cmd_reg *cmd_reg  = _get_cmd_reg(ucmd_ctx);
	sid_resource_t       *conn_res = NULL;
	struct connection    *conn     = NULL;
	struct sid_buffer    *buf      = ucmd_ctx->common->gen_buf;
	const char           *id;
	size_t                buf_pos;
	char                 *data;
	size_t                size;
	int                   r = 0;

	if (!ucmd_ctx->exp_buf)
		return 0;

	if (cmd_reg->flags & CMD_KV_EXPBUF_TO_MAIN) {
		if (sid_buffer_count(ucmd_ctx->exp_buf) > 0) {
			id = sid_resource_get_id(cmd_res);

			sid_buffer_add(buf,
			               &(struct internal_msg_header) {.cat = MSG_CATEGORY_SYSTEM,
			                                              .header =
			                                                      (struct sid_msg_header) {
										      .status = 0,
										      .prot   = 0,
										      .cmd    = SYSTEM_CMD_SYNC,
										      .flags  = 0,
									      }},
			               INTERNAL_MSG_HEADER_SIZE,
			               NULL,
			               &buf_pos);
			sid_buffer_add(buf, (void *) id, strlen(id) + 1, NULL, NULL);
			sid_buffer_get_data_from(buf, buf_pos, (const void **) &data, &size);

			if ((r = worker_control_channel_send(cmd_res,
			                                     MAIN_WORKER_CHANNEL_ID,
			                                     &(struct worker_data_spec) {.data               = data,
			                                                                 .data_size          = size,
			                                                                 .ext.used           = true,
			                                                                 .ext.socket.fd_pass = sid_buffer_get_fd(
												 ucmd_ctx->exp_buf)})) < 0) {
				log_error_errno(ID(cmd_res), r, "Failed to send command exports to main SID process.");
				r = -1;
			}

			sid_buffer_rewind(buf, buf_pos, SID_BUFFER_POS_ABS);
		} // TODO: if sid_buffer_count returns 0, then set the cmd state as if the buffer was acked
	} else if (cmd_reg->flags & CMD_KV_EXPBUF_TO_FILE) {
		if ((r = fsync(sid_buffer_get_fd(ucmd_ctx->exp_buf))) < 0) {
			log_error_errno(ID(cmd_res), r, "Failed to fsync command exports to a file.");
			r = -1;
		}
	} else {
		switch (ucmd_ctx->req_cat) {
			case MSG_CATEGORY_SYSTEM:
				break;

			case MSG_CATEGORY_CLIENT:
				conn_res = sid_resource_search(cmd_res, SID_RESOURCE_SEARCH_IMM_ANC, NULL, NULL);
				conn     = sid_resource_get_data(conn_res);

				if ((r = _send_fd_over_unix_comms(sid_buffer_get_fd(ucmd_ctx->exp_buf), conn->fd)) < 0) {
					log_error_errno(ID(cmd_res), r, "Failed to send command exports to client.");
					r = -1;
				}
				break;

			case MSG_CATEGORY_SELF:
				/* nothing to do here right now */
				break;
		}
	}

	return r;
}

static int _send_out_cmd_resbuf(sid_resource_t *cmd_res)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_resource_get_data(cmd_res);
	sid_resource_t      *conn_res = NULL;
	struct connection   *conn     = NULL;
	int                  r        = -1;

	/* Send out response buffer. */
	switch (ucmd_ctx->req_cat) {
		case MSG_CATEGORY_SYSTEM:
			break;

		case MSG_CATEGORY_CLIENT:
			conn_res = sid_resource_search(cmd_res, SID_RESOURCE_SEARCH_IMM_ANC, NULL, NULL);
			conn     = sid_resource_get_data(conn_res);

			if (sid_buffer_write_all(ucmd_ctx->res_buf, conn->fd) < 0) {
				log_error(ID(cmd_res), "Failed to send command response to client.");
				(void) _connection_cleanup(conn_res);
				goto out;
			}
			break;

		case MSG_CATEGORY_SELF:
			// TODO: Return response buffer content to the resource which created this cmd resource.
			break;
	}

	r = 0;
out:
	return r;
}

static int _cmd_handler(sid_resource_event_source_t *es, void *data)
{
	sid_resource_t       *cmd_res  = data;
	struct sid_ucmd_ctx  *ucmd_ctx = sid_resource_get_data(cmd_res);
	const struct cmd_reg *cmd_reg  = _get_cmd_reg(ucmd_ctx);
	int                   r        = -1;

	if (ucmd_ctx->state == CMD_EXEC_SCHEDULED) {
		_change_cmd_state(cmd_res, CMD_EXECUTING);

		if (cmd_reg->exec && ((r = cmd_reg->exec(&(struct cmd_exec_arg) {.cmd_res = cmd_res})) < 0)) {
			log_error(ID(cmd_res), "Failed to execute command");
			goto out;
		}

		/*
		 * The cmd_reg->exec might have changed the state to CMD_EXPECTING_DATA,
		 * so check if we're still in CMD_EXECUTING - if yes, change state to CMD_EXEC_FINISHED.
		 */
		if (ucmd_ctx->state == CMD_EXECUTING)
			_change_cmd_state(cmd_res, CMD_EXEC_FINISHED);
	}

	if (ucmd_ctx->state == CMD_EXEC_FINISHED) {
		if ((r = _build_cmd_kv_buffers(cmd_res, cmd_reg)) < 0) {
			log_error(ID(cmd_res), "Failed to export KV store.");
			goto out;
		}

		// TODO: check returned error code from _send_out_cmd_* fns
		if (cmd_reg->flags & CMD_KV_EXPECT_EXPBUF_ACK) {
			r = _send_out_cmd_expbuf(cmd_res);
			_change_cmd_state(cmd_res, CMD_EXPECTING_EXPBUF_ACK);
		} else {
			if ((r = _send_out_cmd_resbuf(cmd_res) == 0))
				r = _send_out_cmd_expbuf(cmd_res);
		}
	} else if (ucmd_ctx->state == CMD_EXPBUF_ACKED) {
		r = _send_out_cmd_resbuf(cmd_res);
	}
out:
	if (r < 0) {
		// TODO: res_hdr.status needs to be set before _send_out_cmd_kv_buffers so it's transmitted
		//       and also any results collected after the res_hdr must be discarded
		ucmd_ctx->res_hdr.status |= SID_CMD_STATUS_FAILURE;
		_change_cmd_state(cmd_res, CMD_ERROR);
	} else {
		if (ucmd_ctx->state == CMD_EXEC_FINISHED || ucmd_ctx->state == CMD_EXPBUF_ACKED)
			_change_cmd_state(cmd_res, CMD_OK);
	}

	/*
	 * At the end of processing a 'SELF' request, there's no other external entity or event
	 * that would cause the worker to yield itself so do it now before we resume the event loop.
	 */
	if (ucmd_ctx->req_cat == MSG_CATEGORY_SELF) {
		if (ucmd_ctx->state == CMD_OK || ucmd_ctx->state == CMD_ERROR)
			(void) worker_control_worker_yield(sid_resource_search(cmd_res, SID_RESOURCE_SEARCH_IMM_ANC, NULL, NULL));
	}

	return r;
}

static int _reply_failure(sid_resource_t *conn_res)
{
	struct connection    *conn = sid_resource_get_data(conn_res);
	void                 *data;
	struct sid_msg_header header;
	uint8_t               prot;
	struct sid_msg_header response_header = {
		.status = SID_CMD_STATUS_FAILURE,
	};
	int r = -1;

	(void) sid_buffer_get_data(conn->buf, (const void **) &data, NULL);
	memcpy(&header, data, sizeof(header));
	prot = header.prot;
	(void) sid_buffer_rewind(conn->buf, 0, SID_BUFFER_POS_ABS);
	if (prot <= SID_PROTOCOL) {
		response_header.prot = prot;
		if ((r = sid_buffer_add(conn->buf, &response_header, sizeof(response_header), NULL, NULL)) < 0)
			r = sid_buffer_write_all(conn->buf, conn->fd);
	}

	return r;
}

static bool _socket_client_is_capable(int fd, sid_cmd_t cmd)
{
	struct ucred uc;
	socklen_t    len = sizeof(struct ucred);

	/* root can run any command */
	if ((fd >= 0) && (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &uc, &len) == 0) && (uc.uid == 0))
		return true;

	return !_cmd_root_only[cmd];
}

static int _check_msg(sid_resource_t *res, struct sid_msg *msg)
{
	struct sid_msg_header header;

	if (msg->size < sizeof(struct sid_msg_header)) {
		log_error(ID(res), "Incorrect message header size.");
		return -1;
	}

	memcpy(&header, msg->header, sizeof(header));

	/* Sanitize command number - map all out of range command numbers to CMD_UNKNOWN. */
	switch (msg->cat) {
		case MSG_CATEGORY_SYSTEM:
			break;

		case MSG_CATEGORY_SELF:
			if (header.cmd > _SELF_CMD_END)
				header.cmd = SELF_CMD_UNKNOWN;
			break;

		case MSG_CATEGORY_CLIENT:
			if (header.cmd > _SID_CMD_END)
				header.cmd = SID_CMD_UNKNOWN;

			if (!sid_resource_match(res, &sid_resource_type_ubridge_connection, NULL)) {
				log_error(ID(res),
				          INTERNAL_ERROR "Connection resource missing for client command %s.",
				          sid_cmd_type_to_name(header.cmd));
				return -1;
			}

			if (!_socket_client_is_capable(((struct connection *) sid_resource_get_data(res))->fd, header.cmd)) {
				log_error(ID(res),
				          "Client does not have permission to run command %s.",
				          sid_cmd_type_to_name(header.cmd));
				return -1;
			}
			break;
	}

	return 0;
}

static int _create_command_resource(sid_resource_t *parent_res, struct sid_msg *msg)
{
	struct sid_msg_header header;

	if (_check_msg(parent_res, msg) < 0)
		return -1;

	memcpy(&header, msg->header, sizeof(header));

	if (!sid_resource_create(parent_res,
	                         &sid_resource_type_ubridge_command,
	                         SID_RESOURCE_NO_FLAGS,
	                         _get_cmd_reg(&((struct sid_ucmd_ctx) {.req_cat = msg->cat, .req_hdr = header}))->name,
	                         msg,
	                         SID_RESOURCE_PRIO_NORMAL,
	                         SID_RESOURCE_NO_SERVICE_LINKS)) {
		log_error(ID(parent_res), "Failed to register command for processing.");
		return -1;
	}

	return 0;
}

static int _on_connection_event(sid_resource_event_source_t *es, int fd, uint32_t revents, void *data)
{
	sid_resource_t    *conn_res = data;
	struct connection *conn     = sid_resource_get_data(conn_res);
	struct sid_msg     msg;
	ssize_t            n;

	if (revents & EPOLLERR) {
		if (revents & EPOLLHUP)
			log_error(ID(conn_res), "Peer connection closed prematurely.");
		else
			log_error(ID(conn_res), "Connection error.");
		goto fail;
	}

	n = sid_buffer_read(conn->buf, fd);

	if (n > 0) {
		if (sid_buffer_is_complete(conn->buf, NULL)) {
			msg.cat = MSG_CATEGORY_CLIENT;
			(void) sid_buffer_get_data(conn->buf, (const void **) &msg.header, &msg.size);

			if (_create_command_resource(conn_res, &msg) < 0) {
				if (_reply_failure(conn_res) < 0)
					goto fail;
			}

			(void) sid_buffer_reset(conn->buf);
		}
	} else if (n < 0) {
		if (n != -EAGAIN && n != -EINTR) {
			log_error_errno(ID(conn_res), n, "buffer_read_msg");
			return -1;
		}
	} else {
		if (_connection_cleanup(conn_res) < 0)
			return -1;
	}

	return 0;
fail:
	(void) _connection_cleanup(conn_res);
	return -1;
}

static int _init_connection(sid_resource_t *res, const void *kickstart_data, void **data)
{
	const struct worker_data_spec *data_spec = kickstart_data;
	struct connection             *conn;
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

	if (!(conn->buf = sid_buffer_create(&((struct sid_buffer_spec) {.backend = SID_BUFFER_BACKEND_MALLOC,
	                                                                .type    = SID_BUFFER_TYPE_LINEAR,
	                                                                .mode    = SID_BUFFER_MODE_SIZE_PREFIX}),
	                                    &((struct sid_buffer_init) {.size = 0, .alloc_step = 1, .limit = 0}),
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
	close(data_spec->ext.socket.fd_pass);
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

static int _init_command(sid_resource_t *res, const void *kickstart_data, void **data)
{
	const struct sid_msg *msg      = kickstart_data;
	struct sid_ucmd_ctx  *ucmd_ctx = NULL;
	const struct cmd_reg *cmd_reg  = NULL;
	const char           *worker_id;
	sid_resource_t       *common_res;
	int                   r;
	struct sid_msg_header header;

	memcpy(&header, msg->header, sizeof(header));

	if (!(ucmd_ctx = mem_zalloc(sizeof(*ucmd_ctx)))) {
		log_error(ID(res), "Failed to allocate new command structure.");
		goto fail;
	}

	*data = ucmd_ctx;
	_change_cmd_state(res, CMD_INITIALIZING);

	ucmd_ctx->req_cat = msg->cat;
	ucmd_ctx->req_hdr = header;

	/* Require exact protocol version. We can add possible backward/forward compatibility in future stable versions. */
	if (ucmd_ctx->req_hdr.prot != SID_PROTOCOL) {
		log_error(ID(res), "Protocol version unsupported: %u", ucmd_ctx->req_hdr.prot);
		goto fail;
	}

	if (!(cmd_reg = _get_cmd_reg(ucmd_ctx))) {
		log_error(ID(res), INTERNAL_ERROR "%s: Unknown request category: %d.", __func__, (int) ucmd_ctx->req_cat);
		goto fail;
	}

	/* FIXME: Not all commands require print buffer - add command flag to control creation of this buffer. */
	if (!(ucmd_ctx->prn_buf = sid_buffer_create(&((struct sid_buffer_spec) {.backend = SID_BUFFER_BACKEND_MALLOC,
	                                                                        .type    = SID_BUFFER_TYPE_LINEAR,
	                                                                        .mode    = SID_BUFFER_MODE_PLAIN}),
	                                            &((struct sid_buffer_init) {.size = 0, .alloc_step = PATH_MAX, .limit = 0}),
	                                            &r))) {
		log_error_errno(ID(res), r, "Failed to create print buffer");
		goto fail;
	}

	if (!(ucmd_ctx->res_buf = sid_buffer_create(&((struct sid_buffer_spec) {.backend = SID_BUFFER_BACKEND_MALLOC,
	                                                                        .type    = SID_BUFFER_TYPE_VECTOR,
	                                                                        .mode    = SID_BUFFER_MODE_SIZE_PREFIX}),
	                                            &((struct sid_buffer_init) {.size = 1, .alloc_step = 1, .limit = 0}),
	                                            &r))) {
		log_error_errno(ID(res), r, "Failed to create response buffer");
		goto fail;
	}

	ucmd_ctx->res_hdr = (struct sid_msg_header) {.status = SID_CMD_STATUS_SUCCESS, .prot = SID_PROTOCOL, .cmd = SID_CMD_REPLY};
	if ((r = sid_buffer_add(ucmd_ctx->res_buf, &ucmd_ctx->res_hdr, sizeof(ucmd_ctx->res_hdr), NULL, NULL)) < 0)
		goto fail;

	if (!(common_res = sid_resource_search(res, SID_RESOURCE_SEARCH_GENUS, &sid_resource_type_ubridge_common, COMMON_ID))) {
		log_error(ID(res), INTERNAL_ERROR "%s: Failed to find common resource.", __func__);
		goto fail;
	}
	ucmd_ctx->common = sid_resource_get_data(common_res);

	if (cmd_reg->flags & CMD_KV_IMPORT_UDEV) {
		/* currently, we only parse udev environment for the SCAN command */
		if ((r = _parse_cmd_udev_env(ucmd_ctx,
		                             (const char *) msg->header + SID_MSG_HEADER_SIZE,
		                             msg->size - SID_MSG_HEADER_SIZE)) < 0) {
			log_error_errno(ID(res), r, "Failed to parse udev environment variables");
			goto fail;
		}

		log_debug(ID(res), "Processing uevent for device " CMD_DEV_NAME_NUM_FMT, CMD_DEV_NAME_NUM(ucmd_ctx));
	}

	if (cmd_reg->flags & CMD_KV_EXPBUF_TO_FILE) {
		if ((msg->size > sizeof(*msg->header)) &&
		    !(ucmd_ctx->req_env.exp_path = strdup((char *) msg->header + sizeof(*msg->header))))
			goto fail;
	}

	if (cmd_reg->flags & CMD_SESSION_ID) {
		if (!(worker_id = worker_control_get_worker_id(res))) {
			log_error(ID(res), "Failed to get worker ID to set %s udev variable.", KV_KEY_UDEV_SID_SESSION_ID);
			goto fail;
		}

		if (!_do_sid_ucmd_set_kv(NULL,
		                         ucmd_ctx,
		                         NULL,
		                         KV_NS_UDEV,
		                         KV_KEY_UDEV_SID_SESSION_ID,
		                         KV_SYNC_P,
		                         worker_id,
		                         strlen(worker_id) + 1)) {
			log_error(ID(res), "Failed to set %s udev variable.", KV_KEY_UDEV_SID_SESSION_ID);
			goto fail;
		}
	}

	if (sid_resource_create_deferred_event_source(res, &ucmd_ctx->cmd_handler_es, _cmd_handler, 0, "command handler", res) <
	    0) {
		log_error(ID(res), "Failed to register command handler.");
		goto fail;
	}

	_change_cmd_state(res, CMD_EXEC_SCHEDULED);
	return 0;
fail:
	if (ucmd_ctx) {
		*data = NULL;
		if (cmd_reg && cmd_reg->flags & CMD_KV_EXPBUF_TO_FILE && ucmd_ctx->req_env.exp_path)
			free((void *) ucmd_ctx->req_env.exp_path);

		if (ucmd_ctx->prn_buf)
			sid_buffer_destroy(ucmd_ctx->prn_buf);

		if (ucmd_ctx->res_buf)
			sid_buffer_destroy(ucmd_ctx->res_buf);

		if (ucmd_ctx->req_env.dev.num_s)
			free(ucmd_ctx->req_env.dev.num_s);

		if (ucmd_ctx->req_env.dev.uid_s)
			free(ucmd_ctx->req_env.dev.uid_s);

		free(ucmd_ctx);
	}
	return -1;
}

static int _destroy_command(sid_resource_t *res)
{
	struct sid_ucmd_ctx  *ucmd_ctx = sid_resource_get_data(res);
	const struct cmd_reg *cmd_reg  = _get_cmd_reg(ucmd_ctx);

	sid_buffer_destroy(ucmd_ctx->res_buf);

	if (ucmd_ctx->prn_buf)
		sid_buffer_destroy(ucmd_ctx->prn_buf);

	if (ucmd_ctx->exp_buf)
		sid_buffer_destroy(ucmd_ctx->exp_buf);

	if (ucmd_ctx->req_hdr.cmd == SID_CMD_RESOURCES) {
		if (ucmd_ctx->resources.main_res_mem)
			munmap(ucmd_ctx->resources.main_res_mem, ucmd_ctx->resources.main_res_mem_size);
	}

	if ((cmd_reg->flags & CMD_KV_EXPBUF_TO_FILE))
		free((void *) ucmd_ctx->req_env.exp_path);
	else {
		free(ucmd_ctx->req_env.dev.num_s);
		free(ucmd_ctx->req_env.dev.uid_s);
	}

	free(ucmd_ctx);
	return 0;
}

static int _kv_cb_main_unset(struct kv_store_update_spec *spec)
{
	struct kv_update_arg *update_arg = spec->arg;
	kv_vector_t           tmp_vvalue_old[VVALUE_SINGLE_ALIGNED_CNT];
	kv_vector_t          *vvalue_old;
	int                   r = 0;

	if (!spec->old_data)
		return 1;

	vvalue_old = _get_vvalue(spec->old_flags, spec->old_data, spec->old_data_size, tmp_vvalue_old, VVALUE_CNT(tmp_vvalue_old));

	switch (_mod_match(VVALUE_OWNER(vvalue_old), update_arg->owner)) {
		case MOD_NO_MATCH:
			r = !(VVALUE_FLAGS(vvalue_old) & KV_RS) && (VVALUE_FLAGS(vvalue_old) & KV_FRG_WR);
			break;
		case MOD_MATCH:
			r = 1;
			break;
		case MOD_SUB_MATCH:
			r = VVALUE_FLAGS(vvalue_old) & KV_SUB_WR;
			break;
		case MOD_SUP_MATCH:
			r = VVALUE_FLAGS(vvalue_old) & KV_SUP_WR;
			break;
	}

	if (!r) {
		log_debug(ID(update_arg->res),
		          "Refusing request from module %s to unset existing value for key %s (seqnum %" PRIu64
		          "which belongs to module %s.",
		          update_arg->owner,
		          spec->key,
		          VVALUE_SEQNUM(vvalue_old),
		          VVALUE_OWNER(vvalue_old));
		update_arg->ret_code = EBUSY;
	}

	return r;
}

static int _kv_cb_main_set(struct kv_store_update_spec *spec)
{
	struct kv_update_arg *update_arg = spec->arg;
	kv_vector_t           tmp_old_vvalue[VVALUE_SINGLE_ALIGNED_CNT];
	kv_vector_t           tmp_new_vvalue[VVALUE_SINGLE_ALIGNED_CNT];
	kv_vector_t          *old_vvalue, *new_vvalue;
	int                   r;

	old_vvalue = _get_vvalue(spec->old_flags, spec->old_data, spec->old_data_size, tmp_old_vvalue, VVALUE_CNT(tmp_old_vvalue));
	new_vvalue = _get_vvalue(spec->new_flags, spec->new_data, spec->new_data_size, tmp_new_vvalue, VVALUE_CNT(tmp_new_vvalue));

	/* overwrite whole value */
	r          = (!old_vvalue || ((VVALUE_SEQNUM(new_vvalue) >= VVALUE_SEQNUM(old_vvalue)) && _kv_cb_write(spec)));

	if (r)
		log_debug(ID(update_arg->res),
		          "Updating value for key %s (new seqnum %" PRIu64 " >= old seqnum %" PRIu64 ")",
		          spec->key,
		          VVALUE_SEQNUM(new_vvalue),
		          old_vvalue ? VVALUE_SEQNUM(old_vvalue) : 0);
	else
		log_debug(ID(update_arg->res),
		          "Keeping old value for key %s (new seqnum %" PRIu64 " < old seqnum %" PRIu64 ")",
		          spec->key,
		          VVALUE_SEQNUM(new_vvalue),
		          old_vvalue ? VVALUE_SEQNUM(old_vvalue) : 0);

	return r;
}

static char *_compose_archive_key(sid_resource_t *res, const char *key, size_t key_size)
{
	char *archive_key;

	if (!(archive_key = malloc(key_size + 1))) {
		log_error(ID(res), "Failed to create archive key for key %s.", key);
		return NULL;
	}

	memcpy(archive_key + 1, key, key_size);
	archive_key[0] = KV_PREFIX_OP_ARCHIVE_C[0];

	return archive_key;
}

static int _sync_main_kv_store(sid_resource_t *res, struct sid_ucmd_common_ctx *common_ctx, int fd)
{
	static const char           syncing_msg[] = "Syncing main key-value store:  %s = %s (seqnum %" PRIu64 ")";
	kv_store_value_flags_t      kv_store_value_flags;
	SID_BUFFER_SIZE_PREFIX_TYPE msg_size;
	size_t                      key_size, value_size, ext_data_offset, i;
	char                       *key, *archive_key = NULL, *shm = MAP_FAILED, *p, *end;
	kv_scalar_t                 tmp_svalue, *svalue = NULL;
	kv_vector_t                *vvalue = NULL;
	const char                 *vvalue_str;
	void                       *value_to_store;
	struct kv_rel_spec          rel_spec   = {.delta = &((struct kv_delta) {0}), .abs_delta = &((struct kv_delta) {0})};
	struct kv_update_arg        update_arg = {.gen_buf = common_ctx->gen_buf, .custom = &rel_spec};
	bool                        unset, archive;
	int                         r = -1;

	if (read(fd, &msg_size, SID_BUFFER_SIZE_PREFIX_LEN) != SID_BUFFER_SIZE_PREFIX_LEN) {
		log_error_errno(ID(res), errno, "Failed to read shared memory size");
		goto out;
	}

	if (msg_size <= SID_BUFFER_SIZE_PREFIX_LEN) { /* nothing to sync */
		r = 0;
		goto out;
	} else if (msg_size > INTERNAL_MSG_MAX_FD_DATA_SIZE) {
		log_error(ID(res), "Maximum internal messages size exceeded.");
		goto out;
	}

	if ((p = shm = mmap(NULL, msg_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED) {
		log_error_errno(ID(res), errno, "Failed to map memory with key-value store");
		goto out;
	}

	end = p + msg_size;
	p   += sizeof(msg_size);

	if (kv_store_transaction_begin(common_ctx->kv_store_res) < 0) {
		log_error(ID(res), "Failed to start key-value store transaction");
		goto out;
	}

	while (p < end) {
		memcpy(&kv_store_value_flags, p, sizeof(kv_store_value_flags));
		p += sizeof(kv_store_value_flags);

		memcpy(&key_size, p, sizeof(key_size));
		p += sizeof(key_size);

		memcpy(&value_size, p, sizeof(value_size));
		p   += sizeof(value_size);

		key = p;
		p   += key_size;

		/*
		 * Note: if we're reserving a value, then we keep it even if it's NULL.
		 * This prevents others to use the same key. To unset the value,
		 * one needs to drop the flag explicitly.
		 */

		if (kv_store_value_flags & KV_STORE_VALUE_VECTOR) {
			if (value_size < VVALUE_HEADER_CNT) {
				log_error(ID(res),
				          "Received incorrect vector of size %zu to sync with main key-value store.",
				          value_size);
				goto out;
			}

			if (!(vvalue = malloc(value_size * sizeof(kv_vector_t)))) {
				log_error(ID(res), "Failed to allocate vector to sync main key-value store.");
				goto out;
			}

			for (i = 0; i < value_size; i++) {
				memcpy(&vvalue[i].iov_len, p, sizeof(size_t));
				p                  += sizeof(size_t);
				vvalue[i].iov_base = p;
				p                  += vvalue[i].iov_len;
			}
			/* Copy values to aligned memory */
			memcpy(&tmp_svalue.seqnum, vvalue[VVALUE_IDX_SEQNUM].iov_base, sizeof(tmp_svalue.seqnum));
			vvalue[VVALUE_IDX_SEQNUM].iov_base = &tmp_svalue.seqnum;
			memcpy(&tmp_svalue.flags, vvalue[VVALUE_IDX_FLAGS].iov_base, sizeof(tmp_svalue.flags));
			vvalue[VVALUE_IDX_FLAGS].iov_base = &tmp_svalue.flags;
			memcpy(&tmp_svalue.gennum, vvalue[VVALUE_IDX_GENNUM].iov_base, sizeof(tmp_svalue.gennum));
			vvalue[VVALUE_IDX_GENNUM].iov_base = &tmp_svalue.gennum;

			unset                              = !(VVALUE_FLAGS(vvalue) & KV_RS) && (value_size == VVALUE_HEADER_CNT);

			update_arg.owner                   = VVALUE_OWNER(vvalue);
			update_arg.res                     = common_ctx->kv_store_res;
			update_arg.ret_code                = 0;

			vvalue_str                         = _buffer_get_vvalue_str(common_ctx->gen_buf, unset, vvalue, value_size);
			log_debug(ID(res), syncing_msg, key, vvalue_str ?: "NULL", VVALUE_SEQNUM(vvalue));
			if (vvalue_str)
				sid_buffer_rewind_mem(common_ctx->gen_buf, vvalue_str);

			switch (rel_spec.delta->op = _get_op_from_key(key)) {
				case KV_OP_PLUS:
					key += sizeof(KV_PREFIX_OP_PLUS_C) - 1;
					break;
				case KV_OP_MINUS:
					key += sizeof(KV_PREFIX_OP_MINUS_C) - 1;
					break;
				case KV_OP_SET:
					break;
				case KV_OP_ILLEGAL:
					log_error(ID(res),
					          INTERNAL_ERROR
					          "Illegal operator found for key %s while trying to sync main key-value store.",
					          key);
					goto out;
			}

			archive        = VVALUE_FLAGS(vvalue) & KV_AR;
			value_to_store = vvalue;
		} else {
			if (value_size <= SVALUE_HEADER_SIZE) {
				log_error(ID(res),
				          "Received incorrect value of size %zu to sync with main key-value store.",
				          value_size);
				goto out;
			}

			if (!(svalue = malloc(value_size))) {
				log_error(ID(res), "Failed to allocate svalue to sync main key-value store.");
				goto out;
			}

			memcpy(svalue, p, value_size);
			p                   += value_size;

			ext_data_offset     = _svalue_ext_data_offset(svalue);
			unset               = ((svalue->flags != KV_RS) && (value_size == SVALUE_HEADER_SIZE + ext_data_offset));

			update_arg.owner    = svalue->data;
			update_arg.res      = common_ctx->kv_store_res;
			update_arg.ret_code = 0;

			log_debug(ID(res), syncing_msg, key, unset ? "NULL" : svalue->data + ext_data_offset, svalue->seqnum);

			rel_spec.delta->op = KV_OP_SET;

			archive            = svalue->flags & KV_AR;
			value_to_store     = svalue;
		}

		if (unset) {
			if (!(archive_key = _compose_archive_key(res, key, key_size)))
				goto out;

			if (archive) {
				if (kv_store_unset_with_archive(common_ctx->kv_store_res,
				                                key,
				                                _kv_cb_main_unset,
				                                &update_arg,
				                                archive_key) < 0)
					goto out;
			} else {
				if (kv_store_unset(common_ctx->kv_store_res, key, _kv_cb_main_unset, &update_arg) < 0)
					goto out;

				if (kv_store_unset(common_ctx->kv_store_res, archive_key, _kv_cb_main_unset, &update_arg) < 0)
					goto out;
			}
		} else {
			if (rel_spec.delta->op == KV_OP_SET) {
				if (!(archive_key = _compose_archive_key(res, key, key_size)))
					goto out;

				if (archive) {
					if (!kv_store_set_value_with_archive(common_ctx->kv_store_res,
					                                     key,
					                                     value_to_store,
					                                     value_size,
					                                     kv_store_value_flags,
					                                     KV_STORE_VALUE_NO_OP,
					                                     _kv_cb_main_set,
					                                     &update_arg,
					                                     archive_key))
						goto out;
				} else {
					if (!kv_store_set_value(common_ctx->kv_store_res,
					                        key,
					                        value_to_store,
					                        value_size,
					                        kv_store_value_flags,
					                        KV_STORE_VALUE_NO_OP,
					                        _kv_cb_main_set,
					                        &update_arg))
						goto out;

					if (kv_store_unset(common_ctx->kv_store_res, archive_key, _kv_cb_main_unset, &update_arg) <
					    0)
						goto out;
				}
			} else {
				value_to_store = kv_store_set_value(common_ctx->kv_store_res,
				                                    key,
				                                    value_to_store,
				                                    value_size,
				                                    KV_STORE_VALUE_VECTOR | KV_STORE_VALUE_REF,
				                                    KV_STORE_VALUE_NO_OP,
				                                    _kv_cb_main_delta_step,
				                                    &update_arg);
				_destroy_delta_buffers(rel_spec.delta);
				if (!value_to_store || update_arg.ret_code < 0)
					goto out;
			}
		}

		svalue      = mem_freen(svalue);
		vvalue      = mem_freen(vvalue);
		archive_key = mem_freen(archive_key);
	}

	r = 0;
out:
	if (kv_store_in_transaction(common_ctx->kv_store_res))
		kv_store_transaction_end(common_ctx->kv_store_res, (r < 0));

	free(vvalue);
	free(svalue);
	free(archive_key);

	if (shm != MAP_FAILED && munmap(shm, msg_size) < 0) {
		log_error_errno(ID(res), errno, "Failed to unmap memory with key-value store");
		r = -1;
	}

	return r;
}

static int _worker_proxy_recv_system_cmd_sync(sid_resource_t *worker_proxy_res, struct worker_data_spec *data_spec, void *arg)
{
	struct sid_ucmd_common_ctx *common_ctx = arg;
	int                         r;

	if (!data_spec->ext.used) {
		log_error(ID(worker_proxy_res), INTERNAL_ERROR "Received KV store sync request, but KV store sync data missing.");
		return -1;
	}

	(void) _sync_main_kv_store(worker_proxy_res, common_ctx, data_spec->ext.socket.fd_pass);

	r = worker_control_channel_send(
		worker_proxy_res,
		MAIN_WORKER_CHANNEL_ID,
		&(struct worker_data_spec) {.data = data_spec->data, .data_size = data_spec->data_size, .ext.used = false});

	close(data_spec->ext.socket.fd_pass);
	return r;
}

static int _worker_proxy_recv_system_cmd_resources(sid_resource_t          *worker_proxy_res,
                                                   struct worker_data_spec *data_spec,
                                                   void *arg                __unused)
{
	struct internal_msg_header int_msg;
	struct sid_buffer         *buf;
	int                        r = -1;

	memcpy(&int_msg, data_spec->data, INTERNAL_MSG_HEADER_SIZE);

	if (!(buf = sid_buffer_create(&((struct sid_buffer_spec) {.backend = SID_BUFFER_BACKEND_MEMFD,
	                                                          .type    = SID_BUFFER_TYPE_LINEAR,
	                                                          .mode    = SID_BUFFER_MODE_SIZE_PREFIX}),
	                              &((struct sid_buffer_init) {.size = 0, .alloc_step = PATH_MAX, .limit = 0}),
	                              &r))) {
		log_error_errno(ID(worker_proxy_res), r, "Failed to create temporary buffer.");
		return -1;
	}

	if (sid_resource_write_tree_recursively(sid_resource_search(worker_proxy_res, SID_RESOURCE_SEARCH_TOP, NULL, NULL),
	                                        flags_to_format(int_msg.header.flags),
	                                        buf,
	                                        2,
	                                        false)) {
		log_error(ID(worker_proxy_res), "Failed to write resource tree.");
		goto out;
	}

	/* reply to the worker with the same header and data (cmd id) */
	r = worker_control_channel_send(worker_proxy_res,
	                                MAIN_WORKER_CHANNEL_ID,
	                                &(struct worker_data_spec) {.data               = data_spec->data,
	                                                            .data_size          = data_spec->data_size,
	                                                            .ext.used           = true,
	                                                            .ext.socket.fd_pass = sid_buffer_get_fd(buf)});
out:
	sid_buffer_destroy(buf);
	return r;
}

static int _worker_proxy_recv_fn(sid_resource_t          *worker_proxy_res,
                                 struct worker_channel   *chan,
                                 struct worker_data_spec *data_spec,
                                 void                    *arg)
{
	struct internal_msg_header int_msg;

	if (data_spec->data_size < INTERNAL_MSG_HEADER_SIZE) {
		log_error(ID(worker_proxy_res), INTERNAL_ERROR "Incorrect internal message header size.");
		return -1;
	}

	memcpy(&int_msg, data_spec->data, INTERNAL_MSG_HEADER_SIZE);

	if (int_msg.cat != MSG_CATEGORY_SYSTEM) {
		log_error(ID(worker_proxy_res), INTERNAL_ERROR "Received unexpected message category.");
		return -1;
	}

	switch (int_msg.header.cmd) {
		case SYSTEM_CMD_SYNC:
			return _worker_proxy_recv_system_cmd_sync(worker_proxy_res, data_spec, arg);

		case SYSTEM_CMD_RESOURCES:
			return _worker_proxy_recv_system_cmd_resources(worker_proxy_res, data_spec, arg);

		default:
			log_error(ID(worker_proxy_res), "Unknown system command.");
			return -1;
	}
}

static int _worker_recv_system_cmd_resources(sid_resource_t *worker_res, struct worker_data_spec *data_spec)
{
	static const char           _msg_prologue[] = "Received result from resource cmd for main process, but";
	const char                 *cmd_id;
	sid_resource_t             *cmd_res;
	struct sid_ucmd_ctx        *ucmd_ctx;
	SID_BUFFER_SIZE_PREFIX_TYPE msg_size;
	int                         r = -1;

	// TODO: make sure error path is not causing the client waiting for response to hang !!!

	if (!data_spec->ext.used) {
		log_error(ID(worker_res), "%s data handler is missing.", _msg_prologue);
		return -1;
	}

	if (read(data_spec->ext.socket.fd_pass, &msg_size, SID_BUFFER_SIZE_PREFIX_LEN) != SID_BUFFER_SIZE_PREFIX_LEN) {
		log_error_errno(ID(worker_res), errno, "%s failed to read shared memory size", _msg_prologue);
		goto out;
	}

	if (msg_size <= SID_BUFFER_SIZE_PREFIX_LEN) {
		log_error(ID(worker_res), "%s no data received.", _msg_prologue);
		goto out;
	} else if (msg_size > INTERNAL_MSG_MAX_FD_DATA_SIZE) {
		log_error(ID(worker_res), "Maximum internal messages size exceeded.");
		goto out;
	}

	/* cmd id needs at least 1 character with '0' at the end - so 2 characters at least! */
	if ((data_spec->data_size - INTERNAL_MSG_HEADER_SIZE) < 2) {
		log_error(ID(worker_res), "%s missing command id to match.", _msg_prologue);
		goto out;
	}

	cmd_id = data_spec->data + INTERNAL_MSG_HEADER_SIZE;

	if (!(cmd_res = sid_resource_search(worker_res, SID_RESOURCE_SEARCH_DFS, &sid_resource_type_ubridge_command, cmd_id))) {
		log_error(ID(worker_res), "%s failed to find command resource with id %s.", _msg_prologue, cmd_id);
		goto out;
	}

	ucmd_ctx                              = sid_resource_get_data(cmd_res);

	ucmd_ctx->resources.main_res_mem_size = msg_size;
	ucmd_ctx->resources.main_res_mem =
		mmap(NULL, ucmd_ctx->resources.main_res_mem_size, PROT_READ, MAP_SHARED, data_spec->ext.socket.fd_pass, 0);

	sid_resource_set_event_source_counter(ucmd_ctx->cmd_handler_es, SID_RESOURCE_POS_REL, 1);
	_change_cmd_state(cmd_res, CMD_EXEC_SCHEDULED);

	r = 0;
out:
	close(data_spec->ext.socket.fd_pass);
	return r;
}

static int _worker_recv_system_cmd_sync(sid_resource_t *worker_res, struct worker_data_spec *data_spec)
{
	static const char    _msg_prologue[] = "Received sync ack from main process, but";
	const char          *cmd_id;
	sid_resource_t      *cmd_res;
	struct sid_ucmd_ctx *ucmd_ctx;

	/* cmd_id needs at least 1 character with '\0' at the end - so 2 characters at least! */
	if ((data_spec->data_size - INTERNAL_MSG_HEADER_SIZE) < 2) {
		log_error(ID(worker_res), "%s missing command id to match.", _msg_prologue);
		_change_cmd_state(worker_res, CMD_ERROR);
		return -1;
	}

	cmd_id = data_spec->data + INTERNAL_MSG_HEADER_SIZE;

	if (!(cmd_res = sid_resource_search(worker_res, SID_RESOURCE_SEARCH_DFS, &sid_resource_type_ubridge_command, cmd_id))) {
		log_error(ID(worker_res), "%s failed to find command resource with id %s.", _msg_prologue, cmd_id);
		_change_cmd_state(worker_res, CMD_ERROR);
		return -1;
	}

	ucmd_ctx = sid_resource_get_data(cmd_res);

	sid_resource_set_event_source_counter(ucmd_ctx->cmd_handler_es, SID_RESOURCE_POS_REL, 1);
	_change_cmd_state(cmd_res, CMD_EXPBUF_ACKED);

	return 0;
}

static int _worker_recv_fn(sid_resource_t          *worker_res,
                           struct worker_channel   *chan,
                           struct worker_data_spec *data_spec,
                           void *arg                __unused)
{
	struct internal_msg_header int_msg;

	if (data_spec->data_size < INTERNAL_MSG_HEADER_SIZE) {
		log_error(ID(worker_res), INTERNAL_ERROR "Incorrect internal message header size.");
		return -1;
	}

	memcpy(&int_msg, data_spec->data, INTERNAL_MSG_HEADER_SIZE);

	switch (int_msg.cat) {
		case MSG_CATEGORY_SYSTEM:
			switch (int_msg.header.cmd) {
				case SYSTEM_CMD_SYNC:
					if (_worker_recv_system_cmd_sync(worker_res, data_spec) < 0)
						return -1;
					break;

				case SYSTEM_CMD_RESOURCES:
					if (_worker_recv_system_cmd_resources(worker_res, data_spec) < 0)
						return -1;
					break;

				default:
					log_error(ID(worker_res), INTERNAL_ERROR "Received unexpected system command.");
					return -1;
			}
			break;

		case MSG_CATEGORY_CLIENT:
			/*
			 * Command requested externally through a connection.
			 * sid_msg will be read from client through the connection.
			 */
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
			break;

		case MSG_CATEGORY_SELF:
			/*
			 * Command requested internally.
			 * Generate sid_msg out of int_msg as if it was sent through a connection.
			 */
			if (_create_command_resource(
				    worker_res,
				    &((struct sid_msg) {
					    .cat    = MSG_CATEGORY_SELF,
					    .size   = data_spec->data_size - sizeof(int_msg.cat),
					    .header = (struct sid_msg_header *) (data_spec->data + sizeof(int_msg.cat))})) < 0)
				return -1;
			break;
	}

	return 0;
}

static int _worker_init_fn(sid_resource_t *worker_res, void *arg)
{
	struct sid_ucmd_common_ctx *common_ctx  = arg;
	sid_resource_t             *old_top_res = sid_resource_search(common_ctx->res, SID_RESOURCE_SEARCH_TOP, NULL, NULL);

	/* only take inherited common resource and attach it to the worker */
	(void) sid_resource_isolate_with_children(common_ctx->res);
	(void) sid_resource_add_child(worker_res, common_ctx->res, SID_RESOURCE_NO_FLAGS);

	/* destroy remaining resources */
	(void) sid_resource_unref(old_top_res);

	return 0;
}

/* *res_p is set to the worker_proxy resource. If a new worker process is created, when it returns, *res_p will be NULL */
static int _get_worker(sid_resource_t *ubridge_res, sid_resource_t **res_p)
{
	struct ubridge *ubridge = sid_resource_get_data(ubridge_res);
	char            uuid[UTIL_UUID_STR_SIZE];
	util_mem_t      mem = {.base = uuid, .size = sizeof(uuid)};
	sid_resource_t *worker_control_res, *worker_proxy_res;

	*res_p = NULL;
	if (!(worker_control_res = sid_resource_search(ubridge->internal_res,
	                                               SID_RESOURCE_SEARCH_IMM_DESC,
	                                               &sid_resource_type_worker_control,
	                                               NULL))) {
		log_error(ID(ubridge_res), INTERNAL_ERROR "%s: Failed to find worker control resource.", __func__);
		return -1;
	}

	if ((worker_proxy_res = worker_control_get_idle_worker(worker_control_res)))
		*res_p = worker_proxy_res;
	else {
		log_debug(ID(ubridge_res), "Idle worker not found, creating a new one.");

		if (!util_uuid_gen_str(&mem)) {
			log_error(ID(ubridge_res), "Failed to generate UUID for new worker.");
			return -1;
		}

		if (worker_control_get_new_worker(worker_control_res, &((struct worker_params) {.id = uuid}), res_p) < 0)
			return -1;
	}

	return 0;
}

static int _on_ubridge_interface_event(sid_resource_event_source_t *es, int fd, uint32_t revents, void *data)
{
	sid_resource_t            *ubridge_res = data;
	struct ubridge            *ubridge     = sid_resource_get_data(ubridge_res);
	sid_resource_t            *worker_proxy_res;
	struct worker_data_spec    data_spec;
	struct internal_msg_header int_msg;
	int                        r;

	log_debug(ID(ubridge_res), "Received an event.");

	if (_get_worker(ubridge_res, &worker_proxy_res) < 0)
		return -1;

	/* If this is a worker process, exit the handler */
	if (!worker_proxy_res)
		return 0;

	int_msg.cat         = MSG_CATEGORY_CLIENT;
	int_msg.header      = (struct sid_msg_header) {0};

	data_spec.data      = &int_msg;
	data_spec.data_size = INTERNAL_MSG_HEADER_SIZE;
	data_spec.ext.used  = true;

	if ((data_spec.ext.socket.fd_pass = accept4(ubridge->socket_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC)) < 0) {
		log_sys_error(ID(ubridge_res), "accept", "");
		return -1;
	}

	if ((r = worker_control_channel_send(worker_proxy_res, MAIN_WORKER_CHANNEL_ID, &data_spec)) < 0) {
		log_error_errno(ID(ubridge_res), r, "worker_control_channel_send");
		r = -1;
	}

	(void) close(data_spec.ext.socket.fd_pass);
	return r;
}

int ubridge_cmd_dbdump(sid_resource_t *ubridge_res, const char *file_path)
{
	sid_resource_t             *worker_proxy_res;
	struct internal_msg_header *int_msg;
	struct worker_data_spec     data_spec;
	size_t                      file_path_size;
	char                        buf[INTERNAL_MSG_HEADER_SIZE + PATH_MAX + 1];

	if (_get_worker(ubridge_res, &worker_proxy_res) < 0)
		return -1;

	/* If this is a worker process, return right away */
	if (!worker_proxy_res)
		return 0;

	int_msg         = (struct internal_msg_header *) buf;
	int_msg->cat    = MSG_CATEGORY_SELF;
	int_msg->header = (struct sid_msg_header) {.status = 0, .prot = SID_PROTOCOL, .cmd = SELF_CMD_DBDUMP, .flags = 0};

	if (!file_path || !*file_path)
		file_path_size = 0;
	else {
		file_path_size = strlen(file_path) + 1;
		memcpy(buf + INTERNAL_MSG_HEADER_SIZE, file_path, file_path_size);
	}

	data_spec =
		(struct worker_data_spec) {.data = buf, .data_size = INTERNAL_MSG_HEADER_SIZE + file_path_size, .ext.used = false};

	return worker_control_channel_send(worker_proxy_res, MAIN_WORKER_CHANNEL_ID, &data_spec);
}

/*
static int _on_ubridge_time_event(sid_resource_event_source_t *es, uint64_t usec, void *data)
{
        sid_resource_t *ubridge_res = data;
        static int      counter     = 0;

        log_debug(ID(ubridge_res), "dumping db (%d)", counter++);
        (void) ubridge_cmd_dbdump(ubridge_res, NULL);

        sid_resource_rearm_time_event_source(es, SID_EVENT_TIME_RELATIVE, 10000000);
        return 0;
}
*/

static int _load_kv_store(sid_resource_t *ubridge_res, struct sid_ucmd_common_ctx *common_ctx)
{
	int fd;
	int r;

	if (common_ctx->gennum != 0) {
		log_error(ID(ubridge_res),
		          INTERNAL_ERROR "%s: unexpected KV generation number, KV store already loaded.",
		          __func__);
		return -1;
	}

	if ((fd = open(MAIN_KV_STORE_FILE_PATH, O_RDONLY)) < 0) {
		if (errno == ENOENT)
			return 0;

		log_error_errno(ID(ubridge_res), fd, "Failed to open db file");
		return -1;
	}

	r = _sync_main_kv_store(ubridge_res, common_ctx, fd);

	close(fd);
	return r;
}

static int _on_ubridge_udev_monitor_event(sid_resource_event_source_t *es, int fd, uint32_t revents, void *data)
{
	sid_resource_t     *ubridge_res = data;
	struct ubridge     *ubridge     = sid_resource_get_data(ubridge_res);
	sid_resource_t     *worker_control_res;
	struct udev_device *udev_dev;
	const char         *worker_id;
	int                 r = -1;

	if (!(udev_dev = udev_monitor_receive_device(ubridge->umonitor.mon)))
		goto out;

	if (!(worker_id = udev_device_get_property_value(udev_dev, KV_KEY_UDEV_SID_SESSION_ID)))
		goto out;

	if (!(worker_control_res =
	              sid_resource_search(ubridge_res, SID_RESOURCE_SEARCH_IMM_DESC, &sid_resource_type_worker_control, NULL)))
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

static int _set_up_kv_store_generation(struct sid_ucmd_common_ctx *ctx)
{
	kv_vector_t         vvalue[VVALUE_SINGLE_ALIGNED_CNT];
	sid_ucmd_kv_flags_t flags = value_flags_no_sync | KV_ALIGN;
	const char         *key;
	kv_scalar_t        *svalue;

	if (!(key = _compose_key(ctx->gen_buf,
	                         &((struct kv_key_spec) {.extra_op = NULL,
	                                                 .op       = KV_OP_SET,
	                                                 .dom      = ID_NULL,
	                                                 .ns       = KV_NS_GLOBAL,
	                                                 .ns_part  = ID_NULL,
	                                                 .id_cat   = ID_NULL,
	                                                 .id       = ID_NULL,
	                                                 .core     = KV_KEY_DB_GENERATION}))))
		return -1;

	if ((svalue = kv_store_get_value(ctx->kv_store_res, key, NULL, NULL))) {
		memcpy(&ctx->gennum, svalue->data + _svalue_ext_data_offset(svalue), sizeof(uint16_t));
		ctx->gennum++;
	} else
		ctx->gennum = 1;

	log_debug(ID(ctx->res), "Current generation number: %" PRIu16, ctx->gennum);

	_vvalue_header_prep(vvalue, VVALUE_CNT(vvalue), &null_int, &flags, &ctx->gennum, core_owner);
	_vvalue_data_prep(vvalue, VVALUE_CNT(vvalue), 0, &ctx->gennum, sizeof(ctx->gennum));

	kv_store_set_value(ctx->kv_store_res,
	                   key,
	                   vvalue,
	                   VVALUE_SINGLE_ALIGNED_CNT,
	                   KV_STORE_VALUE_VECTOR,
	                   KV_STORE_VALUE_OP_MERGE,
	                   NULL,
	                   NULL);

	_destroy_key(ctx->gen_buf, key);
	return 0;
}

static int _set_up_boot_id(struct sid_ucmd_common_ctx *ctx)
{
	char         boot_id[UTIL_UUID_STR_SIZE];
	kv_vector_t  vvalue[VVALUE_SINGLE_CNT];
	const char  *key;
	kv_scalar_t *svalue;
	char        *old_boot_id;
	int          r;

	if (!(key = _compose_key(ctx->gen_buf,
	                         &((struct kv_key_spec) {.extra_op = NULL,
	                                                 .op       = KV_OP_SET,
	                                                 .dom      = ID_NULL,
	                                                 .ns       = KV_NS_GLOBAL,
	                                                 .ns_part  = ID_NULL,
	                                                 .id_cat   = ID_NULL,
	                                                 .id       = ID_NULL,
	                                                 .core     = KV_KEY_BOOT_ID}))))
		return -1;

	if ((svalue = kv_store_get_value(ctx->kv_store_res, key, NULL, NULL)))
		old_boot_id = svalue->data + _svalue_ext_data_offset(svalue);
	else
		old_boot_id = NULL;

	if (!(util_uuid_get_boot_id(&(util_mem_t) {.base = boot_id, .size = sizeof(boot_id)}, &r)))
		return r;

	if (old_boot_id)
		log_debug(ID(ctx->res), "Previous system boot id: %s.", old_boot_id);

	log_debug(ID(ctx->res), "Current system boot id: %s.", boot_id);

	_vvalue_header_prep(vvalue, VVALUE_CNT(vvalue), &null_int, &value_flags_no_sync, &ctx->gennum, core_owner);
	_vvalue_data_prep(vvalue, VVALUE_CNT(vvalue), 0, boot_id, sizeof(boot_id));

	kv_store_set_value(ctx->kv_store_res,
	                   key,
	                   vvalue,
	                   VVALUE_IDX_DATA + 1,
	                   KV_STORE_VALUE_VECTOR,
	                   KV_STORE_VALUE_OP_MERGE,
	                   NULL,
	                   NULL);

	_destroy_key(ctx->gen_buf, key);
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

	if (sid_resource_create_io_event_source(ubridge_res,
	                                        NULL,
	                                        umonitor_fd,
	                                        _on_ubridge_udev_monitor_event,
	                                        0,
	                                        "udev monitor",
	                                        ubridge_res) < 0) {
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

static struct module_symbol_params block_symbol_params[]                  = {{
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

static struct module_symbol_params type_symbol_params[]                   = {{
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

static const struct sid_kv_store_resource_params main_kv_store_res_params = {.backend = KV_STORE_BACKEND_BPTREE, .bptree.order = 4};

static int _init_common(sid_resource_t *res, const void *kickstart_data, void **data)
{
	struct sid_ucmd_common_ctx *common_ctx;
	int                         r;

	if (!(common_ctx = mem_zalloc(sizeof(struct sid_ucmd_common_ctx)))) {
		log_error(ID(res), "Failed to allocate memory for common structure.");
		goto fail;
	}
	common_ctx->res = res;

	/*
	 * Set higher priority to kv_store_res compared to modules so they can
	 * still use the KV store even when destroying the whole resource tree.
	 */
	if (!(common_ctx->kv_store_res = sid_resource_create(common_ctx->res,
	                                                     &sid_resource_type_kv_store,
	                                                     SID_RESOURCE_RESTRICT_WALK_UP,
	                                                     MAIN_KV_STORE_NAME,
	                                                     &main_kv_store_res_params,
	                                                     SID_RESOURCE_PRIO_NORMAL - 1,
	                                                     SID_RESOURCE_NO_SERVICE_LINKS))) {
		log_error(ID(res), "Failed to create main key-value store.");
		goto fail;
	}

	if (!(common_ctx->gen_buf = sid_buffer_create(&((struct sid_buffer_spec) {.backend = SID_BUFFER_BACKEND_MALLOC,
	                                                                          .type    = SID_BUFFER_TYPE_LINEAR,
	                                                                          .mode    = SID_BUFFER_MODE_PLAIN}),
	                                              &((struct sid_buffer_init) {.size = 0, .alloc_step = PATH_MAX, .limit = 0}),
	                                              &r))) {
		log_error_errno(ID(res), r, "Failed to create generic buffer");
		goto fail;
	}

	_load_kv_store(res, common_ctx);
	if (_set_up_kv_store_generation(common_ctx) < 0 || _set_up_boot_id(common_ctx) < 0)
		goto fail;

	if (!(common_ctx->modules_res = sid_resource_create(common_ctx->res,
	                                                    &sid_resource_type_aggregate,
	                                                    SID_RESOURCE_NO_FLAGS,
	                                                    MODULES_AGGREGATE_ID,
	                                                    SID_RESOURCE_NO_PARAMS,
	                                                    SID_RESOURCE_PRIO_NORMAL,
	                                                    SID_RESOURCE_NO_SERVICE_LINKS))) {
		log_error(ID(res), "Failed to create aggreagete resource for module handlers.");
		goto fail;
	}

	struct module_registry_resource_params block_res_mod_params = {
		.directory     = SID_UCMD_BLOCK_MOD_DIR,
		.module_prefix = NULL,
		.module_suffix = ".so",
		.flags         = MODULE_REGISTRY_PRELOAD,
		.symbol_params = block_symbol_params,
		.cb_arg        = common_ctx,
	};

	struct module_registry_resource_params type_res_mod_params = {
		.directory     = SID_UCMD_TYPE_MOD_DIR,
		.module_prefix = NULL,
		.module_suffix = ".so",
		.flags         = MODULE_REGISTRY_PRELOAD,
		.symbol_params = type_symbol_params,
		.cb_arg        = common_ctx,
	};

	if (!(sid_resource_create(common_ctx->modules_res,
	                          &sid_resource_type_module_registry,
	                          SID_RESOURCE_DISALLOW_ISOLATION,
	                          MODULES_BLOCK_ID,
	                          &block_res_mod_params,
	                          SID_RESOURCE_PRIO_NORMAL,
	                          SID_RESOURCE_NO_SERVICE_LINKS)) ||
	    !(sid_resource_create(common_ctx->modules_res,
	                          &sid_resource_type_module_registry,
	                          SID_RESOURCE_DISALLOW_ISOLATION,
	                          MODULES_TYPE_ID,
	                          &type_res_mod_params,
	                          SID_RESOURCE_PRIO_NORMAL,
	                          SID_RESOURCE_NO_SERVICE_LINKS))) {
		log_error(ID(res), "Failed to create module handler.");
		goto fail;
	}

	*data = common_ctx;
	return 0;
fail:
	if (common_ctx) {
		if (common_ctx->gen_buf)
			sid_buffer_destroy(common_ctx->gen_buf);
		free(common_ctx);
	}

	return -1;
}

static int _destroy_common(sid_resource_t *res)
{
	struct sid_ucmd_common_ctx *common_ctx = sid_resource_get_data(res);

	sid_buffer_destroy(common_ctx->gen_buf);
	free(common_ctx);

	return 0;
}

static int _init_ubridge(sid_resource_t *res, const void *kickstart_data, void **data)
{
	struct ubridge             *ubridge = NULL;
	sid_resource_t             *common_res;
	struct sid_ucmd_common_ctx *common_ctx = NULL;

	if (!(ubridge = mem_zalloc(sizeof(struct ubridge)))) {
		log_error(ID(res), "Failed to allocate memory for ubridge structure.");
		goto fail;
	}
	ubridge->socket_fd = -1;

	if (!(ubridge->internal_res = sid_resource_create(res,
	                                                  &sid_resource_type_aggregate,
	                                                  SID_RESOURCE_RESTRICT_WALK_DOWN | SID_RESOURCE_DISALLOW_ISOLATION,
	                                                  INTERNAL_AGGREGATE_ID,
	                                                  ubridge,
	                                                  SID_RESOURCE_PRIO_NORMAL,
	                                                  SID_RESOURCE_NO_SERVICE_LINKS))) {
		log_error(ID(res), "Failed to create internal ubridge resource.");
		goto fail;
	}

	if (!(common_res = sid_resource_create(ubridge->internal_res,
	                                       &sid_resource_type_ubridge_common,
	                                       SID_RESOURCE_NO_FLAGS,
	                                       COMMON_ID,
	                                       common_ctx,
	                                       SID_RESOURCE_PRIO_NORMAL,
	                                       SID_RESOURCE_NO_SERVICE_LINKS))) {
		log_error(ID(res), "Failed to create ubridge common resource.");
		goto fail;
	}
	common_ctx                                                      = sid_resource_get_data(common_res);

	struct worker_control_resource_params worker_control_res_params = {
		.worker_type = WORKER_TYPE_INTERNAL,

		.init_cb_spec =
			(struct worker_init_cb_spec) {
				.cb  = _worker_init_fn,
				.arg = common_ctx,
			},

		.channel_specs = (struct worker_channel_spec[]) {
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
						.arg = common_ctx,
					},

				.proxy_tx_cb = NULL_WORKER_CHANNEL_CB_SPEC,
				.proxy_rx_cb =
					(struct worker_channel_cb_spec) {
						.cb  = _worker_proxy_recv_fn,
						.arg = common_ctx,
					},
			},
			NULL_WORKER_CHANNEL_SPEC,
		}};

	if (!sid_resource_create(ubridge->internal_res,
	                         &sid_resource_type_worker_control,
	                         SID_RESOURCE_NO_FLAGS,
	                         SID_RESOURCE_NO_CUSTOM_ID,
	                         &worker_control_res_params,
	                         SID_RESOURCE_PRIO_NORMAL,
	                         SID_RESOURCE_NO_SERVICE_LINKS)) {
		log_error(ID(res), "Failed to create worker control.");
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
	                                        sid_resource_type_ubridge.name,
	                                        res) < 0) {
		log_error(ID(res), "Failed to register interface with event loop.");
		goto fail;
	}

	if (_set_up_udev_monitor(res, &ubridge->umonitor) < 0) {
		log_error(ID(res), "Failed to set up udev monitor.");
		goto fail;
	}

	/*
	sid_resource_create_time_event_source(res,
	                                      NULL,
	                                      CLOCK_MONOTONIC,
	                                      SID_EVENT_TIME_RELATIVE,
	                                      10000000,
	                                      0,
	                                      _on_ubridge_time_event,
	                                      0,
	                                      "timer",
	                                      res);
	*/

	/*
	 * Call sid_util_kernel_cmdline_get_arg here to only read the kernel command
	 * line so we already have that preloaded for any possible workers.
	 */
	(void) sid_util_kernel_cmdline_get_arg("root", NULL, NULL);

	*data = ubridge;
	return 0;
fail:
	if (ubridge) {
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

	if (ubridge->socket_fd != -1)
		(void) close(ubridge->socket_fd);

	free(ubridge);
	return 0;
}

const sid_resource_type_t sid_resource_type_ubridge_command = {
	.name        = "command",
	.short_name  = "com",
	.description = "Internal resource representing single request (command) on ubridge interface.",
	.init        = _init_command,
	.destroy     = _destroy_command,
};

const sid_resource_type_t sid_resource_type_ubridge_connection = {
	.name        = "connection",
	.short_name  = "con",
	.description = "Internal resource representing single ubridge connection to handle requests.",
	.init        = _init_connection,
	.destroy     = _destroy_connection,
};

const sid_resource_type_t sid_resource_type_ubridge_common = {
	.name        = "common",
	.short_name  = "cmn",
	.description = "Internal resource representing common subtree used in both main and worker process.",
	.init        = _init_common,
	.destroy     = _destroy_common,
};

const sid_resource_type_t sid_resource_type_ubridge = {
	.name        = "ubridge",
	.short_name  = "ubr",
	.description = "Resource primarily providing bridge interface between udev and SID. ",
	.init        = _init_ubridge,
	.destroy     = _destroy_ubridge,
};
