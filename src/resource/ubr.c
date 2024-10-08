/*
 * SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "internal/comp-attrs.h"

#include "internal/common.h"

#include "resource/ubr.h"

#include "base/buf.h"
#include "base/comms.h"
#include "base/util.h"
#include "iface/ifc-internal.h"
#include "internal/bmp.h"
#include "internal/fmt.h"
#include "internal/mem.h"
#include "internal/util.h"
#include "resource/kvs.h"
#include "resource/mod-reg.h"
#include "resource/res.h"
#include "resource/ucmd-mod.h"
#include "resource/wrk-ctl.h"

#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <libgen.h>
#include <libudev.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define INTERNAL_AGGREGATE_ID      "ubr-int"
#define COMMON_ID                  "common"
#define MODULES_AGGREGATE_ID       "mods"
#define MODULES_BLOCK_ID           "block"
#define MODULES_TYPE_ID            "type"

#define UDEV_TAG_SID               "sid"
#define KV_KEY_UDEV_SID_TAGS       ".SID_TAGS" /* starts with '.' as we don't want this to store in udev db! */
#define KV_KEY_UDEV_SID_SESSION_ID ".SID_SESSION_ID"
#define KV_KEY_UDEV_SID_DEV_ID     "SID_DEV_ID"

#define MAIN_KV_STORE_NAME         "main"
#define MAIN_WORKER_CHANNEL_ID     "main"

#define SYSTEM_PROC_DEVICES_PATH   SYSTEM_PROC_PATH "/devices"
#define MAIN_KV_STORE_FILE_PATH    "/run/sid.db"

#define KV_PAIR_C                  "="
#define KV_END_C                   ""

#define ID_NULL                    ""
#define KV_KEY_NULL                ID_NULL

#define KV_INDEX_NOOP              0
#define KV_INDEX_ADD               1
#define KV_INDEX_REMOVE            2

#define KV_PREFIX_OP_SYNC_C        ">"
#define KV_PREFIX_OP_ARCHIVE_C     "~"
#define KV_PREFIX_OP_BLANK_C       " "
#define KV_PREFIX_OP_ILLEGAL_C     "X"
#define KV_PREFIX_OP_SET_C         ""
#define KV_PREFIX_OP_PLUS_C        "+"
#define KV_PREFIX_OP_MINUS_C       "-"

#define KV_PREFIX_NS_UNDEFINED_C   ""
#define KV_PREFIX_NS_UDEV_C        "U"
#define KV_PREFIX_NS_DEVICE_C      "D"
#define KV_PREFIX_NS_MODULE_C      "M"
#define KV_PREFIX_NS_DEVMOD_C      "X"
#define KV_PREFIX_NS_GLOBAL_C      "G"

#define KV_PREFIX_KEY_SYS_C        "#"

#define KV_KEY_DB_GENERATION       KV_PREFIX_KEY_SYS_C "DBGEN"
#define KV_KEY_BOOT_ID             KV_PREFIX_KEY_SYS_C "BOOTID"
#define KV_KEY_DEV_READY           KV_PREFIX_KEY_SYS_C "RDY"
#define KV_KEY_DEV_RESERVED        KV_PREFIX_KEY_SYS_C "RES"
#define KV_KEY_DEV_MOD             KV_PREFIX_KEY_SYS_C "MOD"

#define KV_KEY_DOM_ALIAS           "ALS"
#define KV_KEY_DOM_GROUP           "GRP"
#define KV_KEY_DOM_USER            "USR"

#define KV_KEY_GEN_GROUP_MEMBERS   KV_PREFIX_KEY_SYS_C "GMB"
#define KV_KEY_GEN_GROUP_IN        KV_PREFIX_KEY_SYS_C "GIN"

#define MOD_NAME_CORE              SID_MOD_NAME_DELIM
#define MOD_NAME_BLKEXT            "blkext"
#define MOD_NAME_NVME              "nvme"

#define DEV_NAME_PREFIX_NVME       "nvme"

#define DEV_ALIAS_DEVNO            "devno"
#define DEV_ALIAS_DSEQ             "dseq"
#define DEV_ALIAS_NAME             "name"

#define OWNER_CORE                 MOD_NAME_CORE
#define DEFAULT_VALUE_FLAGS_CORE   SID_KV_FL_SYNC_P | SID_KV_FL_RS | SID_KV_FL_RD

#define DEFAULT_CMD_TIM_OUT_USEC   180000000

#define CMD_DEV_PRINT_FMT          "%s (%s/%s)"
#define CMD_DEV_PRINT(ucmd_ctx)    ucmd_ctx->req_env.dev.udev.name, ucmd_ctx->req_env.dev.num_s, ucmd_ctx->req_env.dev.dsq_s

const sid_res_type_t sid_res_type_ubr;
const sid_res_type_t sid_res_type_ubr_cmn;
const sid_res_type_t sid_res_type_ubr_con;
const sid_res_type_t sid_res_type_ubr_cmd;

struct sid_ucmd_common_ctx {
	sid_res_t      *res;               /* resource representing this common ctx */
	sid_res_t      *block_mod_reg_res; /* block modules */
	sid_res_t      *type_mod_reg_res;  /* type modules */
	sid_res_t      *kvs_res;           /* main KV store or KV store snapshot */
	uint16_t        gennum;            /* current KV store generation number */
	struct sid_buf *gen_buf;           /* generic buffer */
};

struct ulink {
	struct udev         *udev;
	struct udev_monitor *mon;
};

struct ubridge {
	sid_res_t   *internal_res;
	int          socket_fd;
	struct ulink ulink;
};

typedef enum {
	CMD_SCAN_PHASE_A_INIT = 0,          /* core only */
	CMD_SCAN_PHASE_A_SCAN_PRE,          /* core + modules */
	CMD_SCAN_PHASE_A_SCAN_CURRENT,      /* core + modules */
	CMD_SCAN_PHASE_A_SCAN_NEXT,         /* core + modules */
	CMD_SCAN_PHASE_A_SCAN_POST_CURRENT, /* core + modules */
	CMD_SCAN_PHASE_A_SCAN_POST_NEXT,    /* core + modules */
	CMD_SCAN_PHASE_A_EXIT,              /* core + modules */

	CMD_SCAN_PHASE_REMOVE_INIT,
	CMD_SCAN_PHASE_REMOVE_CURRENT,
	CMD_SCAN_PHASE_REMOVE_EXIT,

	CMD_SCAN_PHASE_B_INIT,
	CMD_SCAN_PHASE_B_ACTION_CURRENT,
	CMD_SCAN_PHASE_B_ACTION_NEXT,
	CMD_SCAN_PHASE_B_EXIT,

	CMD_SCAN_PHASE_ERROR,
} cmd_scan_phase_t;

struct scan_mod_fns {
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
	int             fd;
	struct sid_buf *buf;
};

typedef enum {
	MSG_CATEGORY_SYSTEM, /* system message */
	MSG_CATEGORY_SELF,   /* self-induced message */
	MSG_CATEGORY_CLIENT, /* message coming from a client */
} msg_category_t;

typedef enum {
	CMD_STATE_UNDEFINED,           /* not defined yet */
	CMD_STATE_INI,                 /* initializing context for cmd */
	CMD_STATE_STG_WAIT,            /* wait for event and/or data to schedule new cmd stage execution  */
	CMD_STATE_EXE_SCHED,           /* cmd execution scheduled */
	CMD_STATE_EXE_RUN,             /* cmd execution running */
	CMD_STATE_EXE_WAIT,            /* wait for event and/or data to resume cmd execution */
	CMD_STATE_RES_BUILD,           /* build cmd stage results */
	CMD_STATE_RES_EXPBUF_F_SEND,   /* send cmd stage export buffer as first */
	CMD_STATE_RES_RESBUF_L_SEND,   /* send cmd state result buffer as last */
	CMD_STATE_RES_RESBUF_F_SEND,   /* send cmd stage result buffer as first */
	CMD_STATE_RES_EXPBUF_L_SEND,   /* send cmd state export buffer as last */
	CMD_STATE_RES_EXPBUF_WAIT_ACK, /* wait for cmd stage export buffer reception ack */
	CMD_STATE_TIM_OUT,             /* cmd timeout */
	CMD_STATE_ERR,                 /* cmd error */
	CMD_STATE_FIN,                 /* all cmd stages done, all results successfully sent */
} cmd_state_t;

static const char *cmd_state_str[]        = {[CMD_STATE_UNDEFINED]           = "CMD_UNDEFINED",
                                             [CMD_STATE_INI]                 = "CMD_INI",
                                             [CMD_STATE_STG_WAIT]            = "CMD_STG_WAIT",
                                             [CMD_STATE_EXE_SCHED]           = "CMD_EXE_SCHED",
                                             [CMD_STATE_EXE_RUN]             = "CMD_EXE_RUN",
                                             [CMD_STATE_EXE_WAIT]            = "CMD_EXE_WAIT",
                                             [CMD_STATE_RES_BUILD]           = "CMD_RES_BUILD",
                                             [CMD_STATE_RES_EXPBUF_F_SEND]   = "CMD_RES_EXPBUF_F_SEND",
                                             [CMD_STATE_RES_RESBUF_L_SEND]   = "CMD_RES_RESBUF_L_SEND",
                                             [CMD_STATE_RES_RESBUF_F_SEND]   = "CMD_RES_RESBUF_F_SEND",
                                             [CMD_STATE_RES_EXPBUF_L_SEND]   = "CMD_RES_EXPBUF_L_SEND",
                                             [CMD_STATE_RES_EXPBUF_WAIT_ACK] = "CMD_RES_EXPBUF_WAIT_ACK",
                                             [CMD_STATE_TIM_OUT]             = "CMD_TIM_OUT",
                                             [CMD_STATE_ERR]                 = "CMD_ERR",
                                             [CMD_STATE_FIN]                 = "CMD_FIN"};

static const char * const dev_ready_str[] = {
	[SID_DEV_RDY_UNDEFINED]     = "RDY_UNDEFINED",
	[SID_DEV_RDY_REMOVED]       = "RDY_REMOVED",
	[SID_DEV_RDY_UNPROCESSED]   = "RDY_UNPROCESSED",
	[SID_DEV_RDY_UNCONFIGURED]  = "RDY_UNCONFIGURED",
	[SID_DEV_RDY_UNINITIALIZED] = "RDY_UNINITIALIZED",
	[SID_DEV_RDY_UNAVAILABLE]   = "RDY_UNAVAILABLE",
	[SID_DEV_RDY_PRIVATE]       = "RDY_PRIVATE",
	[SID_DEV_RDY_FLAT]          = "RDY_FLAT",
	[SID_DEV_RDY_PUBLIC]        = "RDY_PUBLIC",
};

static const char * const dev_reserved_str[] = {
	[SID_DEV_RES_UNDEFINED]   = "RES_UNDEFINED",
	[SID_DEV_RES_UNPROCESSED] = "RES_UNPROCESSED",
	[SID_DEV_RES_RESERVED]    = "RES_RESERVED",
	[SID_DEV_RES_USED]        = "RES_USED",
	[SID_DEV_RES_FREE]        = "RES_FREE",
};

struct sid_ucmd_ctx {
	/* request */
	msg_category_t            req_cat; /* request category */
	struct sid_ifc_msg_header req_hdr; /* request header */

	/* request environment */
	union {
		struct {
			const char    *uid_s; /* device identifier string */
			const char    *num_s; /* device number string (in "major_minor" format) */
			const char    *dsq_s; /* device sequence number string */
			struct udevice udev;
		} dev;

		const char *exp_path; /* export path */
	} req_env;

	/* common context */
	struct sid_ucmd_common_ctx *common;

	/* cmd specific context */
	union {
		struct {
			sid_res_iter_t         *block_mod_iter;
			sid_res_t              *type_mod_res_current;
			sid_res_t              *type_mod_res_next;
			cmd_scan_phase_t        phase; /* current scan phase */
			sid_ucmd_dev_ready_t    dev_ready;
			sid_ucmd_dev_reserved_t dev_reserved;
		} scan;

		struct {
			void  *main_res_mem;      /* mmap-ed memory with result from main process */
			size_t main_res_mem_size; /* overall size of main_res_mem */
		} resources;
	};

	/* cmd stage and state tracking */
	unsigned int stage;      /* current command stage */
	cmd_state_t  prev_state; /* previous command state */
	cmd_state_t  state;      /* current command state */

	/* event sources */
	sid_res_ev_src_t *cmd_handler_es; /* event source for deferred execution of _cmd_handler */
	sid_res_ev_src_t *tim_out_es;     /* event source for timeout event */

	/* response */
	struct sid_ifc_msg_header res_hdr; /* response header */
	struct sid_buf           *prn_buf; /* print buffer */
	struct sid_buf           *res_buf; /* response buffer */
	struct sid_buf           *exp_buf; /* export buffer */

	/* cleanup */
	struct sid_buf *uns_buf; /* unset buffer */
};

struct cmd_reg {
	const char *name;
	uint32_t    flags;
	int (*exec)(sid_res_t *cmd_res);
	unsigned     stage_count;
	const char **stage_names;
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

struct kv_unset_nfo {
	uint64_t    seqnum;
	const char *owner;
};

struct kv_update_arg {
	sid_res_t      *res;
	struct sid_buf *gen_buf;
	bool            is_sync;
	void           *custom;   /* in/out */
	int             ret_code; /* out */
};

typedef enum {
	MOD_NO_MATCH,   /* modules do not match */
	MOD_MATCH,      /* modules do match (1:1) */
	MOD_CORE_MATCH, /* modules do match (core) */
	MOD_SUB_MATCH,  /* modules do match (submod of a mod) */
	MOD_SUP_MATCH,  /* modules do match (supmod of a mod) */
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
	kv_op_t         op;
	delta_flags_t   flags;
	struct sid_buf *plus;
	struct sid_buf *minus;
	struct sid_buf *final;
};

typedef enum {
	_KEY_PART_START  = 0x0,
	KEY_PART_OP      = 0x0,
	KEY_PART_DOM     = 0x1,
	KEY_PART_NS      = 0x2,
	KEY_PART_NS_PART = 0x3,
	KEY_PART_ID_CAT  = 0x4,
	KEY_PART_ID      = 0x5,
	KEY_PART_CORE    = 0x6,
	_KEY_PART_COUNT,
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

static const char *op_to_key_prefix_map[] = {[KV_OP_ILLEGAL] = KV_PREFIX_OP_ILLEGAL_C,
                                             [KV_OP_SET]     = KV_PREFIX_OP_SET_C,
                                             [KV_OP_PLUS]    = KV_PREFIX_OP_PLUS_C,
                                             [KV_OP_MINUS]   = KV_PREFIX_OP_MINUS_C};

static const char *ns_to_key_prefix_map[] = {[SID_KV_NS_UNDEFINED] = KV_PREFIX_NS_UNDEFINED_C,
                                             [SID_KV_NS_UDEV]      = KV_PREFIX_NS_UDEV_C,
                                             [SID_KV_NS_DEVICE]    = KV_PREFIX_NS_DEVICE_C,
                                             [SID_KV_NS_MODULE]    = KV_PREFIX_NS_MODULE_C,
                                             [SID_KV_NS_DEVMOD]    = KV_PREFIX_NS_DEVMOD_C,
                                             [SID_KV_NS_GLOBAL]    = KV_PREFIX_NS_GLOBAL_C};

struct kv_rel_spec {
	struct kv_delta    *delta;
	struct kv_delta    *abs_delta;
	struct kv_key_spec *cur_key_spec;
	struct kv_key_spec *rel_key_spec;
};

struct cross_bitmap_calc_arg {
	kv_vector_t *old_vvalue;
	size_t       old_vsize;
	struct bmp  *old_bmp;
	kv_vector_t *new_vvalue;
	size_t       new_vsize;
	struct bmp  *new_bmp;
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
	SYSTEM_CMD_UMONITOR,
	SYSTEM_CMD_RESOURCES,
	_SYSTEM_CMD_END = SYSTEM_CMD_RESOURCES,
} system_cmd_t;

struct sid_msg {
	msg_category_t             cat;  /* keep this first so we can decide how to read the rest */
	size_t                     size; /* header + data */
	struct sid_ifc_msg_header *header;
};

struct internal_msg_header {
	msg_category_t cat; /* keep this first so we can decide how to read the rest */
	struct sid_ifc_msg_header
		header; /* reusing sid_ifc_msg_header here to avoid defining a new struct with subset of fields we need */
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
#define CMD_SESSION_ID                UINT32_C(0x00000200) /* generate session ID */

/*
 * Capability flags for 'scan' command phases (phases are represented as subcommands).
 */
#define CMD_SCAN_CAP_RDY              UINT32_C(0x00000001) /* can set ready state */
#define CMD_SCAN_CAP_RES              UINT32_C(0x00000002) /* can set reserved state */
#define CMD_SCAN_CAP_ALL              UINT32_C(0xFFFFFFFF) /* can set anything */

static bool _cmd_root_only[] = {
	[SID_IFC_CMD_UNDEFINED]  = false,
	[SID_IFC_CMD_UNKNOWN]    = false,
	[SID_IFC_CMD_ACTIVE]     = false,
	[SID_IFC_CMD_CHECKPOINT] = true,
	[SID_IFC_CMD_REPLY]      = false,
	[SID_IFC_CMD_SCAN]       = true,
	[SID_IFC_CMD_VERSION]    = false,
	[SID_IFC_CMD_DBDUMP]     = true,
	[SID_IFC_CMD_DBSTATS]    = true,
	[SID_IFC_CMD_RESOURCES]  = true,
	[SID_IFC_CMD_DEVICES]    = true,
};

static struct cmd_reg      _cmd_scan_phase_regs[];
static sid_ucmd_kv_flags_t value_flags_no_sync = (DEFAULT_VALUE_FLAGS_CORE) & ~SID_KV_FL_SYNC;
static char               *core_owner          = OWNER_CORE;
static uint64_t            null_int            = 0;
static struct iovec        null_iovec          = {.iov_base = NULL, .iov_len = 0};

static int _do_kv_delta_set(char *key, kv_vector_t *vvalue, size_t vsize, struct kv_update_arg *update_arg);

udev_action_t sid_ucmd_ev_get_dev_action(struct sid_ucmd_ctx *ucmd_ctx)
{
	return ucmd_ctx->req_env.dev.udev.action;
}

int sid_ucmd_ev_get_dev_major(struct sid_ucmd_ctx *ucmd_ctx)
{
	return ucmd_ctx->req_env.dev.udev.major;
}

int sid_ucmd_ev_get_dev_minor(struct sid_ucmd_ctx *ucmd_ctx)
{
	return ucmd_ctx->req_env.dev.udev.minor;
}

const char *sid_ucmd_ev_get_dev_path(struct sid_ucmd_ctx *ucmd_ctx)
{
	return ucmd_ctx->req_env.dev.udev.path;
}

const char *sid_ucmd_ev_get_dev_name(struct sid_ucmd_ctx *ucmd_ctx)
{
	return ucmd_ctx->req_env.dev.udev.name;
}

udev_devtype_t sid_ucmd_ev_get_dev_type(struct sid_ucmd_ctx *ucmd_ctx)
{
	return ucmd_ctx->req_env.dev.udev.type;
}

uint64_t sid_ucmd_ev_get_dev_seqnum(struct sid_ucmd_ctx *ucmd_ctx)
{
	return ucmd_ctx->req_env.dev.udev.seqnum;
}

uint64_t sid_ucmd_ev_get_dev_diskseq(struct sid_ucmd_ctx *ucmd_ctx)
{
	return ucmd_ctx->req_env.dev.udev.diskseq;
}

const char *sid_ucmd_ev_get_dev_synth_uuid(struct sid_ucmd_ctx *ucmd_ctx)
{
	return ucmd_ctx->req_env.dev.udev.synth_uuid;
}

static char *_do_compose_key(struct sid_buf *buf, struct kv_key_spec *key_spec, int prefix_only)
{
	static const char fmt[] = "%s"                  /* space for extra op */
				  "%s" SID_KVS_KEY_JOIN /* op */
				  "%s" SID_KVS_KEY_JOIN /* dom */
				  "%s" SID_KVS_KEY_JOIN /* ns */
				  "%s" SID_KVS_KEY_JOIN /* ns_part */
				  "%s" SID_KVS_KEY_JOIN /* id_cat */
				  "%s" SID_KVS_KEY_JOIN /* id */
				  "%s";
	char *key;

	/* <op>:<dom>:<ns>:<ns_part>:<id_cat>:<id>[:<core>] */

	if (buf) {
		if (sid_buf_add_fmt(buf,
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
		             prefix_only ? KV_KEY_NULL : key_spec->core) < 0)
			key = NULL;
	}

	return key;
}

static char *_compose_key(struct sid_buf *buf, struct kv_key_spec *key_spec)
{
	/* <extra_op><op>:<dom>:<ns>:<ns_part>:<id_cat>:<id>:<core> */
	return _do_compose_key(buf, key_spec, 0);
}

static char *_compose_key_prefix(struct sid_buf *buf, struct kv_key_spec *key_spec)
{
	/* <op>:<dom>:<ns>:<ns_part><id_cat>:<id> */
	return _do_compose_key(buf, key_spec, 1);
}

static key_part_t _decompose_key(const char *key, struct iovec *parts)
{
	key_part_t  part;
	const char *start = key, *end;
	size_t      len;

	for (part = _KEY_PART_START; part < _KEY_PART_COUNT; part++) {
		if ((part == (_KEY_PART_COUNT - 1)) || !(end = strstr(start, SID_KVS_KEY_JOIN))) {
			len = strlen(start);
			end = start + len;
		} else
			len = end - start;

		parts[part].iov_base = (void *) start;
		parts[part].iov_len  = len;

		if (!end[0])
			break;

		start = end + 1;
	}

	return part;
}

#define STR_TO_IOVEC(str) (str) ? ((struct iovec) {.iov_base = (void *) (str), .iov_len = strlen((str))}) : null_iovec

static void _key_spec_to_parts(struct kv_key_spec *key_spec, struct iovec *parts)
{
	parts[KEY_PART_OP]      = STR_TO_IOVEC(op_to_key_prefix_map[key_spec->op]);
	parts[KEY_PART_DOM]     = STR_TO_IOVEC(key_spec->dom);
	parts[KEY_PART_NS]      = STR_TO_IOVEC(ns_to_key_prefix_map[key_spec->ns]);
	parts[KEY_PART_NS_PART] = STR_TO_IOVEC(key_spec->ns_part);
	parts[KEY_PART_ID_CAT]  = STR_TO_IOVEC(key_spec->id_cat);
	parts[KEY_PART_ID]      = STR_TO_IOVEC(key_spec->id);
	parts[KEY_PART_CORE]    = STR_TO_IOVEC(key_spec->core);
}

static void _destroy_key(struct sid_buf *buf, const char *key)
{
	if (!key)
		return;

	if (buf)
		sid_buf_rewind_mem(buf, key);
	else
		free((void *) key);
}

static const char *_get_key_part(const char *key, key_part_t req_part, size_t *len)
{
	key_part_t  part;
	const char *start = key, *end;

	for (part = _KEY_PART_START; part < req_part; part++) {
		if (!(start = strstr(start, SID_KVS_KEY_JOIN)))
			return NULL;
		start++;
	}

	if (len) {
		if (req_part == _KEY_PART_COUNT - 1)
			*len = strlen(start);
		else {
			if (!(end = strstr(start, SID_KVS_KEY_JOIN)))
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
		return SID_KV_NS_UNDEFINED;

	if (str[0] == KV_PREFIX_NS_UDEV_C[0])
		return SID_KV_NS_UDEV;
	else if (str[0] == KV_PREFIX_NS_DEVICE_C[0])
		return SID_KV_NS_DEVICE;
	else if (str[0] == KV_PREFIX_NS_MODULE_C[0])
		return SID_KV_NS_MODULE;
	else if (str[0] == KV_PREFIX_NS_DEVMOD_C[0])
		return SID_KV_NS_DEVMOD;
	else if (str[0] == KV_PREFIX_NS_GLOBAL_C[0])
		return SID_KV_NS_GLOBAL;
	else
		return SID_KV_NS_UNDEFINED;
}

static const char *_copy_ns_part_from_key(const char *key, char *buf, size_t buf_size)
{
	const char *str;
	size_t      len;

	/*                 |<----->|
	   <op>:<dom>:<ns>:<ns_part><id_cat>:<id>[:<core>]
	*/

	if (!(str = _get_key_part(key, KEY_PART_NS_PART, &len)))
		return NULL;

	return util_str_copy_len(str, len, buf, buf_size);
}

static const char *_copy_id_from_key(const char *key, char *buf, size_t buf_size)
{
	const char *str;
	size_t      len;

	/*                                   |<>|
	   <op>:<dom>:<ns>:<ns_part><id_cat>:<id>[:<core>]
	*/

	if (!(str = _get_key_part(key, KEY_PART_ID, &len)))
		return NULL;

	return util_str_copy_len(str, len, buf, buf_size);
}

static void _vvalue_header_prep(kv_vector_t         *vvalue,
                                size_t               vvalue_size,
                                uint64_t            *seqnum,
                                sid_ucmd_kv_flags_t *flags,
                                uint16_t            *gennum,
                                char                *owner)
{
	size_t owner_size = strlen(owner) + 1;

	if (*flags & SID_KV_FL_ALIGN) {
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
	if (VVALUE_FLAGS(vvalue) & SID_KV_FL_ALIGN) {
		assert(vvalue_size >= VVALUE_IDX_DATA_ALIGNED + idx);
		vvalue[VVALUE_IDX_DATA_ALIGNED + idx] = (kv_vector_t) {data, data_size};
	} else {
		assert(vvalue_size >= VVALUE_IDX_DATA + idx);
		vvalue[VVALUE_IDX_DATA + idx] = (kv_vector_t) {data, data_size};
	}
}

static kv_vector_t *
	_get_vvalue(sid_kvs_val_fl_t kv_store_value_flags, void *value, size_t value_size, kv_vector_t *vvalue, size_t vvalue_size)
{
	kv_scalar_t *svalue;
	size_t       owner_size;
	size_t       padding_size;

	if (!value)
		return NULL;

	if (kv_store_value_flags & SID_KVS_VAL_FL_VECTOR)
		return value;

	svalue     = value;
	owner_size = strlen(svalue->data) + 1;

	if (svalue->flags & SID_KV_FL_ALIGN) {
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

static const char *_buffer_get_vvalue_str(struct sid_buf *buf, bool unset, kv_vector_t *vvalue, size_t vvalue_size)
{
	size_t      buf_offset, start_idx, i;
	const char *str;

	if (unset) {
		if (sid_buf_add_fmt(buf, (const void **) &str, NULL, "NULL") < 0)
			return NULL;
		return str;
	}

	buf_offset = sid_buf_count(buf);
	start_idx  = VVALUE_FLAGS(vvalue) & SID_KV_FL_ALIGN ? VVALUE_IDX_DATA_ALIGNED : VVALUE_IDX_DATA;

	for (i = start_idx; i < vvalue_size; i++) {
		if ((sid_buf_add(buf, vvalue[i].iov_base, vvalue[i].iov_len - 1, NULL, NULL) < 0) ||
		    (sid_buf_add(buf, " ", 1, NULL, NULL) < 0))
			goto fail;
	}

	if (sid_buf_add(buf, "\0", 1, NULL, NULL) < 0)
		goto fail;
	sid_buf_get_data_from(buf, buf_offset, (const void **) &str, NULL);

	return str;
fail:
	sid_buf_rewind(buf, buf_offset, SID_BUF_POS_ABS);
	return NULL;
}

static int _write_kv_store_stats(struct sid_dbstats *stats, sid_res_t *kv_store_res)
{
	sid_kvs_iter_t *iter;
	const char     *key;
	size_t          size;
	size_t          meta_size, int_size, int_data_size, ext_size, ext_data_size;

	memset(stats, 0, sizeof(*stats));
	if (!(iter = sid_kvs_iter_create(kv_store_res, NULL, NULL))) {
		sid_res_log_error(kv_store_res, SID_INTERNAL_ERROR "%s: failed to create record iterator", __func__);
		return -ENOMEM;
	}
	while (sid_kvs_iter_next(iter, &size, &key, NULL)) {
		stats->nr_kv_pairs++;
		sid_kvs_iter_current_size(iter, &int_size, &int_data_size, &ext_size, &ext_data_size);
		stats->key_size            += strlen(key) + 1;
		stats->value_int_size      += int_size;
		stats->value_int_data_size += int_data_size;
		stats->value_ext_size      += ext_size;
		stats->value_ext_data_size += ext_data_size;
	}
	sid_kvs_get_size(kv_store_res, &meta_size, &int_size);
	if (stats->value_int_size != int_size)
		sid_res_log_error(kv_store_res,
		                  SID_INTERNAL_ERROR "%s: kv-store size mismatch: %" PRIu64 " is not equal to %zu",
		                  __func__,
		                  stats->value_int_size,
		                  int_size);
	stats->meta_size = meta_size;
	sid_kvs_iter_destroy(iter);
	return 0;
}

static int _check_kv_index_needed(struct kv_update_arg *update_arg, kv_vector_t *vvalue_old, kv_vector_t *vvalue_new)
{
	int old_indexed, new_indexed;

	if (update_arg->is_sync)
		return KV_INDEX_NOOP;

	old_indexed = vvalue_old ? VVALUE_FLAGS(vvalue_old) & SID_KV_FL_SYNC : 0;
	new_indexed = vvalue_new ? VVALUE_FLAGS(vvalue_new) & SID_KV_FL_SYNC : 0;

	if (old_indexed && !new_indexed)
		return KV_INDEX_REMOVE;

	if (!old_indexed && new_indexed)
		return KV_INDEX_ADD;

	return KV_INDEX_NOOP;
}

static int _manage_kv_index(struct kv_update_arg *update_arg, char *key)
{
	int r;

	switch (update_arg->ret_code) {
		case KV_INDEX_ADD:
			key[0] = KV_PREFIX_OP_SYNC_C[0];
			r      = sid_kvs_add_alias(update_arg->res, key + 1, key, false);
			key[0] = ' ';
			break;
		case KV_INDEX_REMOVE:
			key[0] = KV_PREFIX_OP_SYNC_C[0];
			r      = sid_kvs_unset(update_arg->res, key, NULL, NULL);
			key[0] = ' ';
			break;
		default:
			r = 0;
	}

	return r;
}

static mod_match_t _mod_match(const char *mod1, const char *mod2)
{
	size_t i = 0;

	if (!strcmp(mod2, MOD_NAME_CORE))
		return MOD_CORE_MATCH;

	while ((mod1[i] && mod2[i]) && (mod1[i] == mod2[i]))
		i++;

	if (!mod1[i] && !mod2[i])
		/* match - same mod */
		return MOD_MATCH;

	if (i && mod2[i]) {
		if (i == SID_MOD_NAME_DELIM_LEN || !strncmp(mod2 + i, SID_MOD_NAME_DELIM, SID_MOD_NAME_DELIM_LEN))
			/* match - mod2 is submnod of mod1 */
			return MOD_SUB_MATCH;
		else
			/* no match */
			return MOD_NO_MATCH;
	} else if (i && mod1[i]) {
		if (i == SID_MOD_NAME_DELIM_LEN || !strncmp(mod1 + i, SID_MOD_NAME_DELIM, SID_MOD_NAME_DELIM_LEN))
			/* match - mod2 is supermod of mod1 */
			return MOD_SUP_MATCH;
	}

	/* no match */
	return MOD_NO_MATCH;
}

static int _check_kv_wr_allowed(struct kv_update_arg *update_arg, const char *key, kv_vector_t *vvalue_old, kv_vector_t *vvalue_new)
{
	static const char    reason_reserved[] = "reserved";
	static const char    reason_readonly[] = "read-only";
	static const char    reason_private[]  = "private";
	struct kv_unset_nfo *unset_nfo;
	sid_ucmd_kv_flags_t  old_flags;
	const char          *old_owner;
	const char          *new_owner;
	const char          *reason;
	int                  r = 0;

	if (!vvalue_old)
		return 0;

	old_flags = VVALUE_FLAGS(vvalue_old);
	old_owner = VVALUE_OWNER(vvalue_old);

	if (vvalue_new)
		new_owner = VVALUE_OWNER(vvalue_new);
	else {
		unset_nfo = update_arg->custom;
		new_owner = unset_nfo->owner;
	}

	switch (_mod_match(old_owner, new_owner)) {
		case MOD_NO_MATCH:
			if (old_flags & SID_KV_FL_FRG_WR)
				r = 1;
			else {
				if (old_flags & SID_KV_FL_RS) {
					reason = reason_reserved;
					r      = -EBUSY;
				} else if (old_flags & SID_KV_FL_FRG_RD) {
					reason = reason_readonly;
					r      = -EPERM;
				} else {
					reason = reason_private;
					r      = -EACCES;
				}
			}
			break;
		case MOD_MATCH:
		case MOD_CORE_MATCH:
			r = 1;
			break;
		case MOD_SUB_MATCH:
			if (old_flags & SID_KV_FL_SUB_WR)
				r = 1;
			else {
				if (old_flags & SID_KV_FL_RS) {
					reason = reason_reserved;
					r      = -EBUSY;
				} else if (old_flags & SID_KV_FL_SUB_RD) {
					reason = reason_readonly;
					r      = -EPERM;
				} else {
					reason = reason_private;
					r      = -EACCES;
				}
			}
			break;
		case MOD_SUP_MATCH:
			if (old_flags & SID_KV_FL_SUP_WR)
				r = 1;
			else {
				if (old_flags & SID_KV_FL_RS) {
					reason = reason_reserved;
					r      = -EBUSY;
				} else if (old_flags & SID_KV_FL_SUP_RD) {
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
		sid_res_log_debug(update_arg->res,
		                  "Module %s can't write value with key %s which is %s and already attached to module %s.",
		                  new_owner,
		                  key,
		                  reason,
		                  old_owner);

	return r;
}

static int _kv_cb_write(struct sid_kvs_update_spec *spec)
{
	struct kv_update_arg *update_arg = spec->arg;
	kv_vector_t           tmp_vvalue_old[VVALUE_SINGLE_ALIGNED_CNT];
	kv_vector_t           tmp_vvalue_new[VVALUE_SINGLE_ALIGNED_CNT];
	kv_vector_t          *vvalue_old, *vvalue_new;

	vvalue_old = _get_vvalue(spec->old_flags, spec->old_data, spec->old_data_size, tmp_vvalue_old, VVALUE_CNT(tmp_vvalue_old));
	vvalue_new = _get_vvalue(spec->new_flags, spec->new_data, spec->new_data_size, tmp_vvalue_new, VVALUE_CNT(tmp_vvalue_old));

	if ((update_arg->ret_code = _check_kv_wr_allowed(update_arg, spec->key, vvalue_old, vvalue_new)) < 0)
		return 0;

	update_arg->ret_code = _check_kv_index_needed(update_arg, vvalue_old, vvalue_new);
	return 1;
}

static int _kv_cb_reserve(struct sid_kvs_update_spec *spec)
{
	struct kv_update_arg *update_arg = spec->arg;
	kv_vector_t           tmp_vvalue_old[VVALUE_SINGLE_ALIGNED_CNT];
	kv_vector_t           tmp_vvalue_new[VVALUE_SINGLE_ALIGNED_CNT];
	kv_vector_t          *vvalue_old, *vvalue_new;
	struct kv_unset_nfo  *unset_nfo;
	const char           *new_owner;

	vvalue_new = _get_vvalue(spec->new_flags, spec->new_data, spec->new_data_size, tmp_vvalue_new, VVALUE_CNT(tmp_vvalue_new));

	if (vvalue_new)
		new_owner = VVALUE_OWNER(vvalue_new);
	else {
		unset_nfo = update_arg->custom;
		new_owner = unset_nfo->owner;
	}

	if ((vvalue_old = _get_vvalue(spec->old_flags,
	                              spec->old_data,
	                              spec->old_data_size,
	                              tmp_vvalue_old,
	                              VVALUE_CNT(tmp_vvalue_old)))) {
		/* only allow the same module that reserved before to re-reserve/unreserve */
		switch (_mod_match(VVALUE_OWNER(vvalue_old), new_owner)) {
			case MOD_MATCH:
			case MOD_CORE_MATCH:
				break;

			case MOD_NO_MATCH:
			case MOD_SUB_MATCH:
			case MOD_SUP_MATCH:
				sid_res_log_debug(update_arg->res,
				                  "Module %s can't reserve key %s which is already reserved by module %s.",
				                  new_owner,
				                  spec->key,
				                  VVALUE_OWNER(vvalue_old));
				update_arg->ret_code = -EPERM;
				return 0;
		}
	}

	update_arg->ret_code = _check_kv_index_needed(update_arg, vvalue_old, vvalue_new);
	return 1;
}

static const char *_owner_name(sid_res_t *res)
{
	return res ? sid_mod_get_full_name(res) : MOD_NAME_CORE;
}

static size_t _svalue_ext_data_offset(kv_scalar_t *svalue)
{
	size_t owner_size = strlen(svalue->data) + 1;

	if (svalue->flags & SID_KV_FL_ALIGN)
		return owner_size + MEM_ALIGN_UP_PAD(SVALUE_HEADER_SIZE + owner_size, SVALUE_DATA_ALIGNMENT);

	return owner_size;
}

static bool _is_string_data(char *ptr, size_t len)
{
	int i;

	if (ptr[len - 1] != '\0')
		return false;
	for (i = 0; i < len - 1; i++)
		if (!isprint(ptr[i]))
			return false;
	return true;
}

static void _print_vvalue(kv_vector_t    *vvalue,
                          bool            vector,
                          size_t          size,
                          const char     *name,
                          fmt_output_t    format,
                          struct sid_buf *buf,
                          int             level)
{
	size_t start_idx = VVALUE_FLAGS(vvalue) & SID_KV_FL_ALIGN ? VVALUE_IDX_DATA_ALIGNED : VVALUE_IDX_DATA;
	int    i;

	if (vector) {
		fmt_arr_start(format, buf, level, name, true);
		for (i = start_idx; i < size; i++) {
			if (vvalue[i].iov_len) {
				if (_is_string_data(vvalue[i].iov_base, vvalue[i].iov_len))
					fmt_arr_fld_str(format, buf, level + 1, vvalue[i].iov_base, i > start_idx);
				else
					fmt_arr_fld_bin(format,
					                buf,
					                level + 1,
					                vvalue[i].iov_base,
					                vvalue[i].iov_len,
					                i + start_idx);
			} else
				fmt_arr_fld_str(format, buf, level + 1, "", false);
		}
		fmt_arr_end(format, buf, level);
	} else if (vvalue[start_idx].iov_len) {
		if (_is_string_data(vvalue[start_idx].iov_base, vvalue[start_idx].iov_len))
			fmt_fld_str(format, buf, level, name, vvalue[start_idx].iov_base, true);
		else
			fmt_fld_bin(format, buf, level, name, vvalue[start_idx].iov_base, vvalue[start_idx].iov_len, true);
	} else
		fmt_fld_str(format, buf, level, name, "", true);
}

static void _print_flags(kv_vector_t *vvalue, const char *name, fmt_output_t format, struct sid_buf *buf, int level)
{
	static struct {
		uint64_t    fl_val;
		const char *abbrev;
	} fl_tab[]          = {{SID_KV_FL_ALIGN, "AL"},
	                       {SID_KV_FL_SYNC, "SC"},
	                       {SID_KV_FL_PERSIST, "PS"},
	                       {SID_KV_FL_AR, "AR"},
	                       {SID_KV_FL_RS, "RS"},
	                       {SID_KV_FL_FRG_RD, "FR_RD"},
	                       {SID_KV_FL_SUB_RD, "SB_RD"},
	                       {SID_KV_FL_SUP_RD, "SP_RD"},
	                       {SID_KV_FL_FRG_WR, "FR_WR"},
	                       {SID_KV_FL_SUB_WR, "SB_WR"},
	                       {SID_KV_FL_SUP_WR, "SP_WR"}};

	uint64_t flags      = VVALUE_FLAGS(vvalue);
	bool     with_comma = false;
	int      i;

	fmt_arr_start(format, buf, level, "flags", true);
	level++;

#define _PRINT_FLAG(pos)                                                                                                           \
	do {                                                                                                                       \
		if (flags & fl_tab[pos].fl_val) {                                                                                  \
			fmt_arr_fld_str(format, buf, level, fl_tab[pos].abbrev, with_comma);                                       \
			with_comma = true;                                                                                         \
		}                                                                                                                  \
	} while (0)

	for (i = 0; i < (sizeof(fl_tab) / sizeof(fl_tab[0])); i++)
		_PRINT_FLAG(i);

	level--;
	fmt_arr_end(format, buf, level);
}

static fmt_output_t flags_to_format(uint16_t flags)
{
	switch (flags & SID_IFC_CMD_FL_FMT_MASK) {
		case SID_IFC_CMD_FL_FMT_TABLE:
			return FMT_TABLE;
		case SID_IFC_CMD_FL_FMT_JSON:
			return FMT_JSON;
		case SID_IFC_CMD_FL_FMT_ENV:
			return FMT_ENV;
	}
	return FMT_TABLE; /* default to TABLE on invalid format */
}

static int _build_cmd_kv_buffers(sid_res_t *cmd_res, uint32_t flags)
{
	static const char    failed_unset_buf_msg[] = "Failed to add record to unset buffer while building KV buffers.";
	struct sid_ucmd_ctx *ucmd_ctx               = sid_res_get_data(cmd_res);
	fmt_output_t         format;
	struct sid_buf_spec  buf_spec;
	kv_scalar_t         *svalue;
	sid_kvs_iter_t      *iter;
	const char          *key, *index_key;
	void                *raw_value;
	bool                 vector, is_sync;
	size_t               size, vvalue_size, key_size, ext_data_offset;
	sid_kvs_val_fl_t     kv_store_value_flags;
	kv_vector_t         *vvalue;
	unsigned             i, records = 0;
	int                  r          = -1;
	struct sid_buf      *export_buf = NULL, *unset_buf = NULL;
	bool                 needs_comma = false;
	kv_vector_t          tmp_vvalue[VVALUE_SINGLE_ALIGNED_CNT];

	if (!(flags & (CMD_KV_EXPORT_UDEV_TO_RESBUF | CMD_KV_EXPORT_UDEV_TO_EXPBUF | CMD_KV_EXPORT_SID_TO_RESBUF |
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

	if ((is_sync = flags & CMD_KV_EXPORT_SYNC))
		iter = sid_kvs_iter_create_prefix(ucmd_ctx->common->kvs_res, KV_PREFIX_OP_SYNC_C);
	else
		iter = sid_kvs_iter_create(ucmd_ctx->common->kvs_res, NULL, NULL);

	if (!iter) {
		// TODO: Discard udev kv-store we've already appended to the output buffer!
		sid_res_log_error(cmd_res, "Failed to create iterator for temp key-value store.");
		goto fail;
	}

	if (flags & CMD_KV_EXPBUF_TO_FILE)
		buf_spec = (struct sid_buf_spec) {.backend  = SID_BUF_BACKEND_FILE,
		                                  .mode     = SID_BUF_MODE_SIZE_PREFIX,
		                                  .ext.file = {ucmd_ctx->req_env.exp_path ?: MAIN_KV_STORE_FILE_PATH}};
	else
		buf_spec = (struct sid_buf_spec) {.backend = SID_BUF_BACKEND_MEMFD, .mode = SID_BUF_MODE_SIZE_PREFIX};

	if (!(export_buf = sid_buf_create(&buf_spec, &SID_BUF_INIT(.alloc_step = PATH_MAX), &r))) {
		sid_res_log_error(cmd_res, "Failed to create export buffer.");
		goto fail;
	}

	if (!(unset_buf = sid_buf_create(&SID_BUF_SPEC(), &SID_BUF_INIT(.size = 256, .alloc_step = 256), &r))) {
		sid_res_log_error(cmd_res, "Failed to create unset buffer.");
		goto fail;
	}

	/*
	 * For exporting the KV store internally, that is MSG_CATEGORY_SELF commands and
	 * commands exporting buffer to main process, we always use the raw NO_FORMAT.
	 * For external clients, we export in format which is requested.
	 */
	if ((ucmd_ctx->req_cat == MSG_CATEGORY_SELF) || (flags & CMD_KV_EXPBUF_TO_MAIN))
		format = FMT_NONE;
	else
		format = flags_to_format(ucmd_ctx->req_hdr.flags);

	if (format != FMT_NONE) {
		fmt_doc_start(format, export_buf, 0);
		fmt_arr_start(format, export_buf, 1, "siddb", false);
	}

	while ((raw_value = sid_kvs_iter_next(iter, &size, &key, &kv_store_value_flags))) {
		vector = kv_store_value_flags & SID_KVS_VAL_FL_VECTOR;

		if (vector) {
			vvalue      = raw_value;
			vvalue_size = size;
			svalue      = NULL;
			if (is_sync) {
				if (!(VVALUE_FLAGS(vvalue) & SID_KV_FL_SYNC))
					continue;
				VVALUE_FLAGS(vvalue) &= ~SID_KV_FL_SYNC;
			}
			if (flags & CMD_KV_EXPORT_PERSISTENT) {
				if (!(VVALUE_FLAGS(vvalue) & SID_KV_FL_PERSIST))
					continue;
			}
		} else {
			vvalue      = NULL;
			vvalue_size = 0;
			svalue      = raw_value;
			if (is_sync) {
				if (!(svalue->flags & SID_KV_FL_SYNC))
					continue;
				svalue->flags &= ~SID_KV_FL_SYNC;
			}
			if (flags & CMD_KV_EXPORT_PERSISTENT) {
				if (!(svalue->flags & SID_KV_FL_PERSIST))
					continue;
			}
		}

		/* remove leading KV_PREFIX_OP_SYNC_C if present */
		if (*key == KV_PREFIX_OP_SYNC_C[0]) {
			index_key  = key;
			key       += 1;
		} else
			index_key = NULL;

		key_size = strlen(key) + 1;

		// TODO: Also deal with situation if the udev namespace values are defined as vectors by chance.
		if (_get_ns_from_key(key) == SID_KV_NS_UDEV) {
			if (!(flags & (CMD_KV_EXPORT_UDEV_TO_RESBUF | CMD_KV_EXPORT_UDEV_TO_EXPBUF))) {
				sid_res_log_debug(cmd_res, "Ignoring request to export record with key %s to udev.", key);
				goto next;
			}

			if (vector) {
				sid_res_log_error(cmd_res,
				                  SID_INTERNAL_ERROR "%s: Unsupported vector value for key %s in udev namespace.",
				                  __func__,
				                  key);
				goto fail;
			}

			if (flags & CMD_KV_EXPORT_UDEV_TO_RESBUF) {
				ext_data_offset = _svalue_ext_data_offset(svalue);

				/* only export if there's a value assigned and the value is not an empty string */
				if ((size > (SVALUE_HEADER_SIZE + ext_data_offset + 1)) &&
				    ((svalue->data + ext_data_offset)[0] != '\0')) {
					key = _get_key_part(key, KEY_PART_CORE, NULL);

					if (((r = sid_buf_add(ucmd_ctx->res_buf, (void *) key, strlen(key), NULL, NULL)) < 0) ||
					    ((r = sid_buf_add(ucmd_ctx->res_buf, KV_PAIR_C, 1, NULL, NULL)) < 0) ||
					    ((r = sid_buf_add(ucmd_ctx->res_buf,
					                      svalue->data + ext_data_offset,
					                      strlen(svalue->data + ext_data_offset),
					                      NULL,
					                      NULL)) < 0) ||
					    ((r = sid_buf_add(ucmd_ctx->res_buf, KV_END_C, 1, NULL, NULL)) < 0)) {
						sid_res_log_error(cmd_res,
						                  "Failed to add udev property %s=%s to response buffer.",
						                  key,
						                  svalue->data + ext_data_offset);
						goto fail;
					}

					sid_res_log_debug(ucmd_ctx->common->kvs_res,
					                  "Exported udev property %s=%s",
					                  key,
					                  svalue->data + ext_data_offset);
				}
			}

			if (!(flags & CMD_KV_EXPORT_UDEV_TO_EXPBUF))
				goto next;
		} else { /* _get_ns_from_key(key) != KV_NS_UDEV */
			if (!(flags & (CMD_KV_EXPORT_SID_TO_RESBUF | CMD_KV_EXPORT_SID_TO_EXPBUF))) {
				sid_res_log_debug(cmd_res,
				                  "Ignoring request to export record with key %s to SID main KV store.",
				                  key);
				goto next;
			}
		}

		if (format == FMT_NONE) {
			/*
			 * Export keys with data to main process.
			 *
			 * Serialization format fields (message size is implicitly set
			 * when using SID_BUF_MODE_SIZE_PREFIX):
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

			if (((r = sid_buf_add(export_buf, &kv_store_value_flags, sizeof(kv_store_value_flags), NULL, NULL)) < 0) ||
			    ((r = sid_buf_add(export_buf, &key_size, sizeof(key_size), NULL, NULL)) < 0) ||
			    ((r = sid_buf_add(export_buf, &size, sizeof(size), NULL, NULL)) < 0) ||
			    ((r = sid_buf_add(export_buf, (char *) key, strlen(key) + 1, NULL, NULL)) < 0)) {
				sid_res_log_error_errno(cmd_res, errno, "sid_buf_add failed");
				goto fail;
			}

			if (vector) {
				for (i = 0, size = 0; i < vvalue_size; i++) {
					size += vvalue[i].iov_len;

					if (((r = sid_buf_add(export_buf,
					                      &vvalue[i].iov_len,
					                      sizeof(vvalue->iov_len),
					                      NULL,
					                      NULL)) < 0) ||
					    ((r = sid_buf_add(export_buf, vvalue[i].iov_base, vvalue[i].iov_len, NULL, NULL)) <
					     0)) {
						sid_res_log_error_errno(cmd_res, errno, "sid_buf_add failed");
						goto fail;
					}
				}
			} else if ((r = sid_buf_add(export_buf, svalue, size, NULL, NULL)) < 0) {
				sid_res_log_error_errno(cmd_res, errno, "sid_buf_add failed");
				goto fail;
			}
		} else {
			fmt_elm_start(format, export_buf, 2, needs_comma);
			fmt_fld_uint(format, export_buf, 3, "RECORD", records, false);
			fmt_fld_str(format, export_buf, 3, "key", key, true);
			vvalue = _get_vvalue(kv_store_value_flags, raw_value, size, tmp_vvalue, VVALUE_CNT(tmp_vvalue));
			fmt_fld_uint(format, export_buf, 3, "gennum", VVALUE_GENNUM(vvalue), true);
			fmt_fld_uint64(format, export_buf, 3, "seqnum", VVALUE_SEQNUM(vvalue), true);
			_print_flags(vvalue, "flags", format, export_buf, 3);
			fmt_fld_str(format, export_buf, 3, "owner", VVALUE_OWNER(vvalue), true);
			_print_vvalue(vvalue, vector, size, vector ? "values" : "value", format, export_buf, 3);
			fmt_elm_end(format, export_buf, 2);
			needs_comma = true;
		}
		records++;
next:
		switch (_get_op_from_key(key)) {
			case KV_OP_PLUS:
			case KV_OP_MINUS:
				/* schedule removal of any delta record */
				if (sid_buf_add(unset_buf, (void *) &key, sizeof(uintptr_t), NULL, NULL) < 0) {
					sid_res_log_error(cmd_res, failed_unset_buf_msg);
					goto fail;
				}
				break;
			case KV_OP_SET:
			case KV_OP_ILLEGAL:
				/* keep */
				break;
		}

		if (index_key) {
			/* schedule removal of the index key (the alias with KV_PREFIX_OP_SYNC) */
			if (sid_buf_add(unset_buf, (void *) &index_key, sizeof(uintptr_t), NULL, NULL) < 0) {
				sid_res_log_error(cmd_res, failed_unset_buf_msg);
				goto fail;
			}
		}
	}

	if (format != FMT_NONE) {
		fmt_arr_end(format, export_buf, 1);
		fmt_doc_end(format, export_buf, 0);
		fmt_null_byte(export_buf);
	}

	sid_kvs_iter_destroy(iter);

	ucmd_ctx->exp_buf = export_buf;
	ucmd_ctx->uns_buf = unset_buf;
	return 0;

fail:
	if (iter)
		sid_kvs_iter_destroy(iter);
	if (export_buf)
		sid_buf_destroy(export_buf);
	if (unset_buf)
		sid_buf_destroy(unset_buf);

	return r;
}

static int _process_cmd_unsbuf(sid_res_t *cmd_res)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_res_get_data(cmd_res);
	void                *raw_value;
	size_t               i, size;
	const char          *key;
	int                  r = -1;

	if (!ucmd_ctx->uns_buf)
		return 0;

	sid_buf_get_data(ucmd_ctx->uns_buf, (const void **) &raw_value, &size);
	size /= sizeof(uintptr_t);

	for (i = 0; i < size; i++) {
		key = (const char *) ((uintptr_t *) raw_value)[i];

		if (sid_kvs_unset(ucmd_ctx->common->kvs_res, key, NULL, NULL) < 0) {
			sid_res_log_error(cmd_res, "Failed to unset key %s.", key);
			goto out;
		}
	}

	r = 0;
out:
	sid_buf_destroy(ucmd_ctx->uns_buf);
	ucmd_ctx->uns_buf = NULL;
	return r;
}

static int _check_global_kv_rs_for_wr(struct sid_ucmd_ctx    *ucmd_ctx,
                                      const char             *owner,
                                      const char             *dom,
                                      sid_ucmd_kv_namespace_t ns,
                                      const char             *key_core)
{
	kv_vector_t        tmp_vvalue[VVALUE_SINGLE_CNT];
	kv_vector_t       *vvalue;
	const char        *key = NULL;
	void              *found;
	size_t             value_size;
	sid_kvs_val_fl_t   kv_store_value_flags;
	struct kv_key_spec key_spec = {.extra_op = NULL,
	                               .op       = KV_OP_SET,
	                               .dom      = dom ?: ID_NULL,
	                               .ns       = ns,
	                               .ns_part  = ID_NULL,
	                               .id_cat   = ID_NULL,
	                               .id       = ID_NULL,
	                               .core     = key_core};
	int                r        = 1;

	if ((ns != SID_KV_NS_UDEV) && (ns != SID_KV_NS_DEVICE))
		goto out;

	if (!(key = _compose_key(ucmd_ctx->common->gen_buf, &key_spec))) {
		r = -ENOMEM;
		goto out;
	}

	if (!(found = sid_kvs_get(ucmd_ctx->common->kvs_res, key, &value_size, &kv_store_value_flags)))
		goto out;

	vvalue = _get_vvalue(kv_store_value_flags, found, value_size, tmp_vvalue, VVALUE_CNT(tmp_vvalue));

	if (!(VVALUE_FLAGS(vvalue) & SID_KV_FL_RS))
		goto out;

	switch (_mod_match(VVALUE_OWNER(vvalue), owner)) {
		case MOD_NO_MATCH:
			r = VVALUE_FLAGS(vvalue) & SID_KV_FL_FRG_WR;
			break;
		case MOD_MATCH:
		case MOD_CORE_MATCH:
			r = 1;
			break;
		case MOD_SUB_MATCH:
			r = VVALUE_FLAGS(vvalue) & SID_KV_FL_SUB_WR;
			break;
		case MOD_SUP_MATCH:
			r = VVALUE_FLAGS(vvalue) & SID_KV_FL_SUP_WR;
			break;
	}

	if (!r)
		sid_res_log_debug(ucmd_ctx->common->kvs_res,
		                  "Module %s can't overwrite value with key %s which is reserved and attached to %s module.",
		                  owner,
		                  key,
		                  VVALUE_OWNER(vvalue));
out:
	_destroy_key(ucmd_ctx->common->gen_buf, key);
	return r;
}

static const char *_get_ns_part(struct sid_ucmd_ctx *ucmd_ctx, const char *owner, sid_ucmd_kv_namespace_t ns)
{
	switch (ns) {
		case SID_KV_NS_UDEV:
			return ucmd_ctx->req_env.dev.num_s ?: ID_NULL;
		case SID_KV_NS_DEVICE:
		case SID_KV_NS_DEVMOD:
			return ucmd_ctx->req_env.dev.uid_s ?: ID_NULL;
		case SID_KV_NS_MODULE:
			return owner;
		case SID_KV_NS_GLOBAL:
		case SID_KV_NS_UNDEFINED:
			break;
	}

	return ID_NULL;
}

static const char *_get_foreign_ns_part(struct sid_ucmd_ctx    *ucmd_ctx,
                                        const char             *owner,
                                        const char             *foreign_mod_name,
                                        const char             *foreign_dev_id,
                                        sid_ucmd_kv_namespace_t ns)
{
	switch (ns) {
		case SID_KV_NS_UDEV:
			return ucmd_ctx->req_env.dev.num_s ?: ID_NULL;
		case SID_KV_NS_DEVICE:
		case SID_KV_NS_DEVMOD:
			return foreign_dev_id ?: ucmd_ctx->req_env.dev.uid_s ?: ID_NULL;
		case SID_KV_NS_MODULE:
			return foreign_mod_name ?: owner;
		case SID_KV_NS_GLOBAL:
		case SID_KV_NS_UNDEFINED:
			break;
	}

	return ID_NULL;
}

static void _destroy_delta_buffers(struct kv_delta *delta)
{
	if (delta->plus) {
		sid_buf_destroy(delta->plus);
		delta->plus = NULL;
	}

	if (delta->minus) {
		sid_buf_destroy(delta->minus);
		delta->minus = NULL;
	}

	if (delta->final) {
		sid_buf_destroy(delta->final);
		delta->final = NULL;
	}
}

static void _destroy_unused_delta_buffers(struct kv_delta *delta)
{
	if (delta->plus) {
		if (sid_buf_count(delta->plus) < VVALUE_SINGLE_CNT) {
			sid_buf_destroy(delta->plus);
			delta->plus = NULL;
		}
	}

	if (delta->minus) {
		if (sid_buf_count(delta->minus) < VVALUE_SINGLE_CNT) {
			sid_buf_destroy(delta->minus);
			delta->minus = NULL;
		}
	}
}

static int _init_delta_buffer(kv_vector_t *vheader, struct sid_buf **delta_buf, size_t size)
{
	struct sid_buf *buf = NULL;
	size_t          i;
	int             r = 0;

	if (!size)
		return 0;

	if (size < VVALUE_HEADER_CNT) {
		r = -EINVAL;
		goto out;
	}

	if (!(buf = sid_buf_create(&SID_BUF_SPEC(.type = SID_BUF_TYPE_VECTOR), &SID_BUF_INIT(.size = size), &r)))
		goto out;

	for (i = 0; i < VVALUE_HEADER_CNT; i++) {
		if ((r = sid_buf_add(buf, vheader[i].iov_base, vheader[i].iov_len, NULL, NULL)) < 0)
			goto out;
	}
out:
	if (r < 0) {
		if (buf)
			sid_buf_destroy(buf);
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

static int _delta_step_calc(struct sid_kvs_update_spec *spec)
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
						if ((r = sid_buf_add(delta->minus,
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
						if ((r = sid_buf_add(delta->final,
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
						if (((r = sid_buf_add(delta->plus,
						                      new_vvalue[i_new].iov_base,
						                      new_vvalue[i_new].iov_len,
						                      NULL,
						                      NULL)) < 0) ||
						    ((r = sid_buf_add(delta->final,
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
						if ((r = sid_buf_add(delta->final,
						                     new_vvalue[i_new].iov_base,
						                     new_vvalue[i_new].iov_len,
						                     NULL,
						                     NULL)) < 0)
							goto out;
						break;
					case KV_OP_MINUS:
						/* we're removing item: add it to delta->minus */
						if ((r = sid_buf_add(delta->minus,
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
						if (((r = sid_buf_add(delta->plus,
						                      new_vvalue[i_new].iov_base,
						                      new_vvalue[i_new].iov_len,
						                      NULL,
						                      NULL)) < 0) ||
						    ((r = sid_buf_add(delta->final,
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
						if ((r = sid_buf_add(delta->minus,
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
						if ((r = sid_buf_add(delta->final,
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
				bmp_unset_bit(cross->old_bmp, i_old);
				bmp_unset_bit(cross->new_bmp, i_new);
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
	cross1.old_vvalue = sid_kvs_get(update_arg->res, delta_key, &cross1.old_vsize, NULL);
	_destroy_key(update_arg->gen_buf, delta_key);
	if (cross1.old_vvalue && !(cross1.old_bmp = bmp_create(cross1.old_vsize, true, NULL)))
		goto out;

	rel_spec->cur_key_spec->op = KV_OP_MINUS;
	if (!(delta_key = _compose_key(update_arg->gen_buf, rel_spec->cur_key_spec)))
		goto out;
	cross2.old_vvalue = sid_kvs_get(update_arg->res, delta_key, &cross2.old_vsize, NULL);
	_destroy_key(update_arg->gen_buf, delta_key);
	if (cross2.old_vvalue && !(cross2.old_bmp = bmp_create(cross2.old_vsize, true, NULL)))
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
		sid_buf_get_data(rel_spec->delta->minus, (const void **) &cross1.new_vvalue, &cross1.new_vsize);

		if (!(cross1.new_bmp = bmp_create(cross1.new_vsize, true, NULL)))
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
		sid_buf_get_data(rel_spec->delta->plus, (const void **) &cross2.new_vvalue, &cross2.new_vsize);

		if (!(cross2.new_bmp = bmp_create(cross2.new_vsize, true, NULL)))
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
	abs_minus_vsize = ((cross2.old_bmp ? bmp_get_bit_set_count(cross2.old_bmp) : 0) +
	                   (cross1.new_bmp ? bmp_get_bit_set_count(cross1.new_bmp) : 0));
	if (cross2.old_bmp && cross1.new_bmp)
		abs_minus_vsize -= VVALUE_HEADER_CNT;

	abs_plus_vsize = ((cross1.old_bmp ? bmp_get_bit_set_count(cross1.old_bmp) : 0) +
	                  (cross2.new_bmp ? bmp_get_bit_set_count(cross2.new_bmp) : 0));
	if (cross1.old_bmp && cross2.new_bmp)
		abs_plus_vsize -= VVALUE_HEADER_CNT;

	/* go through the old and new plus and minus vectors and merge non-contradicting items */
	if (_init_delta_buffers(rel_spec->abs_delta, vheader, abs_minus_vsize, abs_plus_vsize, 0) < 0)
		goto out;

	if (rel_spec->delta->flags & DELTA_WITH_REL)
		rel_spec->abs_delta->flags |= DELTA_WITH_REL;

	if (cross1.old_vvalue) {
		for (i = VVALUE_IDX_DATA; i < cross1.old_vsize; i++) {
			if (bmp_bit_is_set(cross1.old_bmp, i, NULL) && ((r = sid_buf_add(rel_spec->abs_delta->plus,
			                                                                 cross1.old_vvalue[i].iov_base,
			                                                                 cross1.old_vvalue[i].iov_len,
			                                                                 NULL,
			                                                                 NULL)) < 0))
				goto out;
		}
	}

	if (cross1.new_vvalue) {
		for (i = VVALUE_IDX_DATA; i < cross1.new_vsize; i++) {
			if (bmp_bit_is_set(cross1.new_bmp, i, NULL) && ((r = sid_buf_add(rel_spec->abs_delta->minus,
			                                                                 cross1.new_vvalue[i].iov_base,
			                                                                 cross1.new_vvalue[i].iov_len,
			                                                                 NULL,
			                                                                 NULL)) < 0))
				goto out;
		}
	}

	if (cross2.old_vvalue) {
		for (i = VVALUE_IDX_DATA; i < cross2.old_vsize; i++) {
			if (bmp_bit_is_set(cross2.old_bmp, i, NULL) && ((r = sid_buf_add(rel_spec->abs_delta->minus,
			                                                                 cross2.old_vvalue[i].iov_base,
			                                                                 cross2.old_vvalue[i].iov_len,
			                                                                 NULL,
			                                                                 NULL)) < 0))
				goto out;
		}
	}

	if (cross2.new_vvalue) {
		for (i = VVALUE_IDX_DATA; i < cross2.new_vsize; i++) {
			if (bmp_bit_is_set(cross2.new_bmp, i, NULL) && ((r = sid_buf_add(rel_spec->abs_delta->plus,
			                                                                 cross2.new_vvalue[i].iov_base,
			                                                                 cross2.new_vvalue[i].iov_len,
			                                                                 NULL,
			                                                                 NULL)) < 0))
				goto out;
		}
	}

	if (rel_spec->abs_delta->plus) {
		sid_buf_get_data(rel_spec->abs_delta->plus, (const void **) &abs_plus_v, &abs_plus_vsize);
		qsort(abs_plus_v + VVALUE_IDX_DATA, abs_plus_vsize - VVALUE_IDX_DATA, sizeof(kv_vector_t), _vvalue_str_cmp);
	}

	if (rel_spec->abs_delta->minus) {
		sid_buf_get_data(rel_spec->abs_delta->minus, (const void **) &abs_minus_v, &abs_minus_vsize);
		qsort(abs_minus_v + VVALUE_IDX_DATA, abs_minus_vsize - VVALUE_IDX_DATA, sizeof(kv_vector_t), _vvalue_str_cmp);
	}

	r = 0;
out:
	if (cross1.old_bmp)
		bmp_destroy(cross1.old_bmp);
	if (cross1.new_bmp)
		bmp_destroy(cross1.new_bmp);
	if (cross2.old_bmp)
		bmp_destroy(cross2.old_bmp);
	if (cross2.new_bmp)
		bmp_destroy(cross2.new_bmp);

	rel_spec->cur_key_spec->op = orig_op;

	if (r < 0)
		_destroy_delta_buffers(rel_spec->abs_delta);

	return r;
}

// TODO: Make it possible to set all flags at once or change selected flag bits.
static void _value_vector_mark_sync(kv_vector_t *vvalue, int sync)
{
	if (sync)
		VVALUE_FLAGS(vvalue) |= SID_KV_FL_SYNC;
	else
		VVALUE_FLAGS(vvalue) &= ~SID_KV_FL_SYNC;
}

static int _delta_update(kv_vector_t *vheader, kv_op_t op, struct kv_update_arg *update_arg)
{
	struct kv_rel_spec *rel_spec = update_arg->custom;
	kv_op_t             orig_op  = rel_spec->cur_key_spec->op;
	struct kv_delta    *orig_delta, *orig_abs_delta;
	kv_vector_t        *delta_vvalue, *abs_delta_vvalue;
	size_t              delta_vsize, abs_delta_vsize, i;
	const char         *key_prefix, *key_part;
	char               *key;
	kv_vector_t         rel_vvalue[VVALUE_SINGLE_CNT];
	struct kv_unset_nfo unset_nfo;
	int                 r = -1;

	if (op == KV_OP_PLUS) {
		if (!update_arg->is_sync) {
			if (!rel_spec->abs_delta->plus)
				return 0;
			sid_buf_get_data(rel_spec->abs_delta->plus, (const void **) &abs_delta_vvalue, &abs_delta_vsize);
		}

		if (rel_spec->delta->plus)
			sid_buf_get_data(rel_spec->delta->plus, (const void **) &delta_vvalue, &delta_vsize);
		else {
			delta_vvalue = NULL;
			delta_vsize  = 0;
		}
	} else if (op == KV_OP_MINUS) {
		if (!update_arg->is_sync) {
			if (!rel_spec->abs_delta->minus)
				return 0;
			sid_buf_get_data(rel_spec->abs_delta->minus, (const void **) &abs_delta_vvalue, &abs_delta_vsize);
		}

		if (rel_spec->delta->minus)
			sid_buf_get_data(rel_spec->delta->minus, (const void **) &delta_vvalue, &delta_vsize);
		else {
			delta_vvalue = NULL;
			delta_vsize  = 0;
		}
	} else {
		sid_res_log_error(update_arg->res, SID_INTERNAL_ERROR "%s: incorrect delta operation requested.", __func__);
		return -1;
	}

	if (!update_arg->is_sync) {
		/* store absolute delta for current item - persistent */
		rel_spec->cur_key_spec->op = op;
		key                        = _compose_key(update_arg->gen_buf, rel_spec->cur_key_spec);
		rel_spec->cur_key_spec->op = orig_op;
		if (!key)
			return -1;

		_value_vector_mark_sync(abs_delta_vvalue, 1);

		if (abs_delta_vsize > VVALUE_HEADER_CNT) {
			sid_kvs_set(update_arg->res,
			            key,
			            abs_delta_vvalue,
			            abs_delta_vsize,
			            SID_KVS_VAL_FL_VECTOR,
			            SID_KVS_VAL_OP_NONE,
			            _kv_cb_write,
			            update_arg);
		} else {
			unset_nfo.owner    = VVALUE_OWNER(abs_delta_vvalue);
			unset_nfo.seqnum   = VVALUE_SEQNUM(abs_delta_vvalue);
			update_arg->custom = &unset_nfo;
			sid_kvs_unset(update_arg->res, key, _kv_cb_write, update_arg);
			update_arg->custom = rel_spec;
		}

		_value_vector_mark_sync(abs_delta_vvalue, 0);

		(void) _manage_kv_index(update_arg, key);

		_destroy_key(update_arg->gen_buf, key);
	}

	if (!(delta_vsize && rel_spec->delta->flags & DELTA_WITH_REL)) {
		rel_spec->cur_key_spec->op = orig_op;
		return 0;
	}

	/* the other way round now - store final and absolute delta for each relative */
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
	                    VVALUE_OWNER(vheader));
	_vvalue_data_prep(rel_vvalue, VVALUE_CNT(rel_vvalue), 0, (void *) key_prefix, strlen(key_prefix) + 1);

	for (i = VVALUE_IDX_DATA; i < delta_vsize; i++) {
		/*
		 * FIXME: This is a shortcut for now. Simplify whole kv_delta_set and related so we don't need
		 * to test this condition (check for namespace and then copy the part of the key to reference).
		 */
		if (rel_spec->cur_key_spec->ns == SID_KV_NS_DEVICE) {
			if (!(key_part = _copy_ns_part_from_key(delta_vvalue[i].iov_base, NULL, 0)))
				goto out;
			rel_spec->cur_key_spec->ns_part = key_part;
		} else if (rel_spec->cur_key_spec->ns == SID_KV_NS_MODULE) {
			if (!(key_part = _copy_id_from_key(delta_vvalue[i].iov_base, NULL, 0)))
				goto out;
			rel_spec->cur_key_spec->id = key_part;
		} else {
			sid_res_log_error(update_arg->res,
			                  SID_INTERNAL_ERROR "%s: unsupported namespace with internal number %d found in rel spec",
			                  __func__,
			                  rel_spec->cur_key_spec->ns);
			goto out;
		}

		if (!(key = _compose_key(NULL, rel_spec->cur_key_spec))) {
			_destroy_key(NULL, key_part);
			goto out;
		}

		_do_kv_delta_set(key, rel_vvalue, VVALUE_SINGLE_CNT, update_arg);

		if (rel_spec->cur_key_spec->ns == SID_KV_NS_DEVICE)
			rel_spec->cur_key_spec->ns_part = NULL;
		else if (rel_spec->cur_key_spec->ns == SID_KV_NS_MODULE)
			rel_spec->cur_key_spec->id = NULL;

		_destroy_key(NULL, key);
		_destroy_key(NULL, key_part);
	}

	r = 0;
out:
	_destroy_key(NULL, key_prefix);
	rel_spec->abs_delta = orig_abs_delta;
	rel_spec->delta     = orig_delta;
	UTIL_SWAP(rel_spec->rel_key_spec, rel_spec->cur_key_spec);
	rel_spec->cur_key_spec->op = orig_op;
	return r;
}

static int _kv_cb_delta_step(struct sid_kvs_update_spec *spec)
{
	struct kv_update_arg *update_arg = spec->arg;
	struct kv_rel_spec   *rel_spec   = update_arg->custom;
	int                   r;

	if ((r = _check_kv_wr_allowed(update_arg, spec->key, spec->old_data, spec->new_data)) < 0) {
		update_arg->ret_code = update_arg->is_sync ? 0 : r;
		r                    = 0;
		goto out;
	}

	if ((update_arg->ret_code = _delta_step_calc(spec)) < 0) {
		r = 0;
		goto out;
	}

	if (rel_spec->delta->final) {
		sid_buf_get_data(rel_spec->delta->final, (const void **) &spec->new_data, &spec->new_data_size);
		spec->new_flags &= ~SID_KVS_VAL_FL_REF;
		r                = 1;
		goto out;
	}
out:
	if (update_arg->is_sync) {
		if (r) {
			sid_res_log_debug(update_arg->res,
			                  "%s value for key %s (old seqnum %" PRIu64 ", new seqnum %" PRIu64 ").",
			                  spec->old_data ? "Updating" : "Adding",
			                  spec->key,
			                  spec->old_data ? VVALUE_SEQNUM(spec->old_data) : 0,
			                  VVALUE_SEQNUM(spec->new_data));
		} else
			sid_res_log_debug(update_arg->res,
			                  "Keeping old value for key %s (old seqnum %" PRIu64 ", new seqnum %" PRIu64 ").",
			                  spec->key,
			                  spec->old_data ? VVALUE_SEQNUM(spec->old_data) : 0,
			                  VVALUE_SEQNUM(spec->new_data));
	}

	return r;
}

static int _do_kv_delta_set(char *key, kv_vector_t *vvalue, size_t vsize, struct kv_update_arg *update_arg)
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
	if (!sid_kvs_set(update_arg->res,
	                 key,
	                 vvalue,
	                 vsize,
	                 SID_KVS_VAL_FL_VECTOR | SID_KVS_VAL_FL_REF,
	                 SID_KVS_VAL_OP_NONE,
	                 _kv_cb_delta_step,
	                 update_arg) ||
	    update_arg->ret_code < 0)
		goto out;

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
		if (!update_arg->is_sync) {
			if (_delta_abs_calc(vvalue, update_arg) < 0)
				goto out;
		}

		if (_delta_update(vvalue, KV_OP_PLUS, update_arg) < 0)
			goto out;

		if (_delta_update(vvalue, KV_OP_MINUS, update_arg) < 0)
			goto out;
	}

	r = 0;
out:
	_destroy_delta_buffers(rel_spec->abs_delta);
	_destroy_delta_buffers(rel_spec->delta);
	return r;
}

static int _kv_delta_set(char *key, kv_vector_t *vvalue, size_t vsize, struct kv_update_arg *update_arg)
{
	int r;

	if ((r = sid_kvs_transaction_begin(update_arg->res)) < 0) {
		if (r == -EBUSY)
			sid_res_log_error(update_arg->res, SID_INTERNAL_ERROR "%s: kv_store already in a transaction", __func__);
		return r;
	}
	r = _do_kv_delta_set(key, vvalue, vsize, update_arg);
	sid_kvs_transaction_end(update_arg->res, false);

	return r;
}

static void *_do_sid_ucmd_set_kv(sid_res_t              *res,
                                 struct sid_ucmd_ctx    *ucmd_ctx,
                                 const char             *owner,
                                 const char             *dom,
                                 sid_ucmd_kv_namespace_t ns,
                                 const char             *key_core,
                                 sid_ucmd_kv_flags_t     flags,
                                 const void             *value,
                                 size_t                  value_size)
{
	char                *key        = NULL;
	size_t               vvalue_cnt = flags & SID_KV_FL_ALIGN ? VVALUE_SINGLE_ALIGNED_CNT : VVALUE_SINGLE_CNT;
	kv_vector_t          vvalue[vvalue_cnt];
	kv_scalar_t         *svalue;
	struct kv_update_arg update_arg;
	struct kv_key_spec   key_spec = {.extra_op = NULL,
	                                 .op       = KV_OP_SET,
	                                 .dom      = dom ?: ID_NULL,
	                                 .ns       = ns,
	                                 .ns_part  = _get_ns_part(ucmd_ctx, owner, ns),
	                                 .id_cat   = ns == SID_KV_NS_DEVMOD ? KV_PREFIX_NS_MODULE_C : ID_NULL,
	                                 .id   = ns == SID_KV_NS_DEVMOD ? _get_ns_part(ucmd_ctx, owner, SID_KV_NS_MODULE) : ID_NULL,
	                                 .core = key_core};
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
	if (!((ns == SID_KV_NS_UDEV) && !strcmp(owner, OWNER_CORE))) {
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

	update_arg = (struct kv_update_arg) {.res      = ucmd_ctx->common->kvs_res,
	                                     .gen_buf  = ucmd_ctx->common->gen_buf,
	                                     .is_sync  = false,
	                                     .custom   = NULL,
	                                     .ret_code = -EREMOTEIO};

	if (flags & SID_KV_FL_AR) {
		key[0] = KV_PREFIX_OP_ARCHIVE_C[0];
		if (!(svalue = sid_kvs_set_with_archive(ucmd_ctx->common->kvs_res,
		                                        key + 1,
		                                        vvalue,
		                                        vvalue_cnt,
		                                        SID_KVS_VAL_FL_VECTOR,
		                                        SID_KVS_VAL_OP_MERGE,
		                                        _kv_cb_write,
		                                        &update_arg,
		                                        key)))
			goto out;
	} else {
		if (!(svalue = sid_kvs_set(ucmd_ctx->common->kvs_res,
		                           key,
		                           vvalue,
		                           vvalue_cnt,
		                           SID_KVS_VAL_FL_VECTOR,
		                           SID_KVS_VAL_OP_MERGE,
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

const void *sid_ucmd_kv_set(sid_res_t              *mod_res,
                            struct sid_ucmd_ctx    *ucmd_ctx,
                            sid_ucmd_kv_namespace_t ns,
                            const char             *key,
                            const void             *value,
                            size_t                  value_size,
                            sid_ucmd_kv_flags_t     flags)
{
	const char *dom;

	if (!mod_res || !ucmd_ctx || (ns == SID_KV_NS_UNDEFINED) || UTIL_STR_EMPTY(key) || (key[0] == KV_PREFIX_KEY_SYS_C[0]))
		return NULL;

	if (!sid_mod_reg_match_dep(mod_res, ucmd_ctx->common->block_mod_reg_res) &&
	    !sid_mod_reg_match_dep(mod_res, ucmd_ctx->common->type_mod_reg_res))
		return NULL;

	if (ns == SID_KV_NS_UDEV) {
		dom    = NULL;
		flags |= SID_KV_FL_SYNC_P;
	} else
		dom = KV_KEY_DOM_USER;

	return _do_sid_ucmd_set_kv(mod_res, ucmd_ctx, _owner_name(mod_res), dom, ns, key, flags, value, value_size);
}

static const void *_cmd_get_key_spec_value(sid_res_t           *res,
                                           struct sid_ucmd_ctx *ucmd_ctx,
                                           const char          *owner,
                                           struct kv_key_spec  *key_spec,
                                           size_t              *value_size,
                                           sid_ucmd_kv_flags_t *flags)
{
	const char      *key = NULL;
	sid_kvs_val_fl_t kvs_flags;
	kv_vector_t      tmp_vvalue[VVALUE_SINGLE_ALIGNED_CNT];
	void            *val;
	kv_vector_t     *vvalue;
	size_t           size, ext_data_offset;
	void            *ret = NULL;

	if (!(key = _compose_key(ucmd_ctx->common->gen_buf, key_spec)))
		goto out;

	if (!(val = sid_kvs_get(ucmd_ctx->common->kvs_res, key, &size, &kvs_flags)))
		goto out;

	vvalue = _get_vvalue(kvs_flags, val, size, tmp_vvalue, VVALUE_CNT(tmp_vvalue));

	switch (_mod_match(VVALUE_OWNER(vvalue), owner)) {
		case MOD_NO_MATCH:
			if (!(VVALUE_FLAGS(vvalue) & SID_KV_FL_FRG_RD))
				goto out;
			break;
		case MOD_MATCH:
		case MOD_CORE_MATCH:
			/* nothing to do here */
			break;
		case MOD_SUB_MATCH:
			if (!(VVALUE_FLAGS(vvalue) & SID_KV_FL_SUB_RD))
				goto out;
			break;
		case MOD_SUP_MATCH:
			if (!(VVALUE_FLAGS(vvalue) & SID_KV_FL_SUP_RD))
				goto out;
			break;
	}

	if (kvs_flags & SID_KVS_VAL_FL_VECTOR) {
		if (VVALUE_FLAGS(vvalue) & SID_KV_FL_ALIGN) {
			size -= VVALUE_HEADER_ALIGNED_CNT;
			if (size)
				ret = ((kv_vector_t *) val) + VVALUE_HEADER_ALIGNED_CNT;
		} else {
			size -= VVALUE_HEADER_CNT;
			if (size)
				ret = ((kv_vector_t *) val) + VVALUE_HEADER_CNT;
		}
	} else {
		ext_data_offset  = _svalue_ext_data_offset(val);
		size            -= (SVALUE_HEADER_SIZE + ext_data_offset);
		if (size)
			ret = ((kv_scalar_t *) val)->data + ext_data_offset;
	}

	if (flags)
		*flags = VVALUE_FLAGS(vvalue);

	if (value_size)
		*value_size = size;

out:
	_destroy_key(ucmd_ctx->common->gen_buf, key);
	return ret;
}

static bool _key_parts_match(struct iovec *key_parts1, struct iovec *key_parts2, key_part_t last_key_part)
{
	key_part_t   key_part;
	struct iovec part1, part2;

	for (key_part = _KEY_PART_START; key_part < last_key_part; key_part++) {
		part1 = key_parts1[key_part];
		part2 = key_parts2[key_part];

		if (part1.iov_base && part2.iov_base) {
			if ((part1.iov_len != part2.iov_len) || memcmp(part1.iov_base, part2.iov_base, part1.iov_len))
				return false;
		}
	}

	return true;
}

static char **_get_key_strv_from_vvalue(const kv_vector_t *vvalue, size_t size, struct kv_key_spec *key_filter, size_t *ret_count)
{
	struct iovec key_filter_parts[_KEY_PART_COUNT];
	struct iovec key_parts[_KEY_PART_COUNT];
	key_part_t   last_key_part;
	size_t       i, count = 0;
	struct bmp  *bmp;
	char       **strv;
	char        *p;

	_key_spec_to_parts(key_filter, key_filter_parts);

	if (!(bmp = bmp_create(size, false, NULL)))
		return NULL;

	for (i = 0; i < size; i++) {
		last_key_part = _decompose_key(vvalue[i].iov_base, key_parts);

		if (_key_parts_match(key_parts, key_filter_parts, last_key_part)) {
			bmp_set_bit(bmp, i);
			/* Here, the 'count' is the number of chars used in total. */
			count += vvalue[i].iov_len;
		}
	}

	if (!(strv = malloc(bmp_get_bit_set_count(bmp) * sizeof(char *) + count * sizeof(char))))
		goto out;

	p = (char *) (strv + bmp_get_bit_set_count(bmp));

	/* Here, the 'count' is the current number of items already in the final strv. */
	for (i = 0, count = 0; i < size; i++) {
		if (bmp_bit_is_set(bmp, i, NULL)) {
			strv[count++] = p;
			p             = mempcpy(p, vvalue[i].iov_base, vvalue[i].iov_len);
		}
	}
out:
	bmp_destroy(bmp);
	*ret_count = count;
	return strv;
}

static const void *_do_sid_ucmd_get_kv(sid_res_t              *res,
                                       struct sid_ucmd_ctx    *ucmd_ctx,
                                       const char             *owner,
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
	                               .ns_part  = _get_ns_part(ucmd_ctx, owner, ns),
	                               .id_cat   = ns == SID_KV_NS_DEVMOD ? KV_PREFIX_NS_MODULE_C : ID_NULL,
	                               .id   = ns == SID_KV_NS_DEVMOD ? _get_ns_part(ucmd_ctx, owner, SID_KV_NS_MODULE) : ID_NULL,
	                               .core = key};

	return _cmd_get_key_spec_value(res, ucmd_ctx, owner, &key_spec, value_size, flags);
}

const void *sid_ucmd_kv_get(sid_res_t              *mod_res,
                            struct sid_ucmd_ctx    *ucmd_ctx,
                            sid_ucmd_kv_namespace_t ns,
                            const char             *key,
                            size_t                 *value_size,
                            sid_ucmd_kv_flags_t    *flags,
                            unsigned int            archive)
{
	const char *dom;

	if (!mod_res || !ucmd_ctx || (ns == SID_KV_NS_UNDEFINED) || UTIL_STR_EMPTY(key) || (key[0] == KV_PREFIX_KEY_SYS_C[0]))
		return NULL;

	if (!sid_mod_reg_match_dep(mod_res, ucmd_ctx->common->block_mod_reg_res) &&
	    !sid_mod_reg_match_dep(mod_res, ucmd_ctx->common->type_mod_reg_res))
		return NULL;

	if (ns == SID_KV_NS_UDEV)
		dom = NULL;
	else
		dom = KV_KEY_DOM_USER;

	return _do_sid_ucmd_get_kv(mod_res, ucmd_ctx, _owner_name(mod_res), dom, ns, key, value_size, flags, archive);
}

static const void *_do_sid_ucmd_get_foreign_kv(sid_res_t              *res,
                                               struct sid_ucmd_ctx    *ucmd_ctx,
                                               const char             *owner,
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
	                               .ns_part  = _get_foreign_ns_part(ucmd_ctx, owner, foreign_mod_name, foreign_dev_id, ns),
	                               .id_cat   = ns == SID_KV_NS_DEVMOD ? KV_PREFIX_NS_MODULE_C : ID_NULL,
	                               .id       = ns == SID_KV_NS_DEVMOD ? foreign_mod_name : ID_NULL,
	                               .core     = key};

	return _cmd_get_key_spec_value(res, ucmd_ctx, owner, &key_spec, value_size, flags);
}

const void *sid_ucmd_kv_get_foreign_mod(sid_res_t              *mod_res,
                                        struct sid_ucmd_ctx    *ucmd_ctx,
                                        const char             *foreign_mod_name,
                                        sid_ucmd_kv_namespace_t ns,
                                        const char             *key,
                                        size_t                 *value_size,
                                        sid_ucmd_kv_flags_t    *flags,
                                        unsigned int            archive)
{
	const char *dom;

	if (!mod_res || !ucmd_ctx || UTIL_STR_EMPTY(foreign_mod_name) || !*foreign_mod_name || (ns == SID_KV_NS_UNDEFINED) ||
	    UTIL_STR_EMPTY(key) || (key[0] == KV_PREFIX_KEY_SYS_C[0]))
		return NULL;

	if (!sid_mod_reg_match_dep(mod_res, ucmd_ctx->common->block_mod_reg_res) &&
	    !sid_mod_reg_match_dep(mod_res, ucmd_ctx->common->type_mod_reg_res))
		return NULL;

	dom = ns == SID_KV_NS_UDEV ? NULL : KV_KEY_DOM_USER;

	return _do_sid_ucmd_get_foreign_kv(mod_res,
	                                   ucmd_ctx,
	                                   _owner_name(mod_res),
	                                   foreign_mod_name,
	                                   NULL,
	                                   dom,
	                                   ns,
	                                   key,
	                                   value_size,
	                                   flags,
	                                   archive);
}

const void *sid_ucmd_kv_get_foreign_dev(sid_res_t              *mod_res,
                                        struct sid_ucmd_ctx    *ucmd_ctx,
                                        const char             *foreign_dev_id,
                                        sid_ucmd_kv_namespace_t ns,
                                        const char             *key,
                                        size_t                 *value_size,
                                        sid_ucmd_kv_flags_t    *flags,
                                        unsigned int            archive)
{
	const char *dom;

	if (!mod_res || !ucmd_ctx || UTIL_STR_EMPTY(foreign_dev_id) || (ns == SID_KV_NS_UNDEFINED) || UTIL_STR_EMPTY(key) ||
	    (key[0] == KV_PREFIX_KEY_SYS_C[0]))
		return NULL;

	if (!sid_mod_reg_match_dep(mod_res, ucmd_ctx->common->block_mod_reg_res) &&
	    !sid_mod_reg_match_dep(mod_res, ucmd_ctx->common->type_mod_reg_res))
		return NULL;

	dom = ns == SID_KV_NS_UDEV ? NULL : KV_KEY_DOM_USER;

	return _do_sid_ucmd_get_foreign_kv(mod_res,
	                                   ucmd_ctx,
	                                   _owner_name(mod_res),
	                                   NULL,
	                                   foreign_dev_id,
	                                   dom,
	                                   ns,
	                                   key,
	                                   value_size,
	                                   flags,
	                                   archive);
}

const void *sid_ucmd_kv_get_foreign_dev_mod(sid_res_t              *mod_res,
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

	if (!mod_res || !ucmd_ctx || UTIL_STR_EMPTY(foreign_dev_id) || UTIL_STR_EMPTY(foreign_mod_name) ||
	    (ns == SID_KV_NS_UNDEFINED) || UTIL_STR_EMPTY(key) || (key[0] == KV_PREFIX_KEY_SYS_C[0]))
		return NULL;

	if (!sid_mod_reg_match_dep(mod_res, ucmd_ctx->common->block_mod_reg_res) &&
	    !sid_mod_reg_match_dep(mod_res, ucmd_ctx->common->type_mod_reg_res))
		return NULL;

	dom = ns == SID_KV_NS_UDEV ? NULL : KV_KEY_DOM_USER;

	return _do_sid_ucmd_get_foreign_kv(mod_res,
	                                   ucmd_ctx,
	                                   _owner_name(mod_res),
	                                   foreign_mod_name,
	                                   foreign_dev_id,
	                                   dom,
	                                   ns,
	                                   key,
	                                   value_size,
	                                   flags,
	                                   archive);
}

static int _do_sid_ucmd_mod_reserve_kv(sid_res_t                  *res,
                                       struct sid_ucmd_common_ctx *common,
                                       const char                 *owner,
                                       const char                 *dom,
                                       sid_ucmd_kv_namespace_t     ns,
                                       const char                 *key_core,
                                       sid_ucmd_kv_flags_t         flags,
                                       int                         unset)
{
	char                *key = NULL;
	kv_vector_t          vvalue[VVALUE_HEADER_CNT]; /* only header */
	struct kv_update_arg update_arg;
	struct kv_unset_nfo  unset_nfo;
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

	if (!(common->kvs_res))
		goto out;

	/*
	 * FIXME: If possible, try to find out a way without calling worker_control_is_worker here.
	 *        Otherwise, this code assumes that we always have main process with main KV store
	 *        and worker processes with snapshots to sync. This doesn't necessarily need to
	 *        be true in all cases in the future!
	 */
	is_worker  = sid_wrk_ctl_detect_worker(common->kvs_res);

	update_arg = (struct kv_update_arg) {.res      = common->kvs_res,
	                                     .gen_buf  = NULL,
	                                     .is_sync  = !is_worker,
	                                     .custom   = NULL,
	                                     .ret_code = -EREMOTEIO};

	if (!unset)
		flags |= SID_KV_FL_RS | SID_KV_FL_SYNC_P;

	if (unset && !is_worker) {
		unset_nfo.owner   = owner;
		unset_nfo.seqnum  = 0; /* reservation is handled before/after any events, so no seqnum here - use 0 instead */
		update_arg.custom = &unset_nfo;

		if (sid_kvs_unset(common->kvs_res, key, _kv_cb_reserve, &update_arg) < 0 || update_arg.ret_code < 0)
			goto out;
	} else {
		_vvalue_header_prep(vvalue, VVALUE_CNT(vvalue), &null_int, &flags, &common->gennum, (char *) owner);
		if (!sid_kvs_set(common->kvs_res,
		                 key,
		                 vvalue,
		                 VVALUE_HEADER_CNT,
		                 SID_KVS_VAL_FL_VECTOR,
		                 SID_KVS_VAL_OP_MERGE,
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

int sid_ucmd_kv_reserve(sid_res_t                  *mod_res,
                        struct sid_ucmd_common_ctx *common,
                        sid_ucmd_kv_namespace_t     ns,
                        const char                 *key,
                        sid_ucmd_kv_flags_t         flags)
{
	const char *dom;

	if (!mod_res || !common || UTIL_STR_EMPTY(key) || (key[0] == KV_PREFIX_KEY_SYS_C[0]))
		return -EINVAL;

	if (!sid_mod_reg_match_dep(mod_res, common->block_mod_reg_res) && !sid_mod_reg_match_dep(mod_res, common->type_mod_reg_res))
		return -EINVAL;

	dom = ns == SID_KV_NS_UDEV ? NULL : KV_KEY_DOM_USER;

	return _do_sid_ucmd_mod_reserve_kv(mod_res, common, _owner_name(mod_res), dom, ns, key, flags, 0);
}

int sid_ucmd_kv_unreserve(sid_res_t *mod_res, struct sid_ucmd_common_ctx *common, sid_ucmd_kv_namespace_t ns, const char *key)
{
	const char *dom;

	if (!mod_res || !common || UTIL_STR_EMPTY(key) || (key[0] == KV_PREFIX_KEY_SYS_C[0]))
		return -EINVAL;

	if (!sid_mod_reg_match_dep(mod_res, common->block_mod_reg_res) && !sid_mod_reg_match_dep(mod_res, common->type_mod_reg_res))
		return -EINVAL;

	dom = ns == SID_KV_NS_UDEV ? NULL : KV_KEY_DOM_USER;

	return _do_sid_ucmd_mod_reserve_kv(mod_res, common, _owner_name(mod_res), dom, ns, key, SID_KV_FL_NONE, 1);
}

const char *sid_ucmd_dev_ready_to_str(sid_ucmd_dev_ready_t ready)
{
	return dev_ready_str[ready];
}

const char *sid_ucmd_dev_reserved_to_str(sid_ucmd_dev_reserved_t reserved)
{
	return dev_reserved_str[reserved];
}

static int _do_sid_ucmd_dev_set_ready(sid_res_t           *res,
                                      struct sid_ucmd_ctx *ucmd_ctx,
                                      const char          *owner,
                                      sid_ucmd_dev_ready_t ready,
                                      bool                 is_sync)
{
	sid_ucmd_dev_ready_t old_ready = ucmd_ctx->scan.dev_ready;
	int                  r;

	if (!(_cmd_scan_phase_regs[ucmd_ctx->scan.phase].flags & CMD_SCAN_CAP_RDY)) {
		r = -EPERM;
		goto out;
	}

	if (ready == old_ready) {
		r = 0;
		goto out;
	}

	switch (ready) {
		case SID_DEV_RDY_UNDEFINED:
			r = -EBADRQC;
			goto out;

		case SID_DEV_RDY_REMOVED:
			if (old_ready == SID_DEV_RDY_UNDEFINED) {
				r = -EBADRQC;
				goto out;
			}
			break;

		case SID_DEV_RDY_UNPROCESSED:
			if (old_ready != SID_DEV_RDY_UNDEFINED) {
				r = -EBADRQC;
				goto out;
			}
			break;

		case SID_DEV_RDY_UNCONFIGURED:
			if (old_ready != SID_DEV_RDY_UNPROCESSED) {
				r = -EBADRQC;
				goto out;
			}
			break;

		case SID_DEV_RDY_UNINITIALIZED:
		case SID_DEV_RDY_PRIVATE:
		case SID_DEV_RDY_FLAT:
		case SID_DEV_RDY_UNAVAILABLE:
		case SID_DEV_RDY_PUBLIC:
			if (old_ready == SID_DEV_RDY_UNDEFINED) {
				r = -EBADRQC;
				goto out;
			}
			break;
	}

	if (!_do_sid_ucmd_set_kv(res,
	                         ucmd_ctx,
	                         owner,
	                         NULL,
	                         SID_KV_NS_DEVICE,
	                         KV_KEY_DEV_READY,
	                         (is_sync ? 0 : SID_KV_FL_SYNC) | SID_KV_FL_AR | SID_KV_FL_RD | SID_KV_FL_SUB_WR | SID_KV_FL_SUP_WR,
	                         &ready,
	                         sizeof(ready)))
		r = -1;
	else
		r = 0;
out:
	if (r < 0) {
		sid_res_log_error_errno(res,
		                        r,
		                        "Ready state change failed for device " CMD_DEV_PRINT_FMT ": %s --> %s.",
		                        CMD_DEV_PRINT(ucmd_ctx),
		                        dev_ready_str[old_ready],
		                        dev_ready_str[ready]);
	} else {
		ucmd_ctx->scan.dev_ready = ready;
		sid_res_log_debug(res,
		                  "Ready state changed for device " CMD_DEV_PRINT_FMT ": %s --> %s.",
		                  CMD_DEV_PRINT(ucmd_ctx),
		                  dev_ready_str[old_ready],
		                  dev_ready_str[ready]);
	}

	return r;
}

int sid_ucmd_dev_set_ready(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx, sid_ucmd_dev_ready_t ready)
{
	if (!mod_res || !ucmd_ctx)
		return -EINVAL;

	if (!sid_mod_reg_match_dep(mod_res, ucmd_ctx->common->block_mod_reg_res) &&
	    !sid_mod_reg_match_dep(mod_res, ucmd_ctx->common->type_mod_reg_res))
		return -EINVAL;

	return _do_sid_ucmd_dev_set_ready(mod_res, ucmd_ctx, _owner_name(mod_res), ready, false);
}

static sid_ucmd_dev_ready_t
	_do_sid_ucmd_dev_get_ready(sid_res_t *res, struct sid_ucmd_ctx *ucmd_ctx, const char *owner, unsigned int archive)
{
	const void          *val;
	sid_ucmd_dev_ready_t ready_arch;

	if (archive) {
		if ((val = _do_sid_ucmd_get_kv(res,
		                               ucmd_ctx,
		                               owner,
		                               NULL,
		                               SID_KV_NS_DEVICE,
		                               KV_KEY_DEV_READY,
		                               NULL,
		                               NULL,
		                               archive)))
			memcpy(&ready_arch, val, sizeof(sid_ucmd_dev_ready_t));
		else
			ready_arch = SID_DEV_RDY_UNDEFINED;

		return ready_arch;
	}

	if (ucmd_ctx->scan.dev_ready == SID_DEV_RDY_UNDEFINED) {
		if ((val = _do_sid_ucmd_get_kv(res, ucmd_ctx, owner, NULL, SID_KV_NS_DEVICE, KV_KEY_DEV_READY, NULL, NULL, 0)))
			memcpy(&ucmd_ctx->scan.dev_ready, val, sizeof(sid_ucmd_dev_ready_t));
	}

	return ucmd_ctx->scan.dev_ready;
}

sid_ucmd_dev_ready_t sid_ucmd_dev_get_ready(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx, unsigned int archive)
{
	if (!mod_res || !ucmd_ctx)
		return SID_DEV_RDY_UNDEFINED;

	if (!sid_mod_reg_match_dep(mod_res, ucmd_ctx->common->block_mod_reg_res) &&
	    !sid_mod_reg_match_dep(mod_res, ucmd_ctx->common->type_mod_reg_res))
		return SID_DEV_RDY_UNDEFINED;

	return _do_sid_ucmd_dev_get_ready(mod_res, ucmd_ctx, _owner_name(mod_res), archive);
}

static int _do_sid_ucmd_dev_set_reserved(sid_res_t              *res,
                                         struct sid_ucmd_ctx    *ucmd_ctx,
                                         const char             *owner,
                                         sid_ucmd_dev_reserved_t reserved,
                                         bool                    is_sync)
{
	sid_ucmd_dev_reserved_t old_reserved = ucmd_ctx->scan.dev_reserved;
	int                     r;

	if (!(_cmd_scan_phase_regs[ucmd_ctx->scan.phase].flags & CMD_SCAN_CAP_RES)) {
		r = -EPERM;
		goto out;
	}

	if (reserved == old_reserved) {
		r = 0;
		goto out;
	}

	switch (reserved) {
		case SID_DEV_RDY_UNDEFINED:
			r = -EBADRQC;
			goto out;

		case SID_DEV_RES_UNPROCESSED:
			if (old_reserved != SID_DEV_RES_UNDEFINED) {
				r = -EBADRQC;
				goto out;
			}
			break;

		case SID_DEV_RES_RESERVED:
			break;

		case SID_DEV_RES_USED:
			break;

		case SID_DEV_RES_FREE:
			break;
	}

	if (!_do_sid_ucmd_set_kv(res,
	                         ucmd_ctx,
	                         owner,
	                         NULL,
	                         SID_KV_NS_DEVICE,
	                         KV_KEY_DEV_RESERVED,
	                         (is_sync ? 0 : SID_KV_FL_SYNC) | SID_KV_FL_AR | SID_KV_FL_RD | SID_KV_FL_SUB_WR | SID_KV_FL_SUP_WR,
	                         &reserved,
	                         sizeof(reserved)))
		r = -1;
	else
		r = 0;
out:
	if (r < 0) {
		sid_res_log_error_errno(res,
		                        r,
		                        "Reserved state change failed for device " CMD_DEV_PRINT_FMT ": %s --> %s.",
		                        CMD_DEV_PRINT(ucmd_ctx),
		                        dev_reserved_str[old_reserved],
		                        dev_reserved_str[reserved]);
	} else {
		ucmd_ctx->scan.dev_reserved = reserved;
		sid_res_log_debug(res,
		                  "Reserved state changed for device " CMD_DEV_PRINT_FMT ": %s --> %s.",
		                  CMD_DEV_PRINT(ucmd_ctx),
		                  dev_reserved_str[old_reserved],
		                  dev_reserved_str[reserved]);
	}

	return r;
}

int sid_ucmd_dev_set_reserved(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx, sid_ucmd_dev_reserved_t reserved)
{
	if (!mod_res || !ucmd_ctx)
		return -EINVAL;

	if (!sid_mod_reg_match_dep(mod_res, ucmd_ctx->common->block_mod_reg_res) &&
	    !sid_mod_reg_match_dep(mod_res, ucmd_ctx->common->type_mod_reg_res))
		return -EINVAL;

	return _do_sid_ucmd_dev_set_reserved(mod_res, ucmd_ctx, _owner_name(mod_res), reserved, false);
}

static sid_ucmd_dev_reserved_t
	_do_sid_ucmd_dev_get_reserved(sid_res_t *res, struct sid_ucmd_ctx *ucmd_ctx, const char *owner, unsigned int archive)
{
	const void             *val;
	sid_ucmd_dev_reserved_t reserved_arch;

	if (archive) {
		if ((val = _do_sid_ucmd_get_kv(res,
		                               ucmd_ctx,
		                               owner,
		                               NULL,
		                               SID_KV_NS_DEVICE,
		                               KV_KEY_DEV_RESERVED,
		                               NULL,
		                               NULL,
		                               archive)))
			memcpy(&reserved_arch, val, sizeof(sid_ucmd_dev_ready_t));
		else
			reserved_arch = SID_DEV_RES_UNDEFINED;

		return reserved_arch;
	}

	if (ucmd_ctx->scan.dev_reserved == SID_DEV_RES_UNDEFINED) {
		if ((val = _do_sid_ucmd_get_kv(res, ucmd_ctx, owner, NULL, SID_KV_NS_DEVICE, KV_KEY_DEV_RESERVED, NULL, NULL, 0)))
			memcpy(&ucmd_ctx->scan.dev_reserved, val, sizeof(sid_ucmd_dev_ready_t));
	}

	return ucmd_ctx->scan.dev_reserved;
}

sid_ucmd_dev_reserved_t sid_ucmd_dev_get_reserved(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx, unsigned int archive)
{
	if (!mod_res || !ucmd_ctx)
		return SID_DEV_RES_UNDEFINED;

	if (!sid_mod_reg_match_dep(mod_res, ucmd_ctx->common->block_mod_reg_res) &&
	    !sid_mod_reg_match_dep(mod_res, ucmd_ctx->common->type_mod_reg_res))
		return SID_DEV_RES_UNDEFINED;

	return _do_sid_ucmd_dev_get_reserved(mod_res, ucmd_ctx, _owner_name(mod_res), archive);
}

static int _handle_devs_for_group(sid_res_t              *res,
                                  struct sid_ucmd_ctx    *ucmd_ctx,
                                  const char             *owner,
                                  const kv_vector_t      *vdevs,
                                  size_t                  vdevs_size,
                                  const char             *dom,
                                  sid_ucmd_kv_namespace_t group_ns,
                                  const char             *group_cat,
                                  const char             *group_id,
                                  kv_op_t                 op,
                                  bool                    is_sync)
{
	char               *key            = NULL;
	const char         *rel_key_prefix = NULL;
	kv_vector_t         single_vvalue[VVALUE_SINGLE_CNT];
	kv_vector_t        *vvalue = NULL;
	size_t              vvalue_size;
	sid_ucmd_kv_flags_t flags = value_flags_no_sync;
	unsigned            i;
	int                 r       = -1;

	struct kv_rel_spec rel_spec = {
		.delta        = &((struct kv_delta) {.op = op, .flags = DELTA_WITH_DIFF | DELTA_WITH_REL}),

		.abs_delta    = &((struct kv_delta) {0}),

		.cur_key_spec = &((struct kv_key_spec) {.extra_op = NULL,
	                                                .op       = KV_OP_SET,
	                                                .dom      = dom ?: ID_NULL,
	                                                .ns       = group_ns,
	                                                .ns_part  = _get_ns_part(ucmd_ctx, owner, SID_KV_NS_MODULE),
	                                                .id_cat   = group_cat,
	                                                .id       = group_id,
	                                                .core     = KV_KEY_GEN_GROUP_MEMBERS}),

		.rel_key_spec = &((struct kv_key_spec) {.extra_op = NULL,
	                                                .op       = KV_OP_SET,
	                                                .dom      = ID_NULL,
	                                                .ns       = SID_KV_NS_DEVICE,
	                                                .ns_part  = _get_ns_part(ucmd_ctx, owner, SID_KV_NS_DEVICE),
	                                                .id_cat   = ID_NULL,
	                                                .id       = ID_NULL,
	                                                .core     = KV_KEY_GEN_GROUP_IN})};

	struct kv_update_arg update_arg = {.res     = ucmd_ctx->common->kvs_res,
	                                   .gen_buf = ucmd_ctx->common->gen_buf,
	                                   .is_sync = is_sync,
	                                   .custom  = &rel_spec};

	// TODO: check return values / maybe also pass flags / use proper owner

	if (!(key = _compose_key(NULL, rel_spec.cur_key_spec)))
		goto out;

	if (vdevs) {
		/* use given vector of devices */
		if (!(vvalue = malloc((VVALUE_HEADER_CNT + vdevs_size) * sizeof(kv_vector_t))))
			goto out;
		vvalue_size = VVALUE_HEADER_CNT + vdevs_size;
	} else {
		/* use the device that is associated with current event (ucmd_ctx) */
		vvalue      = single_vvalue;
		vvalue_size = VVALUE_CNT(single_vvalue);
	}

	_vvalue_header_prep(vvalue, vvalue_size, &ucmd_ctx->req_env.dev.udev.seqnum, &flags, &ucmd_ctx->common->gennum, core_owner);

	if (vdevs) {
		for (i = 0; i < vdevs_size; i++)
			vvalue[VVALUE_HEADER_CNT + i] = vdevs[i];
	} else {
		if (!(rel_key_prefix = _compose_key_prefix(NULL, rel_spec.rel_key_spec)))
			goto out;

		_vvalue_data_prep(vvalue, vvalue_size, 0, (void *) rel_key_prefix, strlen(rel_key_prefix) + 1);
	}

	if (_kv_delta_set(key, vvalue, vvalue_size, &update_arg) < 0)
		goto out;

	r = 0;
out:
	if (vdevs)
		free(vvalue);
	_destroy_key(NULL, key);
	_destroy_key(NULL, rel_key_prefix);
	return r;
}

static int _do_sid_ucmd_group_destroy(sid_res_t              *res,
                                      struct sid_ucmd_ctx    *ucmd_ctx,
                                      const char             *owner,
                                      const char             *dom,
                                      sid_ucmd_kv_namespace_t group_ns,
                                      const char             *group_cat,
                                      const char             *group_id,
                                      int                     force)
{
	static sid_ucmd_kv_flags_t kv_flags_sync_no_reserved = (DEFAULT_VALUE_FLAGS_CORE) & ~SID_KV_FL_RS;
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
	                                                                        .ns_part  = _get_ns_part(ucmd_ctx, owner, group_ns),
	                                                                        .id_cat   = group_cat,
	                                                                        .id       = group_id,
	                                                                        .core     = KV_KEY_GEN_GROUP_MEMBERS}),

	                                .rel_key_spec = &((struct kv_key_spec) {.extra_op = NULL,
	                                                                        .op       = KV_OP_SET,
	                                                                        .dom      = ID_NULL,
	                                                                        .ns       = SID_KV_NS_DEVICE,
	                                                                        .ns_part  = ID_NULL,
	                                                                        .id_cat   = ID_NULL,
	                                                                        .id       = ID_NULL,
	                                                                        .core     = KV_KEY_GEN_GROUP_IN})};

	struct kv_update_arg update_arg = {.res     = ucmd_ctx->common->kvs_res,
	                                   .gen_buf = ucmd_ctx->common->gen_buf,
	                                   .is_sync = false,
	                                   .custom  = &rel_spec};

	// TODO: do not call kv_store_get_value, only kv_store_set_value and provide _kv_cb_delta wrapper
	//       to do the "is empty?" check before the actual _kv_cb_delta operation

	if (!(key = _compose_key(NULL, rel_spec.cur_key_spec)))
		goto out;

	if (!sid_kvs_get(ucmd_ctx->common->kvs_res, key, &size, NULL))
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

	if ((r = _kv_delta_set(key, vvalue, VVALUE_HEADER_CNT, &update_arg)) < 0)
		goto out;

	r = 0;
out:
	_destroy_key(NULL, key);
	return r;
}

int sid_ucmd_dev_alias_add(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx, const char *alias_key, const char *alias)
{
	if (!mod_res || !ucmd_ctx || UTIL_STR_EMPTY(alias_key) || UTIL_STR_EMPTY(alias))
		return -EINVAL;

	if (!sid_mod_reg_match_dep(mod_res, ucmd_ctx->common->block_mod_reg_res) &&
	    !sid_mod_reg_match_dep(mod_res, ucmd_ctx->common->type_mod_reg_res))
		return -EINVAL;

	return _handle_devs_for_group(mod_res,
	                              ucmd_ctx,
	                              _owner_name(mod_res),
	                              NULL,
	                              0,
	                              KV_KEY_DOM_ALIAS,
	                              SID_KV_NS_MODULE,
	                              alias_key,
	                              alias,
	                              KV_OP_PLUS,
	                              false);
}

int sid_ucmd_dev_alias_rename(sid_res_t           *mod_res,
                              struct sid_ucmd_ctx *ucmd_ctx,
                              const char          *alias_key,
                              const char          *old_alias,
                              const char          *new_alias)
{
	struct kv_key_spec key_spec;
	const kv_vector_t *vdevs;
	size_t             vdevs_size;

	if (!mod_res || !ucmd_ctx || UTIL_STR_EMPTY(alias_key) || UTIL_STR_EMPTY(old_alias) || UTIL_STR_EMPTY(new_alias))
		return -EINVAL;

	key_spec = (struct kv_key_spec) {.extra_op = NULL,
	                                 .op       = KV_OP_SET,
	                                 .dom      = KV_KEY_DOM_ALIAS,
	                                 .ns       = SID_KV_NS_MODULE,
	                                 .ns_part  = _get_ns_part(ucmd_ctx, _owner_name(mod_res), SID_KV_NS_MODULE),
	                                 .id_cat   = alias_key,
	                                 .id       = old_alias,
	                                 .core     = KV_KEY_GEN_GROUP_MEMBERS};

	if (!(vdevs = _cmd_get_key_spec_value(mod_res, ucmd_ctx, _owner_name(mod_res), &key_spec, &vdevs_size, NULL)) ||
	    !vdevs_size)
		return 0;

	_handle_devs_for_group(mod_res,
	                       ucmd_ctx,
	                       _owner_name(mod_res),
	                       vdevs,
	                       vdevs_size,
	                       KV_KEY_DOM_ALIAS,
	                       SID_KV_NS_MODULE,
	                       alias_key,
	                       new_alias,
	                       KV_OP_PLUS,
	                       false);

	return _do_sid_ucmd_group_destroy(mod_res,
	                                  ucmd_ctx,
	                                  _owner_name(mod_res),
	                                  KV_KEY_DOM_ALIAS,
	                                  SID_KV_NS_MODULE,
	                                  alias_key,
	                                  old_alias,
	                                  true);
}

int sid_ucmd_dev_alias_del(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx, const char *alias_key, const char *alias)
{
	if (!mod_res || !ucmd_ctx || UTIL_STR_EMPTY(alias_key) || UTIL_STR_EMPTY(alias))
		return -EINVAL;

	if (!sid_mod_reg_match_dep(mod_res, ucmd_ctx->common->block_mod_reg_res) &&
	    !sid_mod_reg_match_dep(mod_res, ucmd_ctx->common->type_mod_reg_res))
		return -EINVAL;

	return _handle_devs_for_group(mod_res,
	                              ucmd_ctx,
	                              _owner_name(mod_res),
	                              NULL,
	                              0,
	                              KV_KEY_DOM_ALIAS,
	                              SID_KV_NS_MODULE,
	                              alias_key,
	                              alias,
	                              KV_OP_MINUS,
	                              false);
}

const char **_do_sid_ucmd_dev_alias_get(sid_res_t           *mod_res,
                                        struct sid_ucmd_ctx *ucmd_ctx,
                                        const char          *mod_name,
                                        const char          *foreign_dev_id,
                                        const char          *alias_key,
                                        size_t              *count)
{
	const kv_vector_t *vvalue;
	size_t             vvalue_size;
	char             **key_strv;

	vvalue = _cmd_get_key_spec_value(
		mod_res,
		ucmd_ctx,
		_owner_name(mod_res),
		&((struct kv_key_spec) {.extra_op = NULL,
	                                .op       = KV_OP_SET,
	                                .dom      = ID_NULL,
	                                .ns       = SID_KV_NS_DEVICE,
	                                .ns_part = foreign_dev_id ?: _get_ns_part(ucmd_ctx, _owner_name(mod_res), SID_KV_NS_DEVICE),
	                                .id_cat  = ID_NULL,
	                                .id      = ID_NULL,
	                                .core    = KV_KEY_GEN_GROUP_IN}),
		&vvalue_size,
		NULL);

	if (!vvalue)
		return NULL;

	key_strv = _get_key_strv_from_vvalue(vvalue,
	                                     vvalue_size,
	                                     &((struct kv_key_spec) {.extra_op = NULL,
	                                                             .op       = KV_OP_SET,
	                                                             .dom      = KV_KEY_DOM_ALIAS,
	                                                             .ns       = SID_KV_NS_MODULE,
	                                                             .ns_part  = mod_name,
	                                                             .id_cat   = alias_key ?: NULL,
	                                                             .id       = NULL,
	                                                             .core     = NULL}),
	                                     count);

	return (const char **) key_strv;
}

const char **sid_ucmd_dev_alias_get(sid_res_t           *mod_res,
                                    struct sid_ucmd_ctx *ucmd_ctx,
                                    const char          *mod_name,
                                    const char          *alias_key,
                                    size_t              *count)
{
	if (!mod_res || !ucmd_ctx ||
	    (!sid_mod_reg_match_dep(mod_res, ucmd_ctx->common->block_mod_reg_res) &&
	     !sid_mod_reg_match_dep(mod_res, ucmd_ctx->common->type_mod_reg_res))) {
		if (count)
			*count = 0;
		return NULL;
	}

	return _do_sid_ucmd_dev_alias_get(mod_res, ucmd_ctx, mod_name, NULL, alias_key, count);
}

const char **sid_ucmd_dev_alias_get_foreign_dev(sid_res_t           *mod_res,
                                                struct sid_ucmd_ctx *ucmd_ctx,
                                                const char          *mod_name,
                                                const char          *foreign_dev_id,
                                                const char          *alias_key,
                                                size_t              *count)
{
	if (!mod_res || !ucmd_ctx || UTIL_STR_EMPTY(foreign_dev_id) ||
	    (!sid_mod_reg_match_dep(mod_res, ucmd_ctx->common->block_mod_reg_res) &&
	     !sid_mod_reg_match_dep(mod_res, ucmd_ctx->common->type_mod_reg_res))) {
		if (count)
			*count = 0;
		return NULL;
	}

	return _do_sid_ucmd_dev_alias_get(mod_res, ucmd_ctx, mod_name, foreign_dev_id, alias_key, count);
}

static int _kv_cb_write_new_only(struct sid_kvs_update_spec *spec)
{
	if (spec->old_data)
		return 0;

	return _kv_cb_write(spec);
}

static int _do_sid_ucmd_group_create(sid_res_t              *res,
                                     struct sid_ucmd_ctx    *ucmd_ctx,
                                     const char             *owner,
                                     const char             *dom,
                                     sid_ucmd_kv_namespace_t group_ns,
                                     sid_ucmd_kv_flags_t     group_flags,
                                     const char             *group_cat,
                                     const char             *group_id)
{
	char       *key = NULL;
	kv_vector_t vvalue[VVALUE_HEADER_CNT];
	int         r                   = -1;

	struct kv_key_spec key_spec     = {.extra_op = NULL,
	                                   .op       = KV_OP_SET,
	                                   .dom      = dom ?: ID_NULL,
	                                   .ns       = group_ns,
	                                   .ns_part  = _get_ns_part(ucmd_ctx, owner, group_ns),
	                                   .id_cat   = group_cat,
	                                   .id       = group_id,
	                                   .core     = KV_KEY_GEN_GROUP_MEMBERS};

	struct kv_update_arg update_arg = {.res      = ucmd_ctx->common->kvs_res,
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

	if (!sid_kvs_set(ucmd_ctx->common->kvs_res,
	                 key,
	                 vvalue,
	                 VVALUE_HEADER_CNT,
	                 SID_KVS_VAL_FL_VECTOR,
	                 SID_KVS_VAL_OP_NONE,
	                 _kv_cb_write_new_only,
	                 &update_arg))
		goto out;

	(void) _manage_kv_index(&update_arg, key);

	r = 0;
out:
	_destroy_key(ucmd_ctx->common->gen_buf, key);
	return r;
}

int sid_ucmd_grp_create(sid_res_t              *mod_res,
                        struct sid_ucmd_ctx    *ucmd_ctx,
                        sid_ucmd_kv_namespace_t group_ns,
                        sid_ucmd_kv_flags_t     group_flags,
                        const char             *group_cat,
                        const char             *group_id)
{
	if (!mod_res || !ucmd_ctx || (group_ns == SID_KV_NS_UNDEFINED) || UTIL_STR_EMPTY(group_id))
		return -EINVAL;

	if (!sid_mod_reg_match_dep(mod_res, ucmd_ctx->common->block_mod_reg_res) &&
	    !sid_mod_reg_match_dep(mod_res, ucmd_ctx->common->type_mod_reg_res))
		return -EINVAL;

	group_flags &= ~SID_KV_FL_ALIGN;

	return _do_sid_ucmd_group_create(mod_res,
	                                 ucmd_ctx,
	                                 _owner_name(mod_res),
	                                 KV_KEY_DOM_GROUP,
	                                 group_ns,
	                                 group_flags,
	                                 group_cat,
	                                 group_id);
}

int sid_ucmd_grp_add_current_dev(sid_res_t              *mod_res,
                                 struct sid_ucmd_ctx    *ucmd_ctx,
                                 sid_ucmd_kv_namespace_t group_ns,
                                 const char             *group_cat,
                                 const char             *group_id)
{
	if (!mod_res || !ucmd_ctx || (group_ns == SID_KV_NS_UNDEFINED) || UTIL_STR_EMPTY(group_cat) || UTIL_STR_EMPTY(group_id))
		return -EINVAL;

	if (!sid_mod_reg_match_dep(mod_res, ucmd_ctx->common->block_mod_reg_res) &&
	    !sid_mod_reg_match_dep(mod_res, ucmd_ctx->common->type_mod_reg_res))
		return -EINVAL;

	return _handle_devs_for_group(mod_res,
	                              ucmd_ctx,
	                              _owner_name(mod_res),
	                              NULL,
	                              0,
	                              KV_KEY_DOM_GROUP,
	                              group_ns,
	                              group_cat,
	                              group_id,
	                              KV_OP_PLUS,
	                              false);
}

int sid_ucmd_grp_del_current_dev(sid_res_t              *mod_res,
                                 struct sid_ucmd_ctx    *ucmd_ctx,
                                 sid_ucmd_kv_namespace_t group_ns,
                                 const char             *group_cat,
                                 const char             *group_id)
{
	if (!mod_res || !ucmd_ctx || (group_ns == SID_KV_NS_UNDEFINED) || UTIL_STR_EMPTY(group_cat) || UTIL_STR_EMPTY(group_id))
		return -EINVAL;

	if (!sid_mod_reg_match_dep(mod_res, ucmd_ctx->common->block_mod_reg_res) &&
	    !sid_mod_reg_match_dep(mod_res, ucmd_ctx->common->type_mod_reg_res))
		return -EINVAL;

	return _handle_devs_for_group(mod_res,
	                              ucmd_ctx,
	                              _owner_name(mod_res),
	                              NULL,
	                              0,
	                              KV_KEY_DOM_GROUP,
	                              group_ns,
	                              group_cat,
	                              group_id,
	                              KV_OP_MINUS,
	                              false);
}

int sid_ucmd_grp_destroy(sid_res_t              *mod_res,
                         struct sid_ucmd_ctx    *ucmd_ctx,
                         sid_ucmd_kv_namespace_t group_ns,
                         const char             *group_cat,
                         const char             *group_id,
                         int                     force)
{
	if (!mod_res || !ucmd_ctx || (group_ns == SID_KV_NS_UNDEFINED) || UTIL_STR_EMPTY(group_id))
		return -EINVAL;

	if (!sid_mod_reg_match_dep(mod_res, ucmd_ctx->common->block_mod_reg_res) &&
	    !sid_mod_reg_match_dep(mod_res, ucmd_ctx->common->type_mod_reg_res))
		return -EINVAL;

	return _do_sid_ucmd_group_destroy(mod_res,
	                                  ucmd_ctx,
	                                  _owner_name(mod_res),
	                                  KV_KEY_DOM_GROUP,
	                                  group_ns,
	                                  group_cat,
	                                  group_id,
	                                  force);
}

static int _device_add_field(sid_res_t *res, struct sid_ucmd_ctx *ucmd_ctx, const char *start)
{
	const char *key;
	const char *value;

	if (!(value = strchr(start, KV_PAIR_C[0])) || !*(++value))
		return -1;

	if (asprintf((char **) &key, "%.*s", (int) (value - start - 1), start) < 0)
		return -1;

	if (!(value = _do_sid_ucmd_set_kv(res,
	                                  ucmd_ctx,
	                                  _owner_name(NULL),
	                                  NULL,
	                                  SID_KV_NS_UDEV,
	                                  key,
	                                  SID_KV_FL_RD | SID_KV_FL_WR,
	                                  value,
	                                  strlen(value) + 1)))
		return -1;

	sid_res_log_debug(res, "Imported udev property %s=%s", key, value);

	/* Common key=value pairs are also directly in the ucmd_ctx->udev_dev structure. */
	if (!strcmp(key, UDEV_KEY_ACTION))
		ucmd_ctx->req_env.dev.udev.action = util_udev_str_to_action(value);
	else if (!strcmp(key, UDEV_KEY_DEVPATH)) {
		ucmd_ctx->req_env.dev.udev.path = value;
		ucmd_ctx->req_env.dev.udev.name = util_str_rstr(value, "/");
		ucmd_ctx->req_env.dev.udev.name++;
	} else if (!strcmp(key, UDEV_KEY_DEVTYPE))
		ucmd_ctx->req_env.dev.udev.type = util_udev_str_to_devtyoe(value);
	else if (!strcmp(key, UDEV_KEY_SEQNUM))
		ucmd_ctx->req_env.dev.udev.seqnum = strtoull(value, NULL, 10);
	else if (!strcmp(key, UDEV_KEY_DISKSEQ))
		ucmd_ctx->req_env.dev.udev.diskseq = strtoull(value, NULL, 10);
	else if (!strcmp(key, UDEV_KEY_SYNTH_UUID))
		ucmd_ctx->req_env.dev.udev.synth_uuid = value;

	free((void *) key);
	return 0;
};

static int _parse_cmd_udev_env(sid_res_t *res, struct sid_ucmd_ctx *ucmd_ctx, const char *env, size_t env_size)
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

	if (asprintf((char **) &ucmd_ctx->req_env.dev.num_s,
	             "%d_%d",
	             ucmd_ctx->req_env.dev.udev.major,
	             ucmd_ctx->req_env.dev.udev.minor) < 0) {
		r = -ENOMEM;
		goto out;
	}

	/*
	 * We have this on input ('devno' prefix is already processed so skip it):
	 *
	 *   devnokey1=value1\0key2=value2\0...
	 */
	for (end = env + env_size, env += sizeof(devno); env < end; env += strlen(env) + 1) {
		if ((r = _device_add_field(res, ucmd_ctx, env) < 0))
			goto out;
	}

	if (asprintf((char **) &ucmd_ctx->req_env.dev.dsq_s, "%" PRIu64, ucmd_ctx->req_env.dev.udev.diskseq) < 0) {
		r = -ENOMEM;
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

static int _part_get_whole_disk(sid_res_t *res, struct sid_ucmd_ctx *ucmd_ctx, char *devno_buf, size_t devno_buf_size)
{
	const char *s;
	int         r;

	if ((r = sid_buf_add_fmt(ucmd_ctx->common->gen_buf,
	                         (const void **) &s,
	                         NULL,
	                         "%s%s/../dev",
	                         SYSTEM_SYSFS_PATH,
	                         ucmd_ctx->req_env.dev.udev.path)) < 0) {
		sid_res_log_error_errno(res,
		                        r,
		                        "Failed to compose sysfs path for whole device of partition device " CMD_DEV_PRINT_FMT,
		                        CMD_DEV_PRINT(ucmd_ctx));
		return r;
	}

	if ((r = sid_util_sysfs_get(s, devno_buf, devno_buf_size, NULL)) < 0 || !*devno_buf)
		sid_res_log_error_errno(res, r, "Failed to read whole disk device number from sysfs file %s.", s);

	sid_buf_rewind_mem(ucmd_ctx->common->gen_buf, s);
	return r;
}

static int _dev_is_nvme(struct sid_ucmd_ctx *ucmd_ctx)
{
	/*
	 * FIXME: Is there any better and quick way of detecting we have
	 * 	  an NVMe device than just looking at its kernel name?
	 */
	return !strncmp(sid_ucmd_ev_get_dev_name(ucmd_ctx), DEV_NAME_PREFIX_NVME, sizeof(DEV_NAME_PREFIX_NVME) - 1);
}

static char *_lookup_mod_name(sid_res_t *cmd_res, const int dev_major, const char *dev_name, char *buf, size_t buf_size);

static char *_owner_name_from_blkext(sid_res_t *cmd_res, char *buf, size_t buf_size)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_res_get_data(cmd_res);
	char                 devno_buf[16];
	int                  dev_major;
	char                *p;
	char                *mod_name;

	switch (sid_ucmd_ev_get_dev_type(ucmd_ctx)) {
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
			if (_part_get_whole_disk(cmd_res, ucmd_ctx, devno_buf, sizeof(devno_buf)) < 0)
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
static char *_lookup_mod_name(sid_res_t *cmd_res, const int dev_major, const char *dev_name, char *buf, size_t buf_size)
{
	char  *p, *end, *found = NULL, *mod_name = NULL;
	FILE  *f = NULL;
	char   line[80];
	int    in_block_section = 0;
	int    major;
	size_t len;

	if (!(f = fopen(SYSTEM_PROC_DEVICES_PATH, "r"))) {
		sid_res_log_sys_error(cmd_res, "fopen", SYSTEM_PROC_DEVICES_PATH);
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
		sid_res_log_error(cmd_res,
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
		if (!(found = _owner_name_from_blkext(cmd_res, buf, buf_size))) {
			sid_res_log_error(cmd_res, "Failed to get module name for blkext device.");
			goto out;
		}
		len = strlen(found);
	} else
		len = p - found;

	if (len >= buf_size) {
		sid_res_log_error(cmd_res,
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

static int _connection_cleanup(sid_res_t *conn_res)
{
	return sid_res_isolate(conn_res, SID_RES_ISOL_FL_KEEP_SERVICE_LINKS) == 0 && sid_res_unref(conn_res) == 0;
}

static int                   _change_cmd_state(sid_res_t *cmd_res, cmd_state_t state);
static const struct cmd_reg *_get_cmd_reg(struct sid_ucmd_ctx *ucmd_ctx);

static int _on_cmd_tim_out_event(sid_res_ev_src_t *es, uint64_t usec, void *data)
{
	return _change_cmd_state((sid_res_t *) data, CMD_STATE_TIM_OUT);
}

static void _destroy_tim_out_es(struct sid_ucmd_ctx *ucmd_ctx)
{
	(void) sid_res_ev_destroy(&ucmd_ctx->tim_out_es);
	ucmd_ctx->tim_out_es = 0;
}

static bool _is_last_stage(const struct cmd_reg *cmd_reg, const struct sid_ucmd_ctx *ucmd_ctx)
{
	return !cmd_reg->stage_count || (cmd_reg->stage_count == ucmd_ctx->stage);
}

static int _change_cmd_state(sid_res_t *cmd_res, cmd_state_t state)
{
	static const char     cmd_stage_msg[] = "Command stage: ";
	struct sid_ucmd_ctx  *ucmd_ctx        = sid_res_get_data(cmd_res);
	const struct cmd_reg *cmd_reg;

	if (ucmd_ctx->state == state) {
		sid_res_log_error(cmd_res,
		                  SID_INTERNAL_ERROR "%s: Command already in requested state %s.",
		                  __func__,
		                  cmd_state_str[state]);
		return -1;
	}

	if (state == CMD_STATE_EXE_SCHED) {
		cmd_reg = _get_cmd_reg(ucmd_ctx);

		if ((ucmd_ctx->state != CMD_STATE_INI))
			(void) sid_res_ev_set_counter(ucmd_ctx->cmd_handler_es, SID_RES_POS_REL, 1);

		if (ucmd_ctx->tim_out_es)
			_destroy_tim_out_es(ucmd_ctx);

		if (UTIL_IN_SET(ucmd_ctx->state, CMD_STATE_INI, CMD_STATE_STG_WAIT)) {
			ucmd_ctx->stage++;

			if (cmd_reg->stage_names)
				sid_res_log_debug(cmd_res, "%s%s", cmd_stage_msg, cmd_reg->stage_names[ucmd_ctx->stage - 1]);
			else
				sid_res_log_debug(cmd_res, "%s%u", cmd_stage_msg, ucmd_ctx->stage);
		}
	} else if (state == CMD_STATE_STG_WAIT) {
		cmd_reg = _get_cmd_reg(ucmd_ctx);

		if (_is_last_stage(cmd_reg, ucmd_ctx)) {
			sid_res_log_error(cmd_res,
			                  SID_INTERNAL_ERROR
			                  "%s: Requested to wait for next stage while command already in last stage.",
			                  __func__);
			return -1;
		}

		/* FIXME: Make the timeout configurable per each stage. Make defaults a part of struct cmd_reg. */
		if (sid_res_ev_create_time(cmd_res,
		                           &ucmd_ctx->tim_out_es,
		                           CLOCK_MONOTONIC,
		                           SID_RES_POS_REL,
		                           DEFAULT_CMD_TIM_OUT_USEC,
		                           0,
		                           _on_cmd_tim_out_event,
		                           0,
		                           "stg_tim_out",
		                           cmd_res) < 0) {
			sid_res_log_error(cmd_res, "Failed to create timeout event for waiting for next command stage.");
			return -1;
		}
	} else if (state == CMD_STATE_TIM_OUT) {
		if (ucmd_ctx->state != CMD_STATE_STG_WAIT) {
			sid_res_log_error(cmd_res, SID_INTERNAL_ERROR "Timeout while command not in wait state.");
			return -1;
		}

		if (ucmd_ctx->tim_out_es)
			_destroy_tim_out_es(ucmd_ctx);

		(void) sid_res_ev_set_counter(ucmd_ctx->cmd_handler_es, SID_RES_POS_REL, 1);
	}

	sid_res_log_debug(cmd_res, "Command state changed: %s --> %s.", cmd_state_str[ucmd_ctx->state], cmd_state_str[state]);

	ucmd_ctx->prev_state = ucmd_ctx->state;
	ucmd_ctx->state      = state;

	return 0;
}

static int _cmd_exec_version(sid_res_t *cmd_res)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_res_get_data(cmd_res);
	struct sid_buf      *prn_buf  = ucmd_ctx->prn_buf;
	char                *version_data;
	size_t               size;
	fmt_output_t         format = flags_to_format(ucmd_ctx->req_hdr.flags);

	fmt_doc_start(format, prn_buf, 0);
	fmt_fld_uint(format, prn_buf, 1, "SID_IFC_PROTOCOL", SID_IFC_PROTOCOL, false);
	fmt_fld_uint(format, prn_buf, 1, "SID_MAJOR", SID_VERSION_MAJOR, true);
	fmt_fld_uint(format, prn_buf, 1, "SID_MINOR", SID_VERSION_MINOR, true);
	fmt_fld_uint(format, prn_buf, 1, "SID_RELEASE", SID_VERSION_RELEASE, true);
	fmt_doc_end(format, prn_buf, 0);
	fmt_null_byte(prn_buf);

	sid_buf_get_data(prn_buf, (const void **) &version_data, &size);

	return sid_buf_add(ucmd_ctx->res_buf, version_data, size, NULL, NULL);
}

static int _cmd_exec_resources(sid_res_t *cmd_res)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_res_get_data(cmd_res);
	struct sid_buf      *gen_buf  = ucmd_ctx->common->gen_buf;
	struct sid_buf      *prn_buf  = ucmd_ctx->prn_buf;
	fmt_output_t         format;
	const char          *id;
	size_t               buf_pos0, buf_pos1, buf_pos2;
	char                *data;
	size_t               size;
	int                  r = -1;

	// TODO: check return values from all sid_buf_* and error out properly on error

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
		id = sid_res_get_id(cmd_res);

		sid_buf_add(gen_buf,
		            &(struct internal_msg_header) {.cat = MSG_CATEGORY_SYSTEM,
		                                           .header =
		                                                   (struct sid_ifc_msg_header) {
									   .status = 0,
									   .prot   = 0,
									   .cmd    = SYSTEM_CMD_RESOURCES,
									   .flags  = ucmd_ctx->req_hdr.flags,
								   }},
		            INTERNAL_MSG_HEADER_SIZE,
		            NULL,
		            &buf_pos0);
		sid_buf_add(gen_buf, (void *) id, strlen(id) + 1, NULL, NULL);
		sid_buf_get_data_from(gen_buf, buf_pos0, (const void **) &data, &size);

		if ((r = sid_wrk_ctl_chan_send(cmd_res,
		                               MAIN_WORKER_CHANNEL_ID,
		                               &(struct sid_wrk_data_spec) {
						       .data      = data,
						       .data_size = size,
						       .ext.used  = false,
					       })) < 0) {
			sid_res_log_error_errno(cmd_res, r, "Failed to sent request to main process to write its resource tree.");
			r = -1;
		} else
			r = _change_cmd_state(cmd_res, CMD_STATE_EXE_WAIT);

		sid_buf_rewind(gen_buf, buf_pos0, SID_BUF_POS_ABS);
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

	buf_pos0 = sid_buf_count(prn_buf);
	fmt_elm_start(format, prn_buf, 0, false);
	fmt_arr_start(format, prn_buf, 1, "sidresources", false);
	buf_pos1 = sid_buf_count(prn_buf);

	sid_res_tree_write(sid_res_search(cmd_res, SID_RES_SEARCH_TOP, NULL, NULL), format, prn_buf, 2, true);

	fmt_arr_end(format, prn_buf, 1);
	fmt_elm_end(format, prn_buf, 0);
	fmt_null_byte(prn_buf);
	buf_pos2 = sid_buf_count(prn_buf);

	sid_buf_get_data(prn_buf, (const void **) &data, &size);

	sid_buf_add(ucmd_ctx->res_buf, data + buf_pos0, buf_pos1 - buf_pos0, NULL, NULL);
	sid_buf_add(ucmd_ctx->res_buf,
	            ucmd_ctx->resources.main_res_mem + SID_BUF_SIZE_PREFIX_LEN,
	            ucmd_ctx->resources.main_res_mem_size - SID_BUF_SIZE_PREFIX_LEN,
	            NULL,
	            NULL);
	sid_buf_add(ucmd_ctx->res_buf, data + buf_pos1, buf_pos2 - buf_pos1, NULL, NULL);

	r = 0;
out:
	ucmd_ctx->resources.main_res_mem      = NULL;
	ucmd_ctx->resources.main_res_mem_size = 0;
	return r;
}

static const char *_sval_to_dev_ready_str(kv_scalar_t *val)
{
	sid_ucmd_dev_ready_t ready;

	memcpy(&ready, val->data + _svalue_ext_data_offset(val), sizeof(ready));
	return dev_ready_str[ready];
}

static const char *_sval_to_dev_reserved_str(kv_scalar_t *val)
{
	sid_ucmd_dev_reserved_t reserved;

	memcpy(&reserved, val->data + _svalue_ext_data_offset(val), sizeof(reserved));
	return dev_reserved_str[reserved];
}

static int _cmd_exec_devices(sid_res_t *cmd_res)
{
	char                 devid_buf1[UTIL_UUID_STR_SIZE];
	char                 devid_buf2[UTIL_UUID_STR_SIZE];
	struct sid_ucmd_ctx *ucmd_ctx = sid_res_get_data(cmd_res);
	fmt_output_t         format   = flags_to_format(ucmd_ctx->req_hdr.flags);
	struct sid_buf      *prn_buf  = ucmd_ctx->prn_buf;
	kv_vector_t          tmp_vvalue[VVALUE_SINGLE_CNT];
	sid_kvs_iter_t      *iter;
	void                *data;
	size_t               size;
	sid_kvs_val_fl_t     kv_store_value_flags;
	const char          *key, *key_core;
	char                *prev_devid, *devid;
	kv_vector_t         *vvalue;
	bool                 with_comma = false;
	int                  r          = 0;

	prev_devid                      = devid_buf1;
	devid                           = devid_buf2;

	if (!(iter = sid_kvs_iter_create_prefix(ucmd_ctx->common->kvs_res, "::D:")))
		goto out;

	fmt_doc_start(format, prn_buf, 0);
	fmt_arr_start(format, prn_buf, 1, "siddevices", false);

	prev_devid[0] = 0;

	while ((data = sid_kvs_iter_next(iter, &size, &key, &kv_store_value_flags))) {
		if (!_copy_ns_part_from_key(key, devid, sizeof(devid_buf1)))
			continue;

		if (!(key_core = _get_key_part(key, KEY_PART_CORE, NULL)))
			continue;

		if (strcmp(prev_devid, devid)) {
			if (prev_devid[0] != 0)
				fmt_elm_end(format, prn_buf, 2);
			fmt_elm_start(format, prn_buf, 2, with_comma);
			fmt_fld_str(format, prn_buf, 3, "DEVID", devid, false);
		}

		if (!strcmp(key_core, KV_KEY_GEN_GROUP_IN) || !strcmp(key_core, KV_KEY_GEN_GROUP_MEMBERS)) {
			vvalue = _get_vvalue(kv_store_value_flags, data, size, tmp_vvalue, VVALUE_CNT(tmp_vvalue));
			_print_vvalue(vvalue, kv_store_value_flags & SID_KVS_VAL_FL_VECTOR, size, key_core, format, prn_buf, 3);
		} else if (!strcmp(key_core, KV_KEY_DEV_READY)) {
			fmt_fld_str(format, prn_buf, 3, KV_KEY_DEV_READY, _sval_to_dev_ready_str(data), with_comma);
		} else if (!strcmp(key_core, KV_KEY_DEV_RESERVED)) {
			fmt_fld_str(format, prn_buf, 3, KV_KEY_DEV_RESERVED, _sval_to_dev_reserved_str(data), with_comma);
		}

		UTIL_SWAP(devid, prev_devid);
		with_comma = true;
	}

	if (prev_devid[0] != 0)
		fmt_elm_end(format, prn_buf, 2);

	fmt_arr_end(format, prn_buf, 1);
	fmt_doc_end(format, prn_buf, 0);
	fmt_null_byte(prn_buf);

	sid_buf_get_data(prn_buf, (const void **) &data, &size);
	r = sid_buf_add(ucmd_ctx->res_buf, data, size, NULL, NULL);
out:
	if (iter)
		sid_kvs_iter_destroy(iter);

	return r;
}

static int _cmd_exec_dbstats(sid_res_t *cmd_res)
{
	int                  r;
	struct sid_ucmd_ctx *ucmd_ctx = sid_res_get_data(cmd_res);
	struct sid_buf      *prn_buf  = ucmd_ctx->prn_buf;
	struct sid_dbstats   stats;
	char                *stats_data;
	size_t               size;
	fmt_output_t         format = flags_to_format(ucmd_ctx->req_hdr.flags);

	if ((r = _write_kv_store_stats(&stats, ucmd_ctx->common->kvs_res)) == 0) {
		fmt_doc_start(format, prn_buf, 0);

		fmt_fld_uint64(format, prn_buf, 1, "KEYS_SIZE", stats.key_size, false);
		fmt_fld_uint64(format, prn_buf, 1, "VALUES_INTERNAL_SIZE", stats.value_int_size, true);
		fmt_fld_uint64(format, prn_buf, 1, "VALUES_INTERNAL_DATA_SIZE", stats.value_int_data_size, true);
		fmt_fld_uint64(format, prn_buf, 1, "VALUES_EXTERNAL_SIZE", stats.value_ext_size, true);
		fmt_fld_uint64(format, prn_buf, 1, "VALUES_EXTERNAL_DATA_SIZE", stats.value_ext_data_size, true);
		fmt_fld_uint64(format, prn_buf, 1, "METADATA_SIZE", stats.meta_size, true);
		fmt_fld_uint(format, prn_buf, 1, "NR_KEY_VALUE_PAIRS", stats.nr_kv_pairs, true);

		fmt_doc_end(format, prn_buf, 0);
		fmt_null_byte(prn_buf);

		sid_buf_get_data(prn_buf, (const void **) &stats_data, &size);
		r = sid_buf_add(ucmd_ctx->res_buf, stats_data, size, NULL, NULL);
	}
	return r;
}

const void *sid_ucmd_kv_get_disk_part(sid_res_t           *mod_res,
                                      struct sid_ucmd_ctx *ucmd_ctx,
                                      const char          *key_core,
                                      size_t              *value_size,
                                      sid_ucmd_kv_flags_t *flags)
{
	char               devno_buf[16];
	struct kv_key_spec key_spec = {.extra_op = NULL,
	                               .op       = KV_OP_SET,
	                               .dom      = KV_KEY_DOM_USER,
	                               .ns       = SID_KV_NS_DEVICE,
	                               .ns_part  = ID_NULL, /* will be calculated later */
	                               .id_cat   = ID_NULL,
	                               .id       = ID_NULL,
	                               .core     = key_core};

	if (!mod_res || !ucmd_ctx || UTIL_STR_EMPTY(key_core) || (key_core[0] == KV_PREFIX_KEY_SYS_C[0]))
		return NULL;

	if (_part_get_whole_disk(mod_res, ucmd_ctx, devno_buf, sizeof(devno_buf)) < 0)
		return NULL;

	key_spec.ns_part = _canonicalize_kv_key(devno_buf);

	return _cmd_get_key_spec_value(mod_res, ucmd_ctx, _owner_name(mod_res), &key_spec, value_size, flags);
}

static int _dev_alias_to_devid(struct sid_ucmd_ctx *ucmd_ctx,
                               const char          *alias_key,
                               const char          *alias,
                               uint16_t            *gennum,
                               size_t              *count,
                               char                *buf,
                               size_t               buf_size)
{
	const char  *key;
	char        *p;
	kv_vector_t *vvalue;
	size_t       vvalue_size;
	int          r;

	if (!(key = _compose_key(ucmd_ctx->common->gen_buf,
	                         &((struct kv_key_spec) {.extra_op = NULL,
	                                                 .op       = KV_OP_SET,
	                                                 .dom      = KV_KEY_DOM_ALIAS,
	                                                 .ns       = SID_KV_NS_MODULE,
	                                                 .ns_part  = _get_ns_part(ucmd_ctx, _owner_name(NULL), SID_KV_NS_MODULE),
	                                                 .id_cat   = alias_key,
	                                                 .id       = alias,
	                                                 .core     = KV_KEY_GEN_GROUP_MEMBERS})))) {
		r = -ENOMEM;
		goto out;
	}

	if (!(vvalue = sid_kvs_get(ucmd_ctx->common->kvs_res, key, &vvalue_size, NULL))) {
		r = -ENODATA;
		goto out;
	}

	if (gennum)
		*gennum = VVALUE_GENNUM(vvalue);

	vvalue      += VVALUE_HEADER_CNT;
	vvalue_size -= VVALUE_HEADER_CNT;

	if (count)
		*count = vvalue_size;

	for (p = buf; vvalue_size; vvalue_size--, vvalue++) {
		if (!_copy_ns_part_from_key(vvalue->iov_base, p, buf_size)) {
			r = -ENOBUFS;
			goto out;
		}

		p        += vvalue->iov_len;
		buf_size -= vvalue->iov_len;
	}

	r = 0;
out:
	_destroy_key(ucmd_ctx->common->gen_buf, key);
	return r;
}

static int _set_new_dev_kvs(sid_res_t *res, struct sid_ucmd_ctx *ucmd_ctx, bool is_sync)
{
	static const char failed_msg[] = "Failed to set %s for new device %s (%s/%s).";
	const char       *rec_name     = NULL;
	int               r;

	if ((r = _do_sid_ucmd_dev_set_ready(res, ucmd_ctx, _owner_name(NULL), SID_DEV_RDY_UNPROCESSED, is_sync)) < 0) {
		rec_name = "ready state";
		goto out;
	}

	if ((r = _do_sid_ucmd_dev_set_reserved(res, ucmd_ctx, _owner_name(NULL), SID_DEV_RES_UNPROCESSED, is_sync)) < 0) {
		rec_name = "reserved state";
		goto out;
	}

	if ((r = _handle_devs_for_group(res,
	                                ucmd_ctx,
	                                _owner_name(NULL),
	                                NULL,
	                                0,
	                                KV_KEY_DOM_ALIAS,
	                                SID_KV_NS_MODULE,
	                                DEV_ALIAS_DSEQ,
	                                ucmd_ctx->req_env.dev.dsq_s,
	                                KV_OP_PLUS,
	                                is_sync)) < 0) {
		rec_name = "device sequence number";
		goto out;
	}

	if ((r = _handle_devs_for_group(res,
	                                ucmd_ctx,
	                                _owner_name(NULL),
	                                NULL,
	                                0,
	                                KV_KEY_DOM_ALIAS,
	                                SID_KV_NS_MODULE,
	                                DEV_ALIAS_DEVNO,
	                                ucmd_ctx->req_env.dev.num_s,
	                                KV_OP_PLUS,
	                                is_sync)) < 0) {
		rec_name = "device number";
		goto out;
	}

	if ((r = _handle_devs_for_group(res,
	                                ucmd_ctx,
	                                _owner_name(NULL),
	                                NULL,
	                                0,
	                                KV_KEY_DOM_ALIAS,
	                                SID_KV_NS_MODULE,
	                                DEV_ALIAS_NAME,
	                                ucmd_ctx->req_env.dev.udev.name,
	                                KV_OP_PLUS,
	                                is_sync)) < 0) {
		rec_name = "device name";
		goto out;
	}
out:
	if (r < 0)
		sid_res_log_error_errno(res,
		                        r,
		                        failed_msg,
		                        rec_name,
		                        ucmd_ctx->req_env.dev.udev.name,
		                        ucmd_ctx->req_env.dev.num_s,
		                        ucmd_ctx->req_env.dev.dsq_s);
	return r;
}

/*
 * Returns devid for already recorded device or disk sequence number (diskseq) otherwise.
 */
static const char *
	_get_dep_dev_dseq(sid_res_t *res, struct sid_ucmd_ctx *ucmd_ctx, const char *dep_name, char *buf, size_t buf_size)
{
	static const char err_msg[] = "%s for %s while processing " CMD_DEV_PRINT_FMT;
	char             *dep_path  = NULL;
	const char       *msg, *s = NULL;
	int               r = 0, ret = -1;

	if (dep_name) {
		/* handling a whole device: dep device is under the SYSTEM_SYSFS_SLAVES directory */
		if (asprintf(&dep_path,
		             "%s%s/%s/%s",
		             SYSTEM_SYSFS_PATH,
		             ucmd_ctx->req_env.dev.udev.path,
		             SYSTEM_SYSFS_SLAVES,
		             dep_name) < 0) {
			msg = "Failed to compose underlying device's sysfs path";
			goto out;
		}

	} else {
		/* handling a partition device: dep device == whole device */
		if (asprintf(&dep_path, "%s%s", SYSTEM_SYSFS_PATH, ucmd_ctx->req_env.dev.udev.path) < 0) {
			msg = "Failed to compose partition sysfs path";
			goto out;
		}

		/* we also set the actual dep path here by using the dirname which cuts off the partition suffix */
		dep_name = basename(dirname(dep_path));
	}

	if ((r = sid_buf_add_fmt(ucmd_ctx->common->gen_buf, (const void **) &s, NULL, "%s/diskseq", dep_path)) < 0) {
		msg = "Failed to compose underlying device's sysfs 'dev' attribute path";
		goto out;
	}

	if ((r = sid_util_sysfs_get(s, buf, buf_size, NULL)) < 0) {
		msg = "Failed to read underlying device's 'dseq' sysfs attribute";
		goto out;
	}

	ret = 0;
out:
	if (s)
		sid_buf_rewind_mem(ucmd_ctx->common->gen_buf, s);
	free(dep_path);

	if (ret < 0) {
		if (r < 0)
			sid_res_log_error_errno(res, r, err_msg, msg, dep_name, CMD_DEV_PRINT(ucmd_ctx));
		else
			sid_res_log_error(res, err_msg, msg, dep_name, CMD_DEV_PRINT(ucmd_ctx));

		return NULL;
	}

	return buf;
}

static const char _key_prefix_err_msg[] =
	"Failed to compose key prefix to update device dependency records for " CMD_DEV_PRINT_FMT ".";

static int _update_disk_deps_from_sysfs(sid_res_t *cmd_res)
{
	/*
	 * FIXME: Fail completely here, discarding any changes made to DB so far if any of the steps below fail?
	 */
	struct sid_ucmd_ctx *ucmd_ctx = sid_res_get_data(cmd_res);
	char                *s;
	struct dirent      **dirent  = NULL;
	struct sid_buf      *vec_buf = NULL;
	kv_vector_t         *vvalue;
	size_t               vsize = 0;
	int                  count = 0, i = 0;
	char                 buf[UTIL_UUID_STR_SIZE];
	const char          *dep_dseq;
	int                  r      = -1;

	struct kv_rel_spec rel_spec = {
		.delta        = &((struct kv_delta) {.op = KV_OP_SET, .flags = DELTA_WITH_DIFF | DELTA_WITH_REL}),

		.abs_delta    = &((struct kv_delta) {0}),

		.cur_key_spec = &((struct kv_key_spec) {.extra_op = NULL,
	                                                .op       = KV_OP_SET,
	                                                .dom      = ID_NULL,
	                                                .ns       = SID_KV_NS_DEVICE,
	                                                .ns_part  = _get_ns_part(ucmd_ctx, _owner_name(NULL), SID_KV_NS_DEVICE),
	                                                .id_cat   = ID_NULL,
	                                                .id       = ID_NULL,
	                                                .core     = KV_KEY_GEN_GROUP_MEMBERS}),
		.rel_key_spec = &((struct kv_key_spec) {.extra_op = NULL,
	                                                .op       = KV_OP_SET,
	                                                .dom      = KV_KEY_DOM_ALIAS,
	                                                .ns       = SID_KV_NS_MODULE,
	                                                .ns_part  = _get_ns_part(ucmd_ctx, _owner_name(NULL), SID_KV_NS_MODULE),
	                                                .id_cat   = DEV_ALIAS_DSEQ,
	                                                .id       = ID_NULL, /* will be calculated later */
	                                                .core     = KV_KEY_GEN_GROUP_IN})};

	struct kv_update_arg update_arg = {.res     = ucmd_ctx->common->kvs_res,
	                                   .gen_buf = ucmd_ctx->common->gen_buf,
	                                   .is_sync = false,
	                                   .custom  = &rel_spec};

	if (ucmd_ctx->req_env.dev.udev.action != UDEV_ACTION_REMOVE) {
		if ((r = sid_buf_add_fmt(ucmd_ctx->common->gen_buf,
		                         (const void **) &s,
		                         NULL,
		                         "%s%s/%s",
		                         SYSTEM_SYSFS_PATH,
		                         ucmd_ctx->req_env.dev.udev.path,
		                         SYSTEM_SYSFS_SLAVES)) < 0) {
			sid_res_log_error_errno(cmd_res,
			                        r,
			                        "Failed to compose sysfs %s path for device " CMD_DEV_PRINT_FMT,
			                        SYSTEM_SYSFS_SLAVES,
			                        CMD_DEV_PRINT(ucmd_ctx));
			goto out;
		}

		count = scandir(s, &dirent, NULL, NULL);
		sid_buf_rewind_mem(ucmd_ctx->common->gen_buf, s);

		if (count < 0) {
			/*
			 * FIXME: Add code to deal with/warn about: (errno == ENOENT) && (ucmd_ctx->req_env.dev.udev.action !=
			 * UDEV_ACTION_REMOVE). That means we don't have REMOVE uevent, but at the same time, we don't have sysfs
			 * content, e.g. because we're processing this uevent too late: the device has already been removed right
			 * after this uevent was triggered. For now, error out even in this case.
			 */
			sid_res_log_sys_error(cmd_res, "scandir", s);
			goto out;
		}
	}

	/*
	 * Create vec_buf used to set up database records.
	 * The size of the vec_buf is:
	 *   +VVALUE_HEADER_CNT to include record header
	 *   -2 to subtract "." and ".." directory which we're not interested in
	 */
	if (!(vec_buf = sid_buf_create(&SID_BUF_SPEC(.type = SID_BUF_TYPE_VECTOR),
	                               &SID_BUF_INIT(.size = VVALUE_HEADER_CNT + (count >= 2 ? count - 2 : 0), .alloc_step = 1),
	                               &r))) {
		sid_res_log_error_errno(cmd_res,
		                        r,
		                        "Failed to create buffer to record device dependencies from sysfs for " CMD_DEV_PRINT_FMT,
		                        CMD_DEV_PRINT(ucmd_ctx));
		goto out;
	}

	vsize = VVALUE_HEADER_CNT;
	if (sid_buf_add(vec_buf, NULL, vsize, (const void **) &vvalue, NULL) < 0)
		goto out;

	_vvalue_header_prep(vvalue,
	                    vsize,
	                    &ucmd_ctx->req_env.dev.udev.seqnum,
	                    &value_flags_no_sync,
	                    &ucmd_ctx->common->gennum,
	                    core_owner);
	sid_buf_unbind_mem(vec_buf, vvalue);

	/* Read relatives from sysfs into vec_buf. */
	if (ucmd_ctx->req_env.dev.udev.action != UDEV_ACTION_REMOVE) {
		for (i = 0; i < count; i++) {
			if (dirent[i]->d_name[0] == '.')
				goto next;

			if (!(dep_dseq = _get_dep_dev_dseq(cmd_res, ucmd_ctx, dirent[i]->d_name, buf, sizeof(buf))))
				goto next;

			rel_spec.rel_key_spec->id = dep_dseq;

			s                         = _compose_key_prefix(NULL, rel_spec.rel_key_spec);
			if (!s || ((r = sid_buf_add(vec_buf, (void *) s, strlen(s) + 1, NULL, NULL)) < 0)) {
				_destroy_key(NULL, s);
				goto out;
			}
next:
			free(dirent[i]);
		}

		free(dirent);
		dirent                    = NULL;
		rel_spec.rel_key_spec->id = ID_NULL;
	}

	/* Get the actual vector with relatives and sort it. */
	sid_buf_get_data(vec_buf, (const void **) (&vvalue), &vsize);
	qsort(vvalue + VVALUE_HEADER_CNT, vsize - VVALUE_HEADER_CNT, sizeof(kv_vector_t), _vvalue_str_cmp);

	if (!(s = _compose_key(NULL, rel_spec.cur_key_spec))) {
		sid_res_log_error(cmd_res,
		                  _key_prefix_err_msg,
		                  ucmd_ctx->req_env.dev.udev.name,
		                  ucmd_ctx->req_env.dev.udev.major,
		                  ucmd_ctx->req_env.dev.udev.minor);
		goto out;
	}

	_kv_delta_set(s, vvalue, vsize, &update_arg);

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
			sid_buf_get_data(vec_buf, (const void **) (&vvalue), &vsize);

		for (i = VVALUE_HEADER_CNT; i < vsize; i++)
			_destroy_key(NULL, vvalue[i].iov_base);

		sid_buf_destroy(vec_buf);
	}
	return r;
}

static int _update_part_deps_from_sysfs(sid_res_t *cmd_res)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_res_get_data(cmd_res);
	kv_vector_t          vvalue[VVALUE_SINGLE_CNT];
	char                 buf[UTIL_UUID_STR_SIZE];
	const char          *dep_dseq;
	const char          *s   = NULL;
	char                *key = NULL;
	int                  r   = -1;
	size_t               count;

	struct kv_rel_spec rel_spec = {
		.delta        = &((struct kv_delta) {.op = KV_OP_SET, .flags = DELTA_WITH_DIFF | DELTA_WITH_REL}),

		.abs_delta    = &((struct kv_delta) {0}),

		.cur_key_spec = &((struct kv_key_spec) {.extra_op = NULL,
	                                                .op       = KV_OP_SET,
	                                                .dom      = ID_NULL,
	                                                .ns       = SID_KV_NS_DEVICE,
	                                                .ns_part  = _get_ns_part(ucmd_ctx, _owner_name(NULL), SID_KV_NS_DEVICE),
	                                                .id_cat   = ID_NULL,
	                                                .id       = ID_NULL,
	                                                .core     = KV_KEY_GEN_GROUP_MEMBERS}),
		.rel_key_spec = &((struct kv_key_spec) {.extra_op = NULL,
	                                                .op       = KV_OP_SET,
	                                                .dom      = KV_KEY_DOM_ALIAS,
	                                                .ns       = SID_KV_NS_MODULE,
	                                                .ns_part  = _get_ns_part(ucmd_ctx, _owner_name(NULL), SID_KV_NS_MODULE),
	                                                .id_cat   = DEV_ALIAS_DSEQ,
	                                                .id       = ID_NULL, /* will be calculated later */
	                                                .core     = KV_KEY_GEN_GROUP_IN})};

	struct kv_update_arg update_arg = {.res     = ucmd_ctx->common->kvs_res,
	                                   .gen_buf = ucmd_ctx->common->gen_buf,
	                                   .is_sync = false,
	                                   .custom  = &rel_spec};

	count = (ucmd_ctx->req_env.dev.udev.action == UDEV_ACTION_REMOVE) ? VVALUE_HEADER_CNT : VVALUE_SINGLE_CNT;
	_vvalue_header_prep(vvalue,
	                    count,
	                    &ucmd_ctx->req_env.dev.udev.seqnum,
	                    &value_flags_no_sync,
	                    &ucmd_ctx->common->gennum,
	                    core_owner);

	if (ucmd_ctx->req_env.dev.udev.action != UDEV_ACTION_REMOVE) {
		if (!(dep_dseq = _get_dep_dev_dseq(cmd_res, ucmd_ctx, NULL, buf, sizeof(buf))))
			goto out;

		rel_spec.rel_key_spec->id = dep_dseq;

		if (!(s = _compose_key_prefix(NULL, rel_spec.rel_key_spec)))
			goto out;

		_vvalue_data_prep(vvalue, VVALUE_CNT(vvalue), 0, (void *) s, strlen(s) + 1);
		rel_spec.rel_key_spec->id = ID_NULL;
	}

	if (!(key = _compose_key(NULL, rel_spec.cur_key_spec))) {
		sid_res_log_error(cmd_res,
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
	_kv_delta_set(key, vvalue, count, &update_arg);

	r = 0;
out:
	_destroy_key(NULL, key);
	_destroy_key(NULL, s);
	return r;
}

static int _update_dev_deps_from_sysfs(sid_res_t *cmd_res)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_res_get_data(cmd_res);

	switch (ucmd_ctx->req_env.dev.udev.type) {
		case UDEV_DEVTYPE_DISK:
			if ((_update_disk_deps_from_sysfs(cmd_res) < 0))
				return -1;
			break;
		case UDEV_DEVTYPE_PARTITION:
			if ((_update_part_deps_from_sysfs(cmd_res) < 0))
				return -1;
			break;
		case UDEV_DEVTYPE_UNKNOWN:
			break;
	}

	return 0;
}

static int _exec_block_mods(sid_res_t *cmd_res, bool reverse)
{
	struct sid_ucmd_ctx       *ucmd_ctx = sid_res_get_data(cmd_res);
	sid_res_t                 *block_mod_res;
	const struct scan_mod_fns *block_mod_fns;
	sid_ucmd_fn_t             *block_mod_fn;

	sid_res_iter_reset(ucmd_ctx->scan.block_mod_iter);

	while (true) {
		if (!(block_mod_res = reverse ? sid_res_iter_previous(ucmd_ctx->scan.block_mod_iter)
		                              : sid_res_iter_next(ucmd_ctx->scan.block_mod_iter)))
			break;

		if (sid_mod_reg_get_mod_syms(block_mod_res, (const void ***) &block_mod_fns) < 0) {
			sid_res_log_error(cmd_res, "Failed to retrieve module symbols from module %s.", ID(block_mod_res));
			return -1;
		}

		if ((block_mod_fn = *(((sid_ucmd_fn_t **) block_mod_fns) + ucmd_ctx->scan.phase))) {
			if (block_mod_fn(block_mod_res, ucmd_ctx) < 0)
				return -1;
		}
	}

	return 0;
}

static int _exec_type_mod(sid_res_t *cmd_res, sid_res_t *type_mod_res)
{
	struct sid_ucmd_ctx       *ucmd_ctx = sid_res_get_data(cmd_res);
	const struct scan_mod_fns *type_mod_fns;
	sid_ucmd_fn_t             *type_mod_fn;

	if (!type_mod_res)
		return 0;

	if (sid_mod_reg_get_mod_syms(type_mod_res, (const void ***) &type_mod_fns) < 0) {
		sid_res_log_error(cmd_res, "Failed to retrieve module symbols from module %s.", ID(type_mod_res));
		return -1;
	}

	if ((type_mod_fn = *(((sid_ucmd_fn_t **) type_mod_fns) + ucmd_ctx->scan.phase))) {
		if (type_mod_fn(type_mod_res, ucmd_ctx) < 0)
			return -1;
	}

	return 0;
}

static bool _dev_matches_udev(sid_res_t *cmd_res, const char *devid)
{
	// TODO: implement this
	return true;
}

static int _set_dev_kvs(sid_res_t *cmd_res)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_res_get_data(cmd_res);
	char                 buf[UTIL_UUID_STR_SIZE];
	util_mem_t           mem = {.base = buf, .size = sizeof(buf)};
	const char          *devid, *devid_udev, *devid_to_use, *devid_msg;
	size_t               count;
	int                  r;

	devid_udev = _do_sid_ucmd_get_kv(cmd_res,
	                                 ucmd_ctx,
	                                 _owner_name(NULL),
	                                 NULL,
	                                 SID_KV_NS_UDEV,
	                                 KV_KEY_UDEV_SID_DEV_ID,
	                                 NULL,
	                                 NULL,
	                                 0);

	// TODO: check we have only a single devid returned and that the generation is correct
	r          = _dev_alias_to_devid(ucmd_ctx, DEV_ALIAS_DEVNO, ucmd_ctx->req_env.dev.num_s, NULL, &count, buf, sizeof(buf));

	if (r == 0)
		devid = buf;
	else if (r == -ENODATA)
		devid = NULL;
	else {
		sid_res_log_error_errno(cmd_res, r, "Failed to lookup device ID for " CMD_DEV_PRINT_FMT, CMD_DEV_PRINT(ucmd_ctx));
		return -1;
	}

	if (!devid && devid_udev) {
		devid_to_use = devid_udev;
		devid_msg    = " (pulling ID from udev)";
	} else if (devid && !devid_udev) {
		devid_to_use = devid;
		devid_msg    = " (pushing ID to udev)";
	} else if (!devid && !devid_udev) {
		if (!util_uuid_gen_str(&mem)) {
			sid_res_log_error(cmd_res,
			                  "Failed to generate new device ID for " CMD_DEV_PRINT_FMT ".",
			                  CMD_DEV_PRINT(ucmd_ctx));
			return -1;
		}

		devid_to_use = mem.base;
		devid_msg    = " (ID newly generated)";
	} else {
		devid_to_use = devid;
		devid_msg    = "";
	}

	if (!(ucmd_ctx->req_env.dev.uid_s = strdup(devid_to_use)))
		return -1;

	sid_res_log_debug(cmd_res,
	                  "Using device ID %s for " CMD_DEV_PRINT_FMT "%s",
	                  devid_to_use,
	                  CMD_DEV_PRINT(ucmd_ctx),
	                  devid_msg);

	if (!devid) {
		if (_set_new_dev_kvs(cmd_res, ucmd_ctx, false) < 0)
			return -1;
	} else {
		if (!_dev_matches_udev(cmd_res, devid)) {
			// TODO: handle scenario where udev db and sid kvs is out of sync
		}
	}

	if (!devid_udev) {
		if (!_do_sid_ucmd_set_kv(cmd_res,
		                         ucmd_ctx,
		                         _owner_name(NULL),
		                         NULL,
		                         SID_KV_NS_UDEV,
		                         KV_KEY_UDEV_SID_DEV_ID,
		                         SID_KV_FL_SYNC,
		                         ucmd_ctx->req_env.dev.uid_s,
		                         strlen(ucmd_ctx->req_env.dev.uid_s) + 1)) {
			sid_res_log_error(cmd_res, "Failed to set %s udev variable.", KV_KEY_UDEV_SID_DEV_ID);
			return -1;
		}
	}

	if (!_do_sid_ucmd_set_kv(cmd_res,
	                         ucmd_ctx,
	                         _owner_name(NULL),
	                         NULL,
	                         SID_KV_NS_UDEV,
	                         KV_KEY_UDEV_SID_TAGS,
	                         SID_KV_FL_SYNC,
	                         UDEV_TAG_SID,
	                         sizeof(UDEV_TAG_SID) + 1)) {
		sid_res_log_error(cmd_res, "Failed to set %s udev variable.", KV_KEY_UDEV_SID_TAGS);
		return -1;
	}

	return 0;
}

static const char *_get_base_mod_name(sid_res_t *cmd_res, char *buf, size_t buf_size)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_res_get_data(cmd_res);
	const char          *mod_name;

	if (!(mod_name = _do_sid_ucmd_get_kv(cmd_res,
	                                     ucmd_ctx,
	                                     _owner_name(NULL),
	                                     NULL,
	                                     SID_KV_NS_DEVICE,
	                                     KV_KEY_DEV_MOD,
	                                     NULL,
	                                     NULL,
	                                     0))) {
		if (!(mod_name = _lookup_mod_name(cmd_res,
		                                  ucmd_ctx->req_env.dev.udev.major,
		                                  ucmd_ctx->req_env.dev.udev.name,
		                                  buf,
		                                  buf_size))) {
			sid_res_log_error(cmd_res, "Module name lookup failed.");
			return NULL;
		}

		if (!_do_sid_ucmd_set_kv(cmd_res,
		                         ucmd_ctx,
		                         _owner_name(NULL),
		                         NULL,
		                         SID_KV_NS_DEVICE,
		                         KV_KEY_DEV_MOD,
		                         DEFAULT_VALUE_FLAGS_CORE,
		                         mod_name,
		                         strlen(mod_name) + 1)) {
			sid_res_log_error(cmd_res,
			                  "Failed to store device " CMD_DEV_PRINT_FMT " module name",
			                  CMD_DEV_PRINT(ucmd_ctx));
			return NULL;
		}
	}

	return mod_name;
}

static int _common_scan_init(sid_res_t *cmd_res)
{
	char                 buf[80];
	struct sid_ucmd_ctx *ucmd_ctx = sid_res_get_data(cmd_res);
	const char          *mod_name;

	if (!(ucmd_ctx->scan.block_mod_iter = sid_res_iter_create(ucmd_ctx->common->block_mod_reg_res))) {
		sid_res_log_error(cmd_res, "Failed to create block module iterator.");
		goto fail;
	}

	if (_set_dev_kvs(cmd_res) < 0)
		goto fail;

	if (!(mod_name = _get_base_mod_name(cmd_res, buf, sizeof(buf))))
		goto fail;

	if (ucmd_ctx->req_env.dev.udev.action != UDEV_ACTION_REMOVE) {
		if (_update_dev_deps_from_sysfs(cmd_res) < 0)
			goto fail;
	}

	_exec_block_mods(cmd_res, false);

	if (!(ucmd_ctx->scan.type_mod_res_current = sid_mod_reg_get_mod(ucmd_ctx->common->type_mod_reg_res, mod_name)))
		sid_res_log_debug(cmd_res, "Module %s not loaded.", mod_name);

	return _exec_type_mod(cmd_res, ucmd_ctx->scan.type_mod_res_current);
fail:
	if (ucmd_ctx->scan.block_mod_iter) {
		sid_res_iter_destroy(ucmd_ctx->scan.block_mod_iter);
		ucmd_ctx->scan.block_mod_iter = NULL;
	}

	return -1;
}

static int _cmd_exec_scan_a_init(sid_res_t *cmd_res)
{
	return _common_scan_init(cmd_res);
}

static int _cmd_exec_scan_a_pre(sid_res_t *cmd_res)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_res_get_data(cmd_res);

	_exec_block_mods(cmd_res, false);
	return _exec_type_mod(cmd_res, ucmd_ctx->scan.type_mod_res_current);
}

static int _cmd_exec_scan_a_current(sid_res_t *cmd_res)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_res_get_data(cmd_res);
	sid_ucmd_dev_ready_t ready    = _do_sid_ucmd_dev_get_ready(cmd_res, sid_res_get_data(cmd_res), _owner_name(NULL), 0);

	if (ready == SID_DEV_RDY_UNPROCESSED && !ucmd_ctx->scan.type_mod_res_current) {
		/*
		 * If there is no specific module to process this device type
		 * and the 'ready' state is still 'unprocessed', then assume
		 * device is SID_DEV_RDY_PUBLIC by default.
		 */
		if (_do_sid_ucmd_dev_set_ready(cmd_res, ucmd_ctx, _owner_name(NULL), SID_DEV_RDY_PUBLIC, 0) < 0)
			return -1;
		ready = SID_DEV_RDY_PUBLIC;
	}

	if (!UTIL_IN_SET(ready, SID_DEV_RDY_PRIVATE, SID_DEV_RDY_FLAT, SID_DEV_RDY_PUBLIC))
		return 1;

	_exec_block_mods(cmd_res, false);
	return _exec_type_mod(cmd_res, ucmd_ctx->scan.type_mod_res_current);
}

static int _cmd_exec_scan_a_next(sid_res_t *cmd_res)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_res_get_data(cmd_res);
	sid_ucmd_dev_ready_t ready;
	const char          *next_mod_name;

	ready = _do_sid_ucmd_dev_get_ready(cmd_res, ucmd_ctx, _owner_name(NULL), 0);

	if (!UTIL_IN_SET(ready, SID_DEV_RDY_PUBLIC))
		return 1;

	_exec_block_mods(cmd_res, false);

	if ((next_mod_name = _do_sid_ucmd_get_kv(cmd_res,
	                                         ucmd_ctx,
	                                         _owner_name(NULL),
	                                         KV_KEY_DOM_USER,
	                                         SID_KV_NS_DEVICE,
	                                         SID_UCMD_KEY_DEVICE_NEXT_MOD,
	                                         NULL,
	                                         NULL,
	                                         0))) {
		if (!(ucmd_ctx->scan.type_mod_res_next = sid_mod_reg_get_mod(ucmd_ctx->common->type_mod_reg_res, next_mod_name)))
			sid_res_log_debug(cmd_res, "Module %s not loaded.", next_mod_name);
	} else
		ucmd_ctx->scan.type_mod_res_next = NULL;

	return _exec_type_mod(cmd_res, ucmd_ctx->scan.type_mod_res_next);
}

static int _cmd_exec_scan_a_post_current(sid_res_t *cmd_res)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_res_get_data(cmd_res);
	sid_ucmd_dev_ready_t ready    = _do_sid_ucmd_dev_get_ready(cmd_res, ucmd_ctx, _owner_name(NULL), 0);

	if (!UTIL_IN_SET(ready, SID_DEV_RDY_PRIVATE, SID_DEV_RDY_FLAT, SID_DEV_RDY_PUBLIC))
		return 1;

	_exec_block_mods(cmd_res, false);
	return _exec_type_mod(cmd_res, ucmd_ctx->scan.type_mod_res_current);
}

static int _cmd_exec_scan_a_post_next(sid_res_t *cmd_res)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_res_get_data(cmd_res);
	sid_ucmd_dev_ready_t ready    = _do_sid_ucmd_dev_get_ready(cmd_res, ucmd_ctx, _owner_name(NULL), 0);

	if (!UTIL_IN_SET(ready, SID_DEV_RDY_PUBLIC))
		return 1;

	_exec_block_mods(cmd_res, false);
	return _exec_type_mod(cmd_res, ucmd_ctx->scan.type_mod_res_next);
}

static int _cmd_exec_scan_a_exit(sid_res_t *cmd_res)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_res_get_data(cmd_res);
	int                  r;

	r = _exec_type_mod(cmd_res, ucmd_ctx->scan.type_mod_res_current);
	(void) _exec_block_mods(cmd_res, true);

	if (_do_sid_ucmd_dev_get_ready(cmd_res, ucmd_ctx, _owner_name(NULL), 0) == SID_DEV_RDY_UNPROCESSED)
		if (_do_sid_ucmd_dev_set_ready(cmd_res, ucmd_ctx, _owner_name(NULL), SID_DEV_RDY_PUBLIC, false) < 0)
			r = -1;

	if (_do_sid_ucmd_dev_get_reserved(cmd_res, ucmd_ctx, _owner_name(NULL), 0) == SID_DEV_RES_UNPROCESSED)
		if (_do_sid_ucmd_dev_set_reserved(cmd_res, ucmd_ctx, _owner_name(NULL), SID_DEV_RES_FREE, false) < 0)
			r = -1;

	return r;
}

static int _cmd_exec_scan_remove_init(sid_res_t *cmd_res)
{
	return _common_scan_init(cmd_res);
}

static int _cmd_exec_scan_remove_current(sid_res_t *cmd_res)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_res_get_data(cmd_res);

	_exec_block_mods(cmd_res, false);
	if (_exec_type_mod(cmd_res, ucmd_ctx->scan.type_mod_res_current) < 0)
		return -1;

	return _update_dev_deps_from_sysfs(cmd_res);
}

static int _cmd_exec_scan_remove_exit(sid_res_t *cmd_res)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_res_get_data(cmd_res);
	int                  r;

	r = _exec_type_mod(cmd_res, ucmd_ctx->scan.type_mod_res_current);
	(void) _exec_block_mods(cmd_res, true);

	return r;
}

static int _cmd_exec_scan_b_init(sid_res_t *cmd_res)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_res_get_data(cmd_res);

	_exec_block_mods(cmd_res, false);
	return _exec_type_mod(cmd_res, ucmd_ctx->scan.type_mod_res_current);
}

static int _cmd_exec_scan_b_action_current(sid_res_t *cmd_res)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_res_get_data(cmd_res);

	_exec_block_mods(cmd_res, false);
	return _exec_type_mod(cmd_res, ucmd_ctx->scan.type_mod_res_current);
}

static int _cmd_exec_scan_b_action_next(sid_res_t *cmd_res)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_res_get_data(cmd_res);

	_exec_block_mods(cmd_res, false);
	return _exec_type_mod(cmd_res, ucmd_ctx->scan.type_mod_res_next);
}

static int _cmd_exec_scan_b_exit(sid_res_t *cmd_res)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_res_get_data(cmd_res);
	int                  r;

	r = _exec_type_mod(cmd_res, ucmd_ctx->scan.type_mod_res_current);
	_exec_block_mods(cmd_res, true);

	if (ucmd_ctx->scan.block_mod_iter) {
		sid_res_iter_destroy(ucmd_ctx->scan.block_mod_iter);
		ucmd_ctx->scan.block_mod_iter = NULL;
	}

	return r;
}

static int _cmd_exec_scan_error(sid_res_t *cmd_res)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_res_get_data(cmd_res);
	int                  r        = 0;

	_exec_block_mods(cmd_res, false);

	r |= _exec_type_mod(cmd_res, ucmd_ctx->scan.type_mod_res_current);
	r |= _exec_type_mod(cmd_res, ucmd_ctx->scan.type_mod_res_next);

	return r;
}

static struct cmd_reg _cmd_scan_phase_regs[] = {
	[CMD_SCAN_PHASE_A_INIT]         = {.name = "scan-a-init", .flags = CMD_SCAN_CAP_ALL, .exec = _cmd_exec_scan_a_init},

	[CMD_SCAN_PHASE_A_SCAN_PRE]     = {.name = "scan-a-pre", .flags = CMD_SCAN_CAP_RDY, .exec = _cmd_exec_scan_a_pre},

	[CMD_SCAN_PHASE_A_SCAN_CURRENT] = {.name = "scan-a-current", .flags = CMD_SCAN_CAP_RDY, .exec = _cmd_exec_scan_a_current},

	[CMD_SCAN_PHASE_A_SCAN_NEXT]    = {.name = "scan-a-next", .flags = CMD_SCAN_CAP_RES, .exec = _cmd_exec_scan_a_next},

	[CMD_SCAN_PHASE_A_SCAN_POST_CURRENT] = {.name = "scan-a-post-current", .flags = 0, .exec = _cmd_exec_scan_a_post_current},

	[CMD_SCAN_PHASE_A_SCAN_POST_NEXT]    = {.name = "scan-a-post-next", .flags = 0, .exec = _cmd_exec_scan_a_post_next},

	[CMD_SCAN_PHASE_A_EXIT]              = {.name = "scan-a-exit", .flags = CMD_SCAN_CAP_ALL, .exec = _cmd_exec_scan_a_exit},

	[CMD_SCAN_PHASE_REMOVE_INIT]         = {.name  = "remove-init",
                                                .flags = CMD_SCAN_CAP_RDY | CMD_SCAN_CAP_RES,
                                                .exec  = _cmd_exec_scan_remove_init},

	[CMD_SCAN_PHASE_REMOVE_CURRENT]      = {.name = "remove-current", .flags = 0, .exec = _cmd_exec_scan_remove_current},

	[CMD_SCAN_PHASE_REMOVE_EXIT]         = {.name = "remove-exit", .flags = 0, .exec = _cmd_exec_scan_remove_exit},

	[CMD_SCAN_PHASE_B_INIT]              = {.name = "scan-b-init", .flags = CMD_SCAN_CAP_ALL, .exec = _cmd_exec_scan_b_init},

	[CMD_SCAN_PHASE_B_ACTION_CURRENT] = {.name = "scan-b-action-current", .flags = 0, .exec = _cmd_exec_scan_b_action_current},

	[CMD_SCAN_PHASE_B_ACTION_NEXT]    = {.name = "scan-b-action-next", .flags = 0, .exec = _cmd_exec_scan_b_action_next},

	[CMD_SCAN_PHASE_B_EXIT]           = {.name = "scan-b-exit", .flags = 0, .exec = _cmd_exec_scan_b_exit},

	[CMD_SCAN_PHASE_ERROR]            = {.name = "scan-error", .flags = 0, .exec = _cmd_exec_scan_error},
};

static int _cmd_exec_scan(sid_res_t *cmd_res)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_res_get_data(cmd_res);
	cmd_scan_phase_t     phase, phase_start, phase_end;
	const char          *phase_name;

	switch (ucmd_ctx->stage) {
		case 1:
			if (ucmd_ctx->req_env.dev.udev.action == UDEV_ACTION_REMOVE) {
				phase_start = CMD_SCAN_PHASE_REMOVE_INIT;
				phase_end   = CMD_SCAN_PHASE_REMOVE_EXIT;
			} else {
				phase_start = CMD_SCAN_PHASE_A_INIT;
				phase_end   = CMD_SCAN_PHASE_A_EXIT;
			}
			break;
		case 2:
			phase_start = CMD_SCAN_PHASE_B_INIT;
			phase_end   = CMD_SCAN_PHASE_B_EXIT;
			break;
		default:
			sid_res_log_error(cmd_res, SID_INTERNAL_ERROR "%s: Incorrect stage %u.", __func__, ucmd_ctx->stage);
			return -1;
	}

	for (phase = phase_start; phase <= phase_end; phase++) {
		sid_res_log_debug(cmd_res, "About to execute %s phase.", _cmd_scan_phase_regs[phase].name);
		ucmd_ctx->scan.phase = phase;
		phase_name           = _cmd_scan_phase_regs[phase].name;

		switch (_cmd_scan_phase_regs[phase].exec(cmd_res)) {
			case 0:
				/* No error, continue with subsequent phases */
				sid_res_log_debug(cmd_res, "Finished executing %s phase.", phase_name);
				continue;
			case 1:
				/* Skipped, continue with subsequent phases */
				sid_res_log_debug(cmd_res, "Phase %s skipped, unsuitable ready state.", phase_name);
				continue;
			default:
				/* Error, handle it... */
				break;
		}

		/* Handle error case. */

		/* if init or exit phase has failed, there's nothing else we can do - return. */
		if (UTIL_IN_SET(phase,
		                CMD_SCAN_PHASE_A_INIT,
		                CMD_SCAN_PHASE_B_INIT,
		                CMD_SCAN_PHASE_REMOVE_INIT,
		                CMD_SCAN_PHASE_A_EXIT,
		                CMD_SCAN_PHASE_B_EXIT,
		                CMD_SCAN_PHASE_REMOVE_EXIT)) {
			sid_res_log_error(cmd_res, "%s phase failed.", phase_name);
			return -1;
		}

		/* Otherwise, call out modules to handle the error case. */
		sid_res_log_error(cmd_res,
		                  "%s phase failed. Switching to %s phase.",
		                  phase_name,
		                  _cmd_scan_phase_regs[CMD_SCAN_PHASE_ERROR].name);

		ucmd_ctx->scan.phase = phase = CMD_SCAN_PHASE_ERROR;
		if (_cmd_scan_phase_regs[phase].exec(cmd_res) < 0)
			sid_res_log_error(cmd_res, "%s phase failed.", phase_name);

		/* Also, exit/cleanup after the error phase. */
		switch (ucmd_ctx->stage) {
			case 1:
				if (ucmd_ctx->req_env.dev.udev.action == UDEV_ACTION_REMOVE)
					ucmd_ctx->scan.phase = phase = CMD_SCAN_PHASE_REMOVE_EXIT;
				else
					ucmd_ctx->scan.phase = phase = CMD_SCAN_PHASE_A_EXIT;
				break;
			case 2:
				ucmd_ctx->scan.phase = phase = CMD_SCAN_PHASE_B_EXIT;
		}

		if (_cmd_scan_phase_regs[phase].exec(cmd_res))
			sid_res_log_error(cmd_res, "%s phase failed.", phase_name);
	}

	return 0;
}

static struct cmd_reg _client_cmd_regs[] = {
	[SID_IFC_CMD_UNKNOWN]    = {.name = "c-unknown", .flags = 0, .exec = NULL},
	[SID_IFC_CMD_ACTIVE]     = {.name = "c-active", .flags = 0, .exec = NULL},
	[SID_IFC_CMD_CHECKPOINT] = {.name = "c-checkpoint", .flags = CMD_KV_IMPORT_UDEV, .exec = NULL},
	[SID_IFC_CMD_REPLY]      = {.name = "c-reply", .flags = 0, .exec = NULL},
	[SID_IFC_CMD_SCAN]       = {.name  = "c-scan",
                                    .flags = CMD_KV_IMPORT_UDEV | CMD_KV_EXPORT_UDEV_TO_RESBUF | CMD_KV_EXPORT_SID_TO_EXPBUF |
                                             CMD_KV_EXPBUF_TO_MAIN | CMD_KV_EXPORT_SYNC | CMD_SESSION_ID,
                                    .exec        = _cmd_exec_scan,
                                    .stage_count = 2,
                                    .stage_names = ((const char *[]) {"SCAN_A", "SCAN_B"})},
	[SID_IFC_CMD_VERSION]    = {.name = "c-version", .flags = 0, .exec = _cmd_exec_version},
	[SID_IFC_CMD_DBDUMP]     = {.name  = "c-dbdump",
                                    .flags = CMD_KV_EXPORT_UDEV_TO_EXPBUF | CMD_KV_EXPORT_SID_TO_EXPBUF,
                                    .exec  = NULL},
	[SID_IFC_CMD_DBSTATS]    = {.name = "c-dbstats", .flags = 0, .exec = _cmd_exec_dbstats},
	[SID_IFC_CMD_RESOURCES]  = {.name = "c-resource", .flags = 0, .exec = _cmd_exec_resources},
	[SID_IFC_CMD_DEVICES]    = {.name = "c-devices", .flags = 0, .exec = _cmd_exec_devices},
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

static int _send_out_cmd_expbuf(sid_res_t *cmd_res)
{
	struct sid_ucmd_ctx  *ucmd_ctx = sid_res_get_data(cmd_res);
	const struct cmd_reg *cmd_reg  = _get_cmd_reg(ucmd_ctx);
	sid_res_t            *conn_res = NULL;
	struct connection    *conn     = NULL;
	struct sid_buf       *buf      = ucmd_ctx->common->gen_buf;
	const char           *id;
	size_t                buf_pos;
	char                 *data;
	size_t                size;
	int                   r = -1;

	if (!ucmd_ctx->exp_buf)
		return 0;

	if (cmd_reg->flags & CMD_KV_EXPBUF_TO_MAIN) {
		if (sid_buf_count(ucmd_ctx->exp_buf) == 0) {
			r = -ENODATA;
			goto out;
		}

		id = sid_res_get_id(cmd_res);

		sid_buf_add(buf,
		            &(struct internal_msg_header) {.cat = MSG_CATEGORY_SYSTEM,
		                                           .header =
		                                                   (struct sid_ifc_msg_header) {
									   .status = 0,
									   .prot   = 0,
									   .cmd    = SYSTEM_CMD_SYNC,
									   .flags  = 0,
								   }},
		            INTERNAL_MSG_HEADER_SIZE,
		            NULL,
		            &buf_pos);
		sid_buf_add(buf, (void *) id, strlen(id) + 1, NULL, NULL);
		sid_buf_get_data_from(buf, buf_pos, (const void **) &data, &size);

		if ((r = sid_wrk_ctl_chan_send(
			     cmd_res,
			     MAIN_WORKER_CHANNEL_ID,
			     &(struct sid_wrk_data_spec) {.data               = data,
		                                          .data_size          = size,
		                                          .ext.used           = true,
		                                          .ext.socket.fd_pass = sid_buf_get_fd(ucmd_ctx->exp_buf)})) < 0) {
			sid_res_log_error_errno(cmd_res, r, "Failed to send command exports to main SID process.");
			goto out;
		}

		sid_buf_rewind(buf, buf_pos, SID_BUF_POS_ABS);
	} else if (cmd_reg->flags & CMD_KV_EXPBUF_TO_FILE) {
		if ((r = fsync(sid_buf_get_fd(ucmd_ctx->exp_buf))) < 0) {
			sid_res_log_error_errno(cmd_res, r, "Failed to fsync command exports to a file.");
			goto out;
		}
	} else {
		switch (ucmd_ctx->req_cat) {
			case MSG_CATEGORY_SYSTEM:
				break;

			case MSG_CATEGORY_CLIENT:
				if (!(conn_res = sid_res_search(cmd_res, SID_RES_SEARCH_IMM_ANC, &sid_res_type_ubr_con, NULL))) {
					sid_res_log_warning(cmd_res, "Failed to send command exports to client: connection lost.");
					goto out;
				}
				conn = sid_res_get_data(conn_res);

				if ((r = _send_fd_over_unix_comms(sid_buf_get_fd(ucmd_ctx->exp_buf), conn->fd)) < 0) {
					sid_res_log_error_errno(cmd_res, r, "Failed to send command exports to client.");
					goto out;
				}
				break;

			case MSG_CATEGORY_SELF:
				/* nothing to do here right now */
				break;
		}
	}

	r = 0;
out:
	sid_buf_destroy(ucmd_ctx->exp_buf);
	ucmd_ctx->exp_buf = NULL;
	return r;
}

static int _send_out_cmd_resbuf(sid_res_t *cmd_res)
{
	struct sid_ucmd_ctx *ucmd_ctx = sid_res_get_data(cmd_res);
	sid_res_t           *conn_res = NULL;
	struct connection   *conn     = NULL;
	int                  r        = -1;

	if (!ucmd_ctx->res_buf)
		return 0;

	/* Send out response buffer. */
	switch (ucmd_ctx->req_cat) {
		case MSG_CATEGORY_SYSTEM:
			break;

		case MSG_CATEGORY_CLIENT:
			if (!(conn_res = sid_res_search(cmd_res, SID_RES_SEARCH_IMM_ANC, &sid_res_type_ubr_con, NULL))) {
				sid_res_log_warning(cmd_res, "Failed to send command response to client: connection lost.");
				goto out;
			}

			conn = sid_res_get_data(conn_res);

			if ((r = sid_buf_write_all(ucmd_ctx->res_buf, conn->fd)) < 0) {
				sid_res_log_error_errno(cmd_res, r, "Failed to send command response to client");
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
	sid_buf_destroy(ucmd_ctx->res_buf);
	ucmd_ctx->res_buf = NULL;
	return r;
}

static int _cmd_handler(sid_res_ev_src_t *es, void *data)
{
	sid_res_t            *cmd_res  = data;
	struct sid_ucmd_ctx  *ucmd_ctx = sid_res_get_data(cmd_res);
	const struct cmd_reg *cmd_reg  = _get_cmd_reg(ucmd_ctx);
	int                   r        = -1;

	if (ucmd_ctx->state == CMD_STATE_TIM_OUT) {
		/* TODO: add timeout handling, calling out to module code */
		goto out;
	}

	if (ucmd_ctx->state != CMD_STATE_EXE_SCHED) {
		sid_res_log_error(cmd_res,
		                  SID_INTERNAL_ERROR "%s: Incorrect command state: %s, expected: %s.",
		                  __func__,
		                  cmd_state_str[ucmd_ctx->state],
		                  cmd_state_str[CMD_STATE_EXE_SCHED]);
		goto out;
	}

	if (UTIL_IN_SET(ucmd_ctx->prev_state, CMD_STATE_INI, CMD_STATE_EXE_WAIT, CMD_STATE_STG_WAIT)) {
		/*
		 * If prev_state is:
		 *   - CMD_STATE_INI, we are running this handler for the very first time,
		 *   - CMD_STATE_EXE_WAIT, we are resuming handler from previous run where we needed more data,
		 *   - CMD_STATE_STG_WAIT, we have finished previous cmd stage and now we're running a new one.
		 */
		if ((r = _change_cmd_state(cmd_res, CMD_STATE_EXE_RUN)) < 0)
			goto out;

		/*
		 * =======================================
		 * Execute the command's specific handler.
		 * =======================================
		 */
		if (cmd_reg->exec && ((r = cmd_reg->exec(cmd_res)) < 0)) {
			sid_res_log_error(cmd_res, "Failed to execute command");
			goto out;
		}

		/*
		 * If the command's specific handler has not changed the command
		 * state by itself, change the state to default CMD_STATE_RES_BUILD.
		 */
		if (ucmd_ctx->state == CMD_STATE_EXE_RUN)
			if ((r = _change_cmd_state(cmd_res, CMD_STATE_RES_BUILD)) < 0)
				goto out;
	} else {
		/*
		 * If prev_state is:
		 *   - CMD_STATE_RES_EXPBUF_WAIT_ACK, the expbuf is now acked, so move on to sending the resbuf.
		 */
		if (ucmd_ctx->prev_state == CMD_STATE_RES_EXPBUF_WAIT_ACK) {
			if ((r = _change_cmd_state(cmd_res, CMD_STATE_RES_RESBUF_L_SEND)) < 0)
				goto out;
		}
	}

	if (ucmd_ctx->state == CMD_STATE_RES_BUILD) {
		if ((r = _build_cmd_kv_buffers(cmd_res, cmd_reg->flags)) < 0)
			goto out;

		/*
		 * If we are sending the expbuf to main process, then send
		 * it first (and wait for the main process to ack its
		 * successful reception), then send the respbuf:
		 *
		 * Otherwise, send the respbuf first and then expbuf
		 * (and do not wait for the expbuf reception ack).
		 */
		if ((r = (cmd_reg->flags & CMD_KV_EXPBUF_TO_MAIN ? _change_cmd_state(cmd_res, CMD_STATE_RES_EXPBUF_F_SEND)
		                                                 : _change_cmd_state(cmd_res, CMD_STATE_RES_RESBUF_F_SEND))) < 0)
			goto out;
	}

	if (ucmd_ctx->state == CMD_STATE_RES_EXPBUF_F_SEND) {
		/* We are sending the expbuf first. */
		if (((r = _send_out_cmd_expbuf(cmd_res)) < 0) && (r != -ENODATA))
			goto out;

		/*
		 * If there was no data actually sent in expbuf, then move on to sending the resbuf,
		 * otherwise, wait for expbuf reception ack first.
		 */
		if ((r = (r == -ENODATA) ? _change_cmd_state(cmd_res, CMD_STATE_RES_RESBUF_L_SEND)
		                         : _change_cmd_state(cmd_res, CMD_STATE_RES_EXPBUF_WAIT_ACK)) < 0)
			goto out;

	} else if (ucmd_ctx->state == CMD_STATE_RES_RESBUF_F_SEND) {
		/* We are sending the respuf first. */
		if ((r = _send_out_cmd_resbuf(cmd_res)) < 0)
			goto out;

		/* Then we are sending the expbuf. */
		if ((r = _change_cmd_state(cmd_res, CMD_STATE_RES_EXPBUF_L_SEND)) < 0)
			goto out;
	}

	if (ucmd_ctx->state == CMD_STATE_RES_RESBUF_L_SEND) {
		/* We are sending the resbuf last. */
		if ((r = _send_out_cmd_resbuf(cmd_res)) < 0)
			goto out;

		/* If this is the last stage, finish, otherwise wait for the next stage. */
		if ((r = _is_last_stage(cmd_reg, ucmd_ctx) ? _change_cmd_state(cmd_res, CMD_STATE_FIN)
		                                           : _change_cmd_state(cmd_res, CMD_STATE_STG_WAIT)) < 0)
			goto out;
	} else if (ucmd_ctx->state == CMD_STATE_RES_EXPBUF_L_SEND) {
		/* We are sending the expbuf last. */
		if (((r = _send_out_cmd_expbuf(cmd_res)) < 0) && (r != -ENODATA))
			goto out;

		/* If this is the last stage, finish, otherwise wait for the next stage. */
		if ((r = _is_last_stage(cmd_reg, ucmd_ctx) ? _change_cmd_state(cmd_res, CMD_STATE_FIN)
		                                           : _change_cmd_state(cmd_res, CMD_STATE_STG_WAIT)) < 0)
			goto out;
	}
out:
	if (r < 0) {
		// TODO: res_hdr.status needs to be set before _send_out_cmd_kv_buffers so it's transmitted
		//       and also any results collected after the res_hdr must be discarded
		ucmd_ctx->res_hdr.status |= SID_IFC_CMD_STATUS_FAILURE;
		(void) _change_cmd_state(cmd_res, CMD_STATE_ERR);
		return r;
	}

	if (UTIL_IN_SET(ucmd_ctx->state, CMD_STATE_STG_WAIT, CMD_STATE_FIN))
		(void) _process_cmd_unsbuf(cmd_res);

	/*
	 * TODO: check CMD_STATE_ERR handling - we are setting that under
	 * the (r < 0) condition before and returning, this doesn't seem
	 * correct.
	 */
	if (UTIL_IN_SET(ucmd_ctx->state, CMD_STATE_FIN, CMD_STATE_ERR))
		(void) sid_wrk_ctl_yield_worker(cmd_res);

	return 0;
}

static int _reply_failure(sid_res_t *conn_res)
{
	struct connection        *conn = sid_res_get_data(conn_res);
	void                     *data;
	struct sid_ifc_msg_header header;
	uint8_t                   prot;
	struct sid_ifc_msg_header response_header = {
		.status = SID_IFC_CMD_STATUS_FAILURE,
	};
	int r = -1;

	(void) sid_buf_get_data(conn->buf, (const void **) &data, NULL);
	memcpy(&header, data, sizeof(header));
	prot = header.prot;
	(void) sid_buf_rewind(conn->buf, 0, SID_BUF_POS_ABS);
	if (prot <= SID_IFC_PROTOCOL) {
		response_header.prot = prot;
		if ((r = sid_buf_add(conn->buf, &response_header, sizeof(response_header), NULL, NULL)) < 0)
			r = sid_buf_write_all(conn->buf, conn->fd);
	}

	return r;
}

static bool _socket_client_is_capable(int fd, sid_ifc_cmd_t cmd)
{
	struct ucred uc;
	socklen_t    len = sizeof(struct ucred);

	/* root can run any command */
	if ((fd >= 0) && (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &uc, &len) == 0) && (uc.uid == 0))
		return true;

	return !_cmd_root_only[cmd];
}

static int _check_msg(sid_res_t *res, struct sid_msg *msg)
{
	struct sid_ifc_msg_header header;

	if (msg->size < sizeof(struct sid_ifc_msg_header)) {
		sid_res_log_error(res, "Incorrect message header size.");
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
			if (header.cmd > _SID_IFC_CMD_END)
				header.cmd = SID_IFC_CMD_UNKNOWN;

			if (!sid_res_match(res, &sid_res_type_ubr_con, NULL)) {
				sid_res_log_error(res,
				                  SID_INTERNAL_ERROR "%s: Connection resource missing for client command %s.",
				                  __func__,
				                  sid_ifc_cmd_type_to_name(header.cmd));
				return -1;
			}

			if (!_socket_client_is_capable(((struct connection *) sid_res_get_data(res))->fd, header.cmd)) {
				sid_res_log_error(res,
				                  "Client does not have permission to run command %s.",
				                  sid_ifc_cmd_type_to_name(header.cmd));
				return -1;
			}
			break;
	}

	return 0;
}

static int _create_cmd_res(sid_res_t *parent_res, struct sid_msg *msg)
{
	struct sid_ifc_msg_header header;

	if (_check_msg(parent_res, msg) < 0)
		return -1;

	memcpy(&header, msg->header, sizeof(header));

	if (!sid_res_create(parent_res,
	                    &sid_res_type_ubr_cmd,
	                    SID_RES_FL_NONE,
	                    _get_cmd_reg(&((struct sid_ucmd_ctx) {.req_cat = msg->cat, .req_hdr = header}))->name,
	                    msg,
	                    SID_RES_PRIO_NORMAL,
	                    SID_RES_NO_SERVICE_LINKS)) {
		sid_res_log_error(parent_res, "Failed to register command for processing.");
		return -1;
	}

	return 0;
}

static int _on_connection_event(sid_res_ev_src_t *es, int fd, uint32_t revents, void *data)
{
	sid_res_t         *conn_res = data;
	struct connection *conn     = sid_res_get_data(conn_res);
	struct sid_msg     msg;
	ssize_t            n;

	if (revents & EPOLLERR) {
		if (revents & EPOLLHUP)
			sid_res_log_error(conn_res, "Peer connection closed prematurely.");
		else
			sid_res_log_error(conn_res, "Connection error.");
		goto fail;
	}

	n = sid_buf_read(conn->buf, fd);

	if (n > 0) {
		if (sid_buf_is_complete(conn->buf, NULL)) {
			msg.cat = MSG_CATEGORY_CLIENT;
			(void) sid_buf_get_data(conn->buf, (const void **) &msg.header, &msg.size);

			if (_create_cmd_res(conn_res, &msg) < 0) {
				if (_reply_failure(conn_res) < 0)
					goto fail;
			}

			(void) sid_buf_reset(conn->buf);
		}
	} else if (n < 0) {
		if (n != -EAGAIN && n != -EINTR) {
			sid_res_log_error_errno(conn_res, n, "buffer_read_msg");
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

static int _init_connection(sid_res_t *res, const void *kickstart_data, void **data)
{
	const struct sid_wrk_data_spec *data_spec = kickstart_data;
	struct connection              *conn;
	sid_res_ev_src_t               *conn_es;
	int                             r;

	if (!(conn = mem_zalloc(sizeof(*conn)))) {
		sid_res_log_error(res, "Failed to allocate new connection structure.");
		goto fail;
	}

	conn->fd = data_spec->ext.socket.fd_pass;

	if (sid_res_ev_create_io(res, &conn_es, conn->fd, _on_connection_event, 0, "client connection", res) < 0 ||
	    sid_res_ev_set_exit_on_failure(conn_es, true) < 0) {
		sid_res_log_error(res, "Failed to register connection event handler.");
		goto fail;
	}

	if (!(conn->buf = sid_buf_create(&SID_BUF_SPEC(.mode = SID_BUF_MODE_SIZE_PREFIX), &SID_BUF_INIT(.alloc_step = 1), &r))) {
		sid_res_log_error_errno(res, r, "Failed to create connection buffer");
		goto fail;
	}

	*data = conn;
	return 0;
fail:
	if (conn) {
		if (conn->buf)
			sid_buf_destroy(conn->buf);
		free(conn);
	}
	(void) close(data_spec->ext.socket.fd_pass);
	return -1;
}

static int _destroy_connection(sid_res_t *res)
{
	struct connection *conn = sid_res_get_data(res);

	if (conn->fd != -1)
		(void) close(conn->fd);

	if (conn->buf)
		sid_buf_destroy(conn->buf);

	free(conn);
	return 0;
}

static int _init_command(sid_res_t *res, const void *kickstart_data, void **data)
{
	const struct sid_msg     *msg      = kickstart_data;
	struct sid_ucmd_ctx      *ucmd_ctx = NULL;
	const struct cmd_reg     *cmd_reg  = NULL;
	const char               *worker_id;
	sid_res_t                *common_res;
	int                       r;
	struct sid_ifc_msg_header header;

	memcpy(&header, msg->header, sizeof(header));

	if (!(ucmd_ctx = mem_zalloc(sizeof(*ucmd_ctx)))) {
		sid_res_log_error(res, "Failed to allocate new command structure.");
		goto fail;
	}

	*data = ucmd_ctx;
	if ((r = _change_cmd_state(res, CMD_STATE_INI)) < 0)
		goto fail;

	ucmd_ctx->req_cat = msg->cat;
	ucmd_ctx->req_hdr = header;

	/* Require exact protocol version. We can add possible backward/forward compatibility in future stable versions. */
	if (ucmd_ctx->req_hdr.prot != SID_IFC_PROTOCOL) {
		sid_res_log_error(res, "Protocol version unsupported: %u", ucmd_ctx->req_hdr.prot);
		goto fail;
	}

	if (!(cmd_reg = _get_cmd_reg(ucmd_ctx))) {
		sid_res_log_error(res, SID_INTERNAL_ERROR "%s: Unknown request category: %d.", __func__, (int) ucmd_ctx->req_cat);
		goto fail;
	}

	/* FIXME: Not all commands require print buffer - add command flag to control creation of this buffer. */
	if (!(ucmd_ctx->prn_buf = sid_buf_create(&SID_BUF_SPEC(), &SID_BUF_INIT(.alloc_step = PATH_MAX), &r))) {
		sid_res_log_error_errno(res, r, "Failed to create print buffer");
		goto fail;
	}

	if (!(ucmd_ctx->res_buf = sid_buf_create(&SID_BUF_SPEC(.type = SID_BUF_TYPE_VECTOR, .mode = SID_BUF_MODE_SIZE_PREFIX),
	                                         &SID_BUF_INIT(.size = 1, .alloc_step = 1),
	                                         &r))) {
		sid_res_log_error_errno(res, r, "Failed to create response buffer");
		goto fail;
	}

	ucmd_ctx->res_hdr = (struct sid_ifc_msg_header) {.status = SID_IFC_CMD_STATUS_SUCCESS,
	                                                 .prot   = SID_IFC_PROTOCOL,
	                                                 .cmd    = SID_IFC_CMD_REPLY};
	if ((r = sid_buf_add(ucmd_ctx->res_buf, &ucmd_ctx->res_hdr, sizeof(ucmd_ctx->res_hdr), NULL, NULL)) < 0)
		goto fail;

	if (!(common_res = sid_res_search(res, SID_RES_SEARCH_GENUS, &sid_res_type_ubr_cmn, COMMON_ID))) {
		sid_res_log_error(res, SID_INTERNAL_ERROR "%s: Failed to find common resource.", __func__);
		goto fail;
	}
	ucmd_ctx->common = sid_res_get_data(common_res);

	if (cmd_reg->flags & CMD_KV_IMPORT_UDEV) {
		/* currently, we only parse udev environment for the SCAN command */
		if ((r = _parse_cmd_udev_env(res,
		                             ucmd_ctx,
		                             (const char *) msg->header + SID_IFC_MSG_HEADER_SIZE,
		                             msg->size - SID_IFC_MSG_HEADER_SIZE)) < 0) {
			sid_res_log_error_errno(res, r, "Failed to parse udev environment variables");
			goto fail;
		}

		sid_res_log_debug(res,
		                  "Processing event: %s %s uevent with seqno %" PRIu64 " for device " CMD_DEV_PRINT_FMT,
		                  sid_ucmd_ev_get_dev_synth_uuid(ucmd_ctx) == NULL ? "genuine" : "synthetic",
		                  util_udev_action_to_str(sid_ucmd_ev_get_dev_action(ucmd_ctx)),
		                  sid_ucmd_ev_get_dev_seqnum(ucmd_ctx),
		                  CMD_DEV_PRINT(ucmd_ctx));
	}

	if (cmd_reg->flags & CMD_KV_EXPBUF_TO_FILE) {
		if ((msg->size > sizeof(*msg->header)) &&
		    !(ucmd_ctx->req_env.exp_path = strdup((char *) msg->header + sizeof(*msg->header))))
			goto fail;
	}

	if (cmd_reg->flags & CMD_SESSION_ID) {
		if (!(worker_id = sid_wrk_ctl_get_worker_id(res))) {
			sid_res_log_error(res, "Failed to get worker ID to set %s udev variable.", KV_KEY_UDEV_SID_SESSION_ID);
			goto fail;
		}

		if (!_do_sid_ucmd_set_kv(res,
		                         ucmd_ctx,
		                         _owner_name(NULL),
		                         NULL,
		                         SID_KV_NS_UDEV,
		                         KV_KEY_UDEV_SID_SESSION_ID,
		                         SID_KV_FL_SYNC_P,
		                         worker_id,
		                         strlen(worker_id) + 1)) {
			sid_res_log_error(res, "Failed to set %s udev variable.", KV_KEY_UDEV_SID_SESSION_ID);
			goto fail;
		}
	}

	if (sid_res_ev_create_deferred(res, &ucmd_ctx->cmd_handler_es, _cmd_handler, 0, "command handler", res) < 0 ||
	    sid_res_ev_set_exit_on_failure(ucmd_ctx->cmd_handler_es, true) < 0) {
		sid_res_log_error(res, "Failed to register command handler.");
		goto fail;
	}

	if ((r = _change_cmd_state(res, CMD_STATE_EXE_SCHED)) < 0)
		goto fail;

	return 0;
fail:
	if (ucmd_ctx) {
		*data = NULL;
		if (cmd_reg && cmd_reg->flags & CMD_KV_EXPBUF_TO_FILE && ucmd_ctx->req_env.exp_path)
			free((void *) ucmd_ctx->req_env.exp_path);

		if (ucmd_ctx->prn_buf)
			sid_buf_destroy(ucmd_ctx->prn_buf);

		if (ucmd_ctx->res_buf)
			sid_buf_destroy(ucmd_ctx->res_buf);

		if (ucmd_ctx->req_env.dev.num_s)
			free((char *) ucmd_ctx->req_env.dev.num_s);

		if (ucmd_ctx->req_env.dev.uid_s)
			free((char *) ucmd_ctx->req_env.dev.uid_s);

		if (ucmd_ctx->req_env.dev.dsq_s)
			free((char *) ucmd_ctx->req_env.dev.dsq_s);

		free(ucmd_ctx);
	}
	return -1;
}

static int _destroy_command(sid_res_t *res)
{
	struct sid_ucmd_ctx  *ucmd_ctx = sid_res_get_data(res);
	const struct cmd_reg *cmd_reg  = _get_cmd_reg(ucmd_ctx);

	if (ucmd_ctx->res_buf)
		sid_buf_destroy(ucmd_ctx->res_buf);

	if (ucmd_ctx->prn_buf)
		sid_buf_destroy(ucmd_ctx->prn_buf);

	if (ucmd_ctx->exp_buf)
		sid_buf_destroy(ucmd_ctx->exp_buf);

	if (ucmd_ctx->req_hdr.cmd == SID_IFC_CMD_RESOURCES) {
		if (ucmd_ctx->resources.main_res_mem)
			(void) munmap(ucmd_ctx->resources.main_res_mem, ucmd_ctx->resources.main_res_mem_size);
	}

	if ((cmd_reg->flags & CMD_KV_EXPBUF_TO_FILE))
		free((void *) ucmd_ctx->req_env.exp_path);
	else {
		free((char *) ucmd_ctx->req_env.dev.num_s);
		free((char *) ucmd_ctx->req_env.dev.uid_s);
		free((char *) ucmd_ctx->req_env.dev.dsq_s);
	}

	free(ucmd_ctx);
	return 0;
}

static int _kv_cb_main_unset(struct sid_kvs_update_spec *spec)
{
	struct kv_update_arg *update_arg = spec->arg;
	struct kv_unset_nfo  *unset_nfo  = update_arg->custom;
	kv_vector_t           tmp_old_vvalue[VVALUE_SINGLE_ALIGNED_CNT];
	kv_vector_t          *old_vvalue;
	int                   r = 0;

	if (!spec->old_data) {
		sid_res_log_debug(update_arg->res,
		                  "Skipping unset for key %s as it is already unset (new seqnum %" PRIu64 ").",
		                  spec->key,
		                  unset_nfo->seqnum);
		return 1;
	}

	old_vvalue = _get_vvalue(spec->old_flags, spec->old_data, spec->old_data_size, tmp_old_vvalue, VVALUE_CNT(tmp_old_vvalue));

	r          = ((unset_nfo->seqnum == 0) || (unset_nfo->seqnum >= VVALUE_SEQNUM(old_vvalue))) && _kv_cb_write(spec);

	if (r)
		sid_res_log_debug(update_arg->res,
		                  "Unsetting key %s (old seqnum %" PRIu64 ", new seqnum %" PRIu64 ").",
		                  spec->key,
		                  VVALUE_SEQNUM(old_vvalue),
		                  unset_nfo->seqnum);
	else
		sid_res_log_debug(update_arg->res,
		                  "Keeping key %s (old seqnum %" PRIu64 ", new seqnum %" PRIu64 ").",
		                  spec->key,
		                  VVALUE_SEQNUM(old_vvalue),
		                  unset_nfo->seqnum);

	return r;
}

static int _kv_cb_main_set(struct sid_kvs_update_spec *spec)
{
	struct kv_update_arg *update_arg = spec->arg;
	kv_vector_t           tmp_old_vvalue[VVALUE_SINGLE_ALIGNED_CNT];
	kv_vector_t           tmp_new_vvalue[VVALUE_SINGLE_ALIGNED_CNT];
	kv_vector_t          *old_vvalue, *new_vvalue;
	int                   r;

	new_vvalue = _get_vvalue(spec->new_flags, spec->new_data, spec->new_data_size, tmp_new_vvalue, VVALUE_CNT(tmp_new_vvalue));

	if (!spec->old_data) {
		sid_res_log_debug(update_arg->res,
		                  "Adding value for key %s (new seqnum %" PRIu64 ").",
		                  spec->key,
		                  VVALUE_SEQNUM(new_vvalue));
		return 1;
	}

	old_vvalue = _get_vvalue(spec->old_flags, spec->old_data, spec->old_data_size, tmp_old_vvalue, VVALUE_CNT(tmp_old_vvalue));

	/* overwrite whole value */
	/* note that 'VVALUE_SEQNUM(new_vvalue) == 0' means 'skip seqnum check' */
	r = ((VVALUE_SEQNUM(new_vvalue) == 0) || (VVALUE_SEQNUM(new_vvalue) >= VVALUE_SEQNUM(old_vvalue))) && _kv_cb_write(spec);

	if (r)
		sid_res_log_debug(update_arg->res,
		                  "Updating value for key %s (old seqnum %" PRIu64 ", new seqnum %" PRIu64 ").",
		                  spec->key,
		                  old_vvalue ? VVALUE_SEQNUM(old_vvalue) : 0,
		                  VVALUE_SEQNUM(new_vvalue));
	else
		sid_res_log_debug(update_arg->res,
		                  "Keeping old value for key %s (old seqnum %" PRIu64 ", new seqnum %" PRIu64 ").",
		                  spec->key,
		                  old_vvalue ? VVALUE_SEQNUM(old_vvalue) : 0,
		                  VVALUE_SEQNUM(new_vvalue));

	return r;
}

static char *_compose_archive_key(sid_res_t *res, const char *key, size_t key_size)
{
	char *archive_key;

	if (!(archive_key = malloc(key_size + 1))) {
		sid_res_log_error(res, "Failed to create archive key for key %s.", key);
		return NULL;
	}

	memcpy(archive_key + 1, key, key_size);
	archive_key[0] = KV_PREFIX_OP_ARCHIVE_C[0];

	return archive_key;
}

static int _sync_main_kv_store(sid_res_t *res, struct sid_ucmd_common_ctx *common_ctx, int fd)
{
	static const char        syncing_msg[] = "Syncing main key-value store:  %s = %s (seqnum %" PRIu64 ")";
	sid_kvs_val_fl_t         kv_store_value_flags;
	SID_BUF_SIZE_PREFIX_TYPE msg_size;
	size_t                   key_size, value_size, ext_data_offset, i;
	char                    *key, *archive_key = NULL, *shm = MAP_FAILED, *p, *end;
	kv_scalar_t              tmp_svalue, *svalue = NULL;
	kv_vector_t             *vvalue = NULL;
	const char              *vvalue_str;
	void                    *value_to_store;
	const void              *final_value;
	struct kv_rel_spec       rel_spec   = {.delta = &((struct kv_delta) {0}), .abs_delta = &((struct kv_delta) {0})};
	struct kv_update_arg     update_arg = {.gen_buf = common_ctx->gen_buf, .is_sync = true, .custom = &rel_spec};
	struct kv_unset_nfo      unset_nfo;
	bool                     unset, archive;
	int                      r = -1;

	if (read(fd, &msg_size, SID_BUF_SIZE_PREFIX_LEN) != SID_BUF_SIZE_PREFIX_LEN) {
		sid_res_log_error_errno(res, errno, "Failed to read shared memory size");
		goto out;
	}

	if (msg_size <= SID_BUF_SIZE_PREFIX_LEN) { /* nothing to sync */
		r = 0;
		goto out;
	} else if (msg_size > INTERNAL_MSG_MAX_FD_DATA_SIZE) {
		sid_res_log_error(res, "Maximum internal messages size exceeded.");
		goto out;
	}

	if ((p = shm = mmap(NULL, msg_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED) {
		sid_res_log_error_errno(res, errno, "Failed to map memory with key-value store");
		goto out;
	}

	end  = p + msg_size;
	p   += sizeof(msg_size);

	if (sid_kvs_transaction_begin(common_ctx->kvs_res) < 0) {
		sid_res_log_error(res, "Failed to start key-value store transaction");
		goto out;
	}

	while (p < end) {
		memcpy(&kv_store_value_flags, p, sizeof(kv_store_value_flags));
		p += sizeof(kv_store_value_flags);

		memcpy(&key_size, p, sizeof(key_size));
		p += sizeof(key_size);

		memcpy(&value_size, p, sizeof(value_size));
		p   += sizeof(value_size);

		key  = p;
		p   += key_size;

		/*
		 * Note: if we're reserving a value, then we keep it even if it's NULL.
		 * This prevents others to use the same key. To unset the value,
		 * one needs to drop the flag explicitly.
		 */

		if (kv_store_value_flags & SID_KVS_VAL_FL_VECTOR) {
			if (value_size < VVALUE_HEADER_CNT) {
				sid_res_log_error(res,
				                  "Received incorrect vector of size %zu to sync with main key-value store.",
				                  value_size);
				goto out;
			}

			if (!(vvalue = malloc(value_size * sizeof(kv_vector_t)))) {
				sid_res_log_error(res, "Failed to allocate vector to sync main key-value store.");
				goto out;
			}

			for (i = 0; i < value_size; i++) {
				memcpy(&vvalue[i].iov_len, p, sizeof(size_t));
				p                  += sizeof(size_t);
				vvalue[i].iov_base  = p;
				p                  += vvalue[i].iov_len;
			}
			/* Copy values to aligned memory */
			memcpy(&tmp_svalue.seqnum, vvalue[VVALUE_IDX_SEQNUM].iov_base, sizeof(tmp_svalue.seqnum));
			vvalue[VVALUE_IDX_SEQNUM].iov_base = &tmp_svalue.seqnum;
			memcpy(&tmp_svalue.flags, vvalue[VVALUE_IDX_FLAGS].iov_base, sizeof(tmp_svalue.flags));
			vvalue[VVALUE_IDX_FLAGS].iov_base = &tmp_svalue.flags;
			memcpy(&tmp_svalue.gennum, vvalue[VVALUE_IDX_GENNUM].iov_base, sizeof(tmp_svalue.gennum));
			vvalue[VVALUE_IDX_GENNUM].iov_base = &tmp_svalue.gennum;

			unset               = !(VVALUE_FLAGS(vvalue) & SID_KV_FL_RS) && (value_size == VVALUE_HEADER_CNT);

			update_arg.res      = common_ctx->kvs_res;
			update_arg.ret_code = 0;

			unset_nfo.owner     = VVALUE_OWNER(vvalue);
			unset_nfo.seqnum    = VVALUE_SEQNUM(vvalue);

			vvalue_str          = _buffer_get_vvalue_str(common_ctx->gen_buf, unset, vvalue, value_size);
			sid_res_log_debug(res, syncing_msg, key, vvalue_str ?: "NULL", VVALUE_SEQNUM(vvalue));
			if (vvalue_str)
				sid_buf_rewind_mem(common_ctx->gen_buf, vvalue_str);

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
					sid_res_log_error(
						res,
						SID_INTERNAL_ERROR
						"%s: Illegal operator found for key %s while trying to sync main key-value store.",
						__func__,
						key);
					goto out;
			}

			archive        = VVALUE_FLAGS(vvalue) & SID_KV_FL_AR;
			value_to_store = vvalue;
		} else {
			if (value_size <= SVALUE_HEADER_SIZE) {
				sid_res_log_error(res,
				                  "Received incorrect value of size %zu to sync with main key-value store.",
				                  value_size);
				goto out;
			}

			if (!(svalue = malloc(value_size))) {
				sid_res_log_error(res, "Failed to allocate svalue to sync main key-value store.");
				goto out;
			}

			memcpy(svalue, p, value_size);
			p               += value_size;

			ext_data_offset  = _svalue_ext_data_offset(svalue);
			unset          = ((svalue->flags != SID_KV_FL_RS) && (value_size == SVALUE_HEADER_SIZE + ext_data_offset));

			update_arg.res = common_ctx->kvs_res;
			update_arg.ret_code = 0;

			unset_nfo.owner     = svalue->data;
			unset_nfo.seqnum    = svalue->seqnum;

			sid_res_log_debug(res, syncing_msg, key, unset ? "NULL" : svalue->data + ext_data_offset, svalue->seqnum);

			rel_spec.delta->op = KV_OP_SET;

			archive            = svalue->flags & SID_KV_FL_AR;
			value_to_store     = svalue;
		}

		if (unset) {
			if (!(archive_key = _compose_archive_key(res, key, key_size)))
				goto out;

			update_arg.custom = &unset_nfo;

			if (archive) {
				if (sid_kvs_unset_with_archive(common_ctx->kvs_res,
				                               key,
				                               _kv_cb_main_unset,
				                               &update_arg,
				                               archive_key) < 0)
					goto out;
			} else {
				if (sid_kvs_unset(common_ctx->kvs_res, key, _kv_cb_main_unset, &update_arg) < 0)
					goto out;

				if (sid_kvs_unset(common_ctx->kvs_res, archive_key, _kv_cb_main_unset, &update_arg) < 0)
					goto out;
			}
		} else {
			if (rel_spec.delta->op == KV_OP_SET) {
				if (!(archive_key = _compose_archive_key(res, key, key_size)))
					goto out;

				if (archive) {
					if (!sid_kvs_set_with_archive(common_ctx->kvs_res,
					                              key,
					                              value_to_store,
					                              value_size,
					                              kv_store_value_flags,
					                              SID_KVS_VAL_OP_NONE,
					                              _kv_cb_main_set,
					                              &update_arg,
					                              archive_key))
						goto out;
				} else {
					if (!sid_kvs_set(common_ctx->kvs_res,
					                 key,
					                 value_to_store,
					                 value_size,
					                 kv_store_value_flags,
					                 SID_KVS_VAL_OP_NONE,
					                 _kv_cb_main_set,
					                 &update_arg))
						goto out;

					update_arg.custom = &unset_nfo;

					if (sid_kvs_unset(common_ctx->kvs_res, archive_key, _kv_cb_main_unset, &update_arg) < 0)
						goto out;
				}
			} else {
				if (!sid_kvs_set(common_ctx->kvs_res,
				                 key,
				                 value_to_store,
				                 value_size,
				                 SID_KVS_VAL_FL_VECTOR | SID_KVS_VAL_FL_REF,
				                 SID_KVS_VAL_OP_NONE,
				                 _kv_cb_delta_step,
				                 &update_arg)) {
					_destroy_delta_buffers(rel_spec.delta);
					goto out;
				}

				sid_buf_get_data(rel_spec.delta->final, &final_value, &value_size);

				unset = !(VVALUE_FLAGS(final_value) & SID_KV_FL_RS) && (value_size == VVALUE_HEADER_CNT);
				if (unset) {
					if (value_size == VVALUE_HEADER_CNT) {
						unset_nfo.owner   = VVALUE_OWNER(final_value);
						unset_nfo.seqnum  = VVALUE_SEQNUM(final_value);
						update_arg.custom = &unset_nfo;
						sid_kvs_unset(common_ctx->kvs_res, key, _kv_cb_main_unset, &update_arg);
					}
				}

				_destroy_delta_buffers(rel_spec.delta);
			}
		}

		svalue      = mem_freen(svalue);
		vvalue      = mem_freen(vvalue);
		archive_key = mem_freen(archive_key);
	}

	r = 0;
out:
	if (sid_kvs_transaction_active(common_ctx->kvs_res))
		sid_kvs_transaction_end(common_ctx->kvs_res, (r < 0));

	free(vvalue);
	free(svalue);
	free(archive_key);

	if (shm != MAP_FAILED && munmap(shm, msg_size) < 0) {
		sid_res_log_error_errno(res, errno, "Failed to unmap memory with key-value store");
		r = -1;
	}

	return r;
}

static int _worker_proxy_recv_system_cmd_sync(sid_res_t *worker_proxy_res, struct sid_wrk_data_spec *data_spec, void *arg)
{
	struct sid_ucmd_common_ctx *common_ctx = arg;
	int                         r;

	if (!data_spec->ext.used) {
		sid_res_log_error(worker_proxy_res,
		                  SID_INTERNAL_ERROR "%s: Received KV store sync request, but KV store sync data missing.",
		                  __func__);
		return -1;
	}

	(void) _sync_main_kv_store(worker_proxy_res, common_ctx, data_spec->ext.socket.fd_pass);

	r = sid_wrk_ctl_chan_send(
		worker_proxy_res,
		MAIN_WORKER_CHANNEL_ID,
		&(struct sid_wrk_data_spec) {.data = data_spec->data, .data_size = data_spec->data_size, .ext.used = false});

	(void) close(data_spec->ext.socket.fd_pass);
	return r;
}

static int _worker_proxy_recv_system_cmd_resources(sid_res_t                *worker_proxy_res,
                                                   struct sid_wrk_data_spec *data_spec,
                                                   void *arg                 __unused)
{
	struct internal_msg_header int_msg;
	struct sid_buf            *buf;
	int                        r = -1;

	memcpy(&int_msg, data_spec->data, INTERNAL_MSG_HEADER_SIZE);

	if (!(buf = sid_buf_create(&SID_BUF_SPEC(.backend = SID_BUF_BACKEND_MEMFD, .mode = SID_BUF_MODE_SIZE_PREFIX),
	                           &SID_BUF_INIT(.alloc_step = PATH_MAX),
	                           &r))) {
		sid_res_log_error_errno(worker_proxy_res, r, "Failed to create temporary buffer.");
		return -1;
	}

	if (sid_res_tree_write(sid_res_search(worker_proxy_res, SID_RES_SEARCH_TOP, NULL, NULL),
	                       flags_to_format(int_msg.header.flags),
	                       buf,
	                       2,
	                       false)) {
		sid_res_log_error(worker_proxy_res, "Failed to write resource tree.");
		goto out;
	}

	/* reply to the worker with the same header and data (cmd id) */
	r = sid_wrk_ctl_chan_send(worker_proxy_res,
	                          MAIN_WORKER_CHANNEL_ID,
	                          &(struct sid_wrk_data_spec) {.data               = data_spec->data,
	                                                       .data_size          = data_spec->data_size,
	                                                       .ext.used           = true,
	                                                       .ext.socket.fd_pass = sid_buf_get_fd(buf)});
out:
	sid_buf_destroy(buf);
	return r;
}

static int _worker_proxy_recv_fn(sid_res_t                *worker_proxy_res,
                                 struct sid_wrk_chan      *chan,
                                 struct sid_wrk_data_spec *data_spec,
                                 void                     *arg)
{
	struct internal_msg_header int_msg;

	if (data_spec->data_size < INTERNAL_MSG_HEADER_SIZE) {
		sid_res_log_error(worker_proxy_res, SID_INTERNAL_ERROR "%s: Incorrect internal message header size.", __func__);
		return -1;
	}

	memcpy(&int_msg, data_spec->data, INTERNAL_MSG_HEADER_SIZE);

	if (int_msg.cat != MSG_CATEGORY_SYSTEM) {
		sid_res_log_error(worker_proxy_res, SID_INTERNAL_ERROR "%s: Received unexpected message category.", __func__);
		return -1;
	}

	switch (int_msg.header.cmd) {
		case SYSTEM_CMD_SYNC:
			return _worker_proxy_recv_system_cmd_sync(worker_proxy_res, data_spec, arg);

		case SYSTEM_CMD_RESOURCES:
			return _worker_proxy_recv_system_cmd_resources(worker_proxy_res, data_spec, arg);

		default:
			sid_res_log_error(worker_proxy_res, "Unknown system command.");
			return -1;
	}
}

static int _worker_recv_system_cmd_resources(sid_res_t *worker_res, struct sid_wrk_data_spec *data_spec)
{
	static const char        _msg_prologue[] = "Received result from resource cmd for main process, but";
	const char              *cmd_id;
	sid_res_t               *cmd_res;
	struct sid_ucmd_ctx     *ucmd_ctx;
	SID_BUF_SIZE_PREFIX_TYPE msg_size;
	int                      r = -1;

	// TODO: make sure error path is not causing the client waiting for response to hang !!!

	if (!data_spec->ext.used) {
		sid_res_log_error(worker_res, "%s data handler is missing.", _msg_prologue);
		return -1;
	}

	if (read(data_spec->ext.socket.fd_pass, &msg_size, SID_BUF_SIZE_PREFIX_LEN) != SID_BUF_SIZE_PREFIX_LEN) {
		sid_res_log_error_errno(worker_res,
		                        errno,
		                        SID_INTERNAL_ERROR "%s: %s failed to read shared memory size",
		                        __func__,
		                        _msg_prologue);
		goto out;
	}

	if (msg_size <= SID_BUF_SIZE_PREFIX_LEN) {
		sid_res_log_error(worker_res, SID_INTERNAL_ERROR "%s: %s no data received.", __func__, _msg_prologue);
		goto out;
	} else if (msg_size > INTERNAL_MSG_MAX_FD_DATA_SIZE) {
		sid_res_log_error(worker_res, SID_INTERNAL_ERROR "%s: Maximum internal messages size exceeded.", __func__);
		goto out;
	}

	/* cmd id needs at least 1 character with '0' at the end - so 2 characters at least! */
	if ((data_spec->data_size - INTERNAL_MSG_HEADER_SIZE) < 2) {
		sid_res_log_error(worker_res, SID_INTERNAL_ERROR "%s: %s missing command id to match.", __func__, _msg_prologue);
		goto out;
	}

	cmd_id = data_spec->data + INTERNAL_MSG_HEADER_SIZE;

	if (!(cmd_res = sid_res_search(worker_res, SID_RES_SEARCH_DFS, &sid_res_type_ubr_cmd, cmd_id))) {
		sid_res_log_error(worker_res,
		                  SID_INTERNAL_ERROR "%s: %s failed to find command resource with id %s.",
		                  __func__,
		                  _msg_prologue,
		                  cmd_id);
		goto out;
	}

	ucmd_ctx                              = sid_res_get_data(cmd_res);

	ucmd_ctx->resources.main_res_mem_size = msg_size;
	ucmd_ctx->resources.main_res_mem =
		mmap(NULL, ucmd_ctx->resources.main_res_mem_size, PROT_READ, MAP_SHARED, data_spec->ext.socket.fd_pass, 0);

	r = _change_cmd_state(cmd_res, CMD_STATE_EXE_SCHED);
out:
	(void) close(data_spec->ext.socket.fd_pass);
	return r;
}

static int _worker_recv_system_cmd_umonitor(sid_res_t *worker_res, struct sid_wrk_data_spec *data_spec)
{
	static const char cmd_id[] = "c-scan";
	sid_res_t        *cmd_res;

	if (!(cmd_res = sid_res_search(worker_res, SID_RES_SEARCH_DFS, &sid_res_type_ubr_cmd, cmd_id))) {
		sid_res_log_error(worker_res,
		                  SID_INTERNAL_ERROR "%s: Failed to find command resource with id %s.",
		                  __func__,
		                  cmd_id);
		return -1;
	}

	return _change_cmd_state(cmd_res, CMD_STATE_EXE_SCHED);
}

static int _worker_recv_system_cmd_sync(sid_res_t *worker_res, struct sid_wrk_data_spec *data_spec)
{
	static const char _msg_prologue[] = "Received sync ack from main process, but";
	const char       *cmd_id;
	sid_res_t        *cmd_res;

	/* cmd_id needs at least 1 character with '\0' at the end - so 2 characters at least! */
	if ((data_spec->data_size - INTERNAL_MSG_HEADER_SIZE) < 2) {
		sid_res_log_error(worker_res, SID_INTERNAL_ERROR "%s: %s missing command id to match.", __func__, _msg_prologue);
		return -1;
	}

	cmd_id = data_spec->data + INTERNAL_MSG_HEADER_SIZE;

	if (!(cmd_res = sid_res_search(worker_res, SID_RES_SEARCH_DFS, &sid_res_type_ubr_cmd, cmd_id))) {
		sid_res_log_error(worker_res,
		                  SID_INTERNAL_ERROR "%s: %s failed to find command resource with id %s.",
		                  __func__,
		                  _msg_prologue,
		                  cmd_id);
		return -1;
	}

	return _change_cmd_state(cmd_res, CMD_STATE_EXE_SCHED);
}

static int
	_worker_recv_fn(sid_res_t *worker_res, struct sid_wrk_chan *chan, struct sid_wrk_data_spec *data_spec, void *arg __unused)
{
	struct internal_msg_header int_msg;

	if (data_spec->data_size < INTERNAL_MSG_HEADER_SIZE) {
		sid_res_log_error(worker_res, SID_INTERNAL_ERROR "%s: Incorrect internal message header size.", __func__);
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

				case SYSTEM_CMD_UMONITOR:
					if (_worker_recv_system_cmd_umonitor(worker_res, data_spec) < 0)
						return -1;
					break;

				case SYSTEM_CMD_RESOURCES:
					if (_worker_recv_system_cmd_resources(worker_res, data_spec) < 0)
						return -1;
					break;

				default:
					sid_res_log_error(worker_res,
					                  SID_INTERNAL_ERROR "%s: Received unexpected system command.",
					                  __func__);
					return -1;
			}
			break;

		case MSG_CATEGORY_CLIENT:
			/*
			 * Command requested externally through a connection.
			 * sid_msg will be read from client through the connection.
			 */
			if (data_spec->ext.used) {
				if (!sid_res_create(worker_res,
				                    &sid_res_type_ubr_con,
				                    SID_RES_FL_NONE,
				                    SID_RES_NO_CUSTOM_ID,
				                    data_spec,
				                    SID_RES_PRIO_NORMAL,
				                    SID_RES_NO_SERVICE_LINKS)) {
					sid_res_log_error(worker_res, "Failed to create connection resource.");
					return -1;
				}
			} else {
				sid_res_log_error(worker_res, "Received command from worker proxy, but connection handle missing.");
				return -1;
			}
			break;

		case MSG_CATEGORY_SELF:
			/*
			 * Command requested internally.
			 * Generate sid_msg out of int_msg as if it was sent through a connection.
			 */
			if (_create_cmd_res(worker_res,
			                    &((struct sid_msg) {.cat    = MSG_CATEGORY_SELF,
			                                        .size   = data_spec->data_size - sizeof(int_msg.cat),
			                                        .header = (struct sid_ifc_msg_header *) (data_spec->data +
			                                                                                 sizeof(int_msg.cat))})) <
			    0)
				return -1;
			break;
	}

	return 0;
}

static int _worker_init_fn(sid_res_t *worker_res, void *arg)
{
	struct sid_ucmd_common_ctx *common_ctx  = arg;
	sid_res_t                  *old_top_res = sid_res_search(common_ctx->res, SID_RES_SEARCH_TOP, NULL, NULL);

	/* only take inherited common resource and attach it to the worker */
	(void) sid_res_isolate(common_ctx->res, SID_RES_ISOL_FL_SUBTREE);
	(void) sid_res_add_child(worker_res, common_ctx->res, SID_RES_FL_NONE);

	/* destroy remaining resources */
	(void) sid_res_unref(old_top_res);

	return 0;
}

/* *res_p is set to the worker_proxy resource. If a new worker process is created, when it returns, *res_p will be NULL */
static int _get_worker(sid_res_t *ubridge_res, sid_res_t **res_p)
{
	struct ubridge *ubridge = sid_res_get_data(ubridge_res);
	char            uuid[UTIL_UUID_STR_SIZE];
	util_mem_t      mem = {.base = uuid, .size = sizeof(uuid)};
	sid_res_t      *worker_control_res, *worker_proxy_res;

	*res_p = NULL;
	if (!(worker_control_res = sid_res_search(ubridge->internal_res, SID_RES_SEARCH_IMM_DESC, &sid_res_type_wrk_ctl, NULL))) {
		sid_res_log_error(ubridge_res, SID_INTERNAL_ERROR "%s: Failed to find worker control resource.", __func__);
		return -1;
	}

	if ((worker_proxy_res = sid_wrk_ctl_get_idle_worker(worker_control_res)))
		*res_p = worker_proxy_res;
	else {
		sid_res_log_debug(ubridge_res, "Idle worker not found, creating a new one.");

		if (!util_uuid_gen_str(&mem)) {
			sid_res_log_error(ubridge_res, "Failed to generate UUID for new worker.");
			return -1;
		}

		if (sid_wrk_ctl_get_new_worker(worker_control_res, &((struct sid_wrk_params) {.id = uuid}), res_p) < 0)
			return -1;
	}

	return 0;
}

static int _on_ubridge_interface_event(sid_res_ev_src_t *es, int fd, uint32_t revents, void *data)
{
	sid_res_t                 *ubridge_res = data;
	struct ubridge            *ubridge     = sid_res_get_data(ubridge_res);
	sid_res_t                 *worker_proxy_res;
	struct sid_wrk_data_spec   data_spec;
	struct internal_msg_header int_msg;
	int                        r;

	sid_res_log_debug(ubridge_res, "Received an event.");

	if (_get_worker(ubridge_res, &worker_proxy_res) < 0)
		return -1;

	/* If this is a worker process, exit the handler */
	if (!worker_proxy_res)
		return 0;

	int_msg.cat         = MSG_CATEGORY_CLIENT;
	int_msg.header      = (struct sid_ifc_msg_header) {0};

	data_spec.data      = &int_msg;
	data_spec.data_size = INTERNAL_MSG_HEADER_SIZE;
	data_spec.ext.used  = true;

	if ((data_spec.ext.socket.fd_pass = accept4(ubridge->socket_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC)) < 0) {
		sid_res_log_sys_error(ubridge_res, "accept", "");
		return -1;
	}

	if ((r = sid_wrk_ctl_chan_send(worker_proxy_res, MAIN_WORKER_CHANNEL_ID, &data_spec)) < 0) {
		sid_res_log_error_errno(ubridge_res, r, "worker_control_channel_send");
		r = -1;
	}

	(void) close(data_spec.ext.socket.fd_pass);
	return r;
}

int sid_ubr_cmd_dbdump(sid_res_t *ubridge_res, const char *file_path)
{
	sid_res_t                  *worker_proxy_res;
	struct internal_msg_header *int_msg;
	struct sid_wrk_data_spec    data_spec;
	size_t                      file_path_size;
	char                        buf[INTERNAL_MSG_HEADER_SIZE + PATH_MAX + 1];

	if (!sid_res_match(ubridge_res, &sid_res_type_ubr, NULL))
		return -EINVAL;

	if (_get_worker(ubridge_res, &worker_proxy_res) < 0)
		return -1;

	/* If this is a worker process, return right away */
	if (!worker_proxy_res)
		return 0;

	int_msg         = (struct internal_msg_header *) buf;
	int_msg->cat    = MSG_CATEGORY_SELF;
	int_msg->header = (struct sid_ifc_msg_header) {.status = 0, .prot = SID_IFC_PROTOCOL, .cmd = SELF_CMD_DBDUMP, .flags = 0};

	if (!file_path || !*file_path)
		file_path_size = 0;
	else {
		file_path_size = strlen(file_path) + 1;
		memcpy(buf + INTERNAL_MSG_HEADER_SIZE, file_path, file_path_size);
	}

	data_spec =
		(struct sid_wrk_data_spec) {.data = buf, .data_size = INTERNAL_MSG_HEADER_SIZE + file_path_size, .ext.used = false};

	return sid_wrk_ctl_chan_send(worker_proxy_res, MAIN_WORKER_CHANNEL_ID, &data_spec);
}

/*
static int _on_ubridge_time_event(sid_res_ev_src_t *es, uint64_t usec, void *data)
{
        sid_res_t *ubridge_res = data;
        static int      counter     = 0;

        log_debug(ID(ubridge_res), "dumping db (%d)", counter++);
        (void) ubridge_cmd_dbdump(ubridge_res, NULL);

        sid_res_ev_time_rearm(es, SID_EVENT_TIME_RELATIVE, 10000000);
        return 0;
}
*/

static int _load_kv_store(sid_res_t *ubridge_res, struct sid_ucmd_common_ctx *common_ctx)
{
	int fd;
	int r;

	if (common_ctx->gennum != 0) {
		sid_res_log_error(ubridge_res,
		                  SID_INTERNAL_ERROR "%s: unexpected KV generation number, KV store already loaded.",
		                  __func__);
		return -1;
	}

	if ((fd = open(MAIN_KV_STORE_FILE_PATH, O_RDONLY)) < 0) {
		if (errno == ENOENT)
			return 0;

		sid_res_log_error_errno(ubridge_res, fd, "Failed to open db file");
		return -1;
	}

	r = _sync_main_kv_store(ubridge_res, common_ctx, fd);

	(void) close(fd);
	return r;
}

static int _on_ubridge_umonitor_event(sid_res_ev_src_t *es, int fd, uint32_t revents, void *data)
{
	sid_res_t                 *ubridge_res = data;
	struct ubridge            *ubridge     = sid_res_get_data(ubridge_res);
	unsigned long long         seqnum;
	sid_res_t                 *worker_control_res;
	sid_res_t                 *worker_proxy_res;
	struct udev_device        *udev_dev;
	const char                *worker_id;
	struct internal_msg_header int_msg;
	struct sid_wrk_data_spec   data_spec;
	int                        r = -1;

	if (!(udev_dev = udev_monitor_receive_device(ubridge->ulink.mon)))
		goto out;

	seqnum = udev_device_get_seqnum(udev_dev);
	sid_res_log_debug(ubridge_res, "Received event on udev monitor with seqno %" PRIu64, seqnum);

	if (!(worker_id = udev_device_get_property_value(udev_dev, KV_KEY_UDEV_SID_SESSION_ID))) {
		sid_res_log_error(ubridge_res,
		                  "Failed to get value of %s variable in received uevent with seqno %" PRIu64,
		                  KV_KEY_UDEV_SID_SESSION_ID,
		                  udev_device_get_seqnum(udev_dev));
		goto out;
	}

	if (!(worker_control_res = sid_res_search(ubridge->internal_res, SID_RES_SEARCH_IMM_DESC, &sid_res_type_wrk_ctl, NULL))) {
		sid_res_log_error(ubridge_res, SID_INTERNAL_ERROR "%s: Failed to find worker control resource.", __func__);
		goto out;
	}

	if (!(worker_proxy_res = sid_wrk_ctl_find_worker(worker_control_res, worker_id))) {
		sid_res_log_error(ubridge_res, SID_INTERNAL_ERROR "%s: Failed to find worker with id %s.", __func__, worker_id);
		goto out;
	}

	sid_res_log_debug(worker_proxy_res, "Matched worker for event with seqno %" PRIu64, seqnum);

	int_msg = (struct internal_msg_header) {
		.cat    = MSG_CATEGORY_SYSTEM,
		.header = (struct sid_ifc_msg_header) {.status = 0, .prot = 0, .cmd = SYSTEM_CMD_UMONITOR, .flags = 0}};

	data_spec.data      = &int_msg;
	data_spec.data_size = INTERNAL_MSG_HEADER_SIZE;
	data_spec.ext.used  = false;

	if ((r = sid_wrk_ctl_chan_send(worker_proxy_res, MAIN_WORKER_CHANNEL_ID, &data_spec)) < 0)
		sid_res_log_error_errno(ubridge_res, r, "Failed to notify worker about UDEV event with seqno %" PRIu64, seqnum);
out:
	if (udev_dev)
		udev_device_unref(udev_dev);
	return r;
}

static void _destroy_ulink(sid_res_t *ubridge_res, struct ulink *ulink)
{
	if (!ulink->udev)
		return;

	if (ulink->mon) {
		udev_monitor_unref(ulink->mon);
		ulink->mon = NULL;
	}

	udev_unref(ulink->udev);
	ulink->udev = NULL;
}

static int _set_up_ubridge_socket(sid_res_t *ubridge_res, int *ubridge_socket_fd)
{
	char *val;
	int   fd;

	if (sid_srv_lnk_fd_activation_present(1)) {
		if (!(val = getenv(SID_SRV_LNK_KEY_ACTIVATION_TYPE))) {
			sid_res_log_error(ubridge_res, "Missing %s key in environment.", SID_SRV_LNK_KEY_ACTIVATION_TYPE);
			return -ENOKEY;
		}

		if (strcmp(val, SID_SRV_LNK_VAL_ACTIVATION_FD)) {
			sid_res_log_error(ubridge_res, "Incorrect value for key %s: %s.", SID_SRV_LNK_VAL_ACTIVATION_FD, val);
			return -EINVAL;
		}

		/* The very first FD passed in is the one we are interested in. */
		fd = SID_SRV_LNK_FD_ACTIVATION_FDS_START;

		if (!(sid_srv_lnk_fd_is_socket_unix(fd, SOCK_STREAM, 1, SID_IFC_SOCKET_PATH, SID_IFC_SOCKET_PATH_LEN))) {
			sid_res_log_error(ubridge_res, "Passed file descriptor is of incorrect type.");
			return -EINVAL;
		}
	} else {
		/* No systemd autoactivation - create new socket FD. */
		if ((fd = sid_comms_unix_create(SID_IFC_SOCKET_PATH,
		                                SID_IFC_SOCKET_PATH_LEN,
		                                SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC)) < 0) {
			sid_res_log_error_errno(ubridge_res, fd, "Failed to create local server socket");
			return fd;
		}
	}

	*ubridge_socket_fd = fd;
	return 0;
}

static int _set_up_kv_store_generation(struct sid_ucmd_common_ctx *ctx)
{
	kv_vector_t         vvalue[VVALUE_SINGLE_ALIGNED_CNT];
	sid_ucmd_kv_flags_t flags = value_flags_no_sync | SID_KV_FL_ALIGN;
	const char         *key;
	kv_scalar_t        *svalue;

	if (!(key = _compose_key(ctx->gen_buf,
	                         &((struct kv_key_spec) {.extra_op = NULL,
	                                                 .op       = KV_OP_SET,
	                                                 .dom      = ID_NULL,
	                                                 .ns       = SID_KV_NS_GLOBAL,
	                                                 .ns_part  = ID_NULL,
	                                                 .id_cat   = ID_NULL,
	                                                 .id       = ID_NULL,
	                                                 .core     = KV_KEY_DB_GENERATION}))))
		return -1;

	if ((svalue = sid_kvs_get(ctx->kvs_res, key, NULL, NULL))) {
		memcpy(&ctx->gennum, svalue->data + _svalue_ext_data_offset(svalue), sizeof(uint16_t));
		ctx->gennum++;
	} else
		ctx->gennum = 1;

	sid_res_log_debug(ctx->res, "Current generation number: %" PRIu16, ctx->gennum);

	_vvalue_header_prep(vvalue, VVALUE_CNT(vvalue), &null_int, &flags, &ctx->gennum, core_owner);
	_vvalue_data_prep(vvalue, VVALUE_CNT(vvalue), 0, &ctx->gennum, sizeof(ctx->gennum));

	sid_kvs_set(ctx->kvs_res, key, vvalue, VVALUE_SINGLE_ALIGNED_CNT, SID_KVS_VAL_FL_VECTOR, SID_KVS_VAL_OP_MERGE, NULL, NULL);

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
	                                                 .ns       = SID_KV_NS_GLOBAL,
	                                                 .ns_part  = ID_NULL,
	                                                 .id_cat   = ID_NULL,
	                                                 .id       = ID_NULL,
	                                                 .core     = KV_KEY_BOOT_ID}))))
		return -1;

	if ((svalue = sid_kvs_get(ctx->kvs_res, key, NULL, NULL)))
		old_boot_id = svalue->data + _svalue_ext_data_offset(svalue);
	else
		old_boot_id = NULL;

	if (!(util_uuid_get_boot_id(&(util_mem_t) {.base = boot_id, .size = sizeof(boot_id)}, &r)))
		return r;

	if (old_boot_id)
		sid_res_log_debug(ctx->res, "Previous system boot id: %s.", old_boot_id);

	sid_res_log_debug(ctx->res, "Current system boot id: %s.", boot_id);

	_vvalue_header_prep(vvalue, VVALUE_CNT(vvalue), &null_int, &value_flags_no_sync, &ctx->gennum, core_owner);
	_vvalue_data_prep(vvalue, VVALUE_CNT(vvalue), 0, boot_id, sizeof(boot_id));

	sid_kvs_set(ctx->kvs_res, key, vvalue, VVALUE_IDX_DATA + 1, SID_KVS_VAL_FL_VECTOR, SID_KVS_VAL_OP_MERGE, NULL, NULL);

	_destroy_key(ctx->gen_buf, key);
	return 0;
}

static int _ulink_import(sid_res_t *ubridge_res, struct sid_ucmd_common_ctx *common_ctx, struct ulink *ulink)
{
	struct sid_ucmd_ctx     ucmd_ctx = {0}; /* dummy context so we can still use _handle_dev_for_group */
	struct udev_enumerate  *udev_enum;
	struct udev_list_entry *udev_entry;
	const char             *udev_name;
	struct udev_device     *udev_dev;
	const char             *dev_id, *dev_seq, *dev_name;
	dev_t                   dev_num;
	char                    devno_buf[16];
	int                     r;

	ucmd_ctx.common = common_ctx;

	if (!(udev_enum = udev_enumerate_new(ulink->udev))) {
		sid_res_log_error(ubridge_res, "Failed to create udev device enumerator.");
		return -1;
	}

	if ((udev_enumerate_add_match_tag(udev_enum, UDEV_TAG_SID) < 0) || (udev_enumerate_scan_devices(udev_enum) < 0)) {
		sid_res_log_error(ubridge_res, "Failed to create udev device enumerator filter.");
		return -1;
	}

	r = 0;
	udev_list_entry_foreach(udev_entry, udev_enumerate_get_list_entry(udev_enum))
	{
		udev_name = udev_list_entry_get_name(udev_entry);

		if (!(udev_dev = udev_device_new_from_syspath(ulink->udev, udev_name))) {
			sid_res_log_error(ubridge_res, "Failed to get udev device structure for %s.", udev_name);
			continue;
		}

		if (!(dev_id = udev_device_get_property_value(udev_dev, KV_KEY_UDEV_SID_DEV_ID)) ||
		    !(dev_seq = udev_device_get_property_value(udev_dev, UDEV_KEY_DISKSEQ)) ||
		    !(dev_name = udev_device_get_sysname(udev_dev))) {
			sid_res_log_error(ubridge_res, "Failed to get udev property values for %s.", udev_name);
			udev_device_unref(udev_dev);
			continue;
		}

		dev_num = udev_device_get_devnum(udev_dev);

		if (snprintf(devno_buf, sizeof(devno_buf), "%u_%u", major(dev_num), minor(dev_num)) < 0) {
			sid_res_log_error(ubridge_res, "Failed to construct device number string for %s.", udev_name);
			udev_device_unref(udev_dev);
			continue;
		}

		ucmd_ctx.req_env.dev.num_s     = devno_buf;
		ucmd_ctx.req_env.dev.uid_s     = (char *) dev_id;
		ucmd_ctx.req_env.dev.dsq_s     = (char *) dev_seq;
		ucmd_ctx.req_env.dev.udev.name = dev_name;
		ucmd_ctx.scan.dev_ready        = SID_DEV_RDY_UNDEFINED;
		ucmd_ctx.scan.dev_reserved     = SID_DEV_RES_UNDEFINED;

		sid_res_log_debug(ubridge_res,
		                  "Found udev db record tagged with " UDEV_TAG_SID ". Importing id=%s, dseq=%s, devno=%s, name=%s.",
		                  dev_id,
		                  dev_seq,
		                  devno_buf,
		                  dev_name);

		r = _set_new_dev_kvs(ubridge_res, &ucmd_ctx, true);
		udev_device_unref(udev_dev);

		if (r < 0)
			break;
	}

	udev_enumerate_unref(udev_enum);
	return r;
}

static int _set_up_ulink(sid_res_t *ubridge_res, struct sid_ucmd_common_ctx *common_ctx, struct ulink *ulink)
{
	int               umonitor_fd = -1;
	sid_res_ev_src_t *umonitor_es;

	if (!(ulink->udev = udev_new())) {
		sid_res_log_error(ubridge_res, "Failed to create udev handle.");
		goto fail;
	}

	if (!(ulink->mon = udev_monitor_new_from_netlink(ulink->udev, "udev"))) {
		sid_res_log_error(ubridge_res, "Failed to create udev monitor.");
		goto fail;
	}

	if (udev_monitor_filter_add_match_tag(ulink->mon, UDEV_TAG_SID) < 0) {
		sid_res_log_error(ubridge_res, "Failed to create tag filter.");
		goto fail;
	}

	umonitor_fd = udev_monitor_get_fd(ulink->mon);

	if (sid_res_ev_create_io(ubridge_res,
	                         &umonitor_es,
	                         umonitor_fd,
	                         _on_ubridge_umonitor_event,
	                         0,
	                         "udev monitor",
	                         ubridge_res) < 0) {
		sid_res_log_error(ubridge_res, "Failed to register udev monitoring.");
		goto fail;
	}

	if (_ulink_import(ubridge_res, common_ctx, ulink) < 0) {
		sid_res_log_error(ubridge_res, "Failed to import records from udev database.");
		goto fail;
	}

	if (udev_monitor_enable_receiving(ulink->mon) < 0) {
		sid_res_log_error(ubridge_res, "Failed to enable udev monitoring.");
		goto fail;
	}

	return 0;
fail:
	_destroy_ulink(ubridge_res, ulink);
	return -1;
}

static struct sid_mod_sym_params block_symbol_params[] = {{
								  SID_UCMD_MOD_FN_NAME_SCAN_A_INIT,
								  SID_MOD_SYM_FL_INDIRECT,
							  },
                                                          {
								  SID_UCMD_MOD_FN_NAME_SCAN_PRE,
								  SID_MOD_SYM_FL_INDIRECT,
							  },
                                                          {
								  SID_UCMD_MOD_FN_NAME_SCAN_CURRENT,
								  SID_MOD_SYM_FL_INDIRECT,
							  },
                                                          {
								  SID_UCMD_MOD_FN_NAME_SCAN_NEXT,
								  SID_MOD_SYM_FL_INDIRECT,
							  },
                                                          {
								  SID_UCMD_MOD_FN_NAME_SCAN_POST_CURRENT,
								  SID_MOD_SYM_FL_INDIRECT,
							  },
                                                          {
								  SID_UCMD_MOD_FN_NAME_SCAN_POST_NEXT,
								  SID_MOD_SYM_FL_INDIRECT,
							  },
                                                          {
								  SID_UCMD_MOD_FN_NAME_SCAN_A_EXIT,
								  SID_MOD_SYM_FL_INDIRECT,
							  },
                                                          {
								  SID_UCMD_MOD_FN_NAME_SCAN_REMOVE_INIT,
								  SID_MOD_SYM_FL_INDIRECT,
							  },
                                                          {
								  SID_UCMD_MOD_FN_NAME_SCAN_REMOVE,
								  SID_MOD_SYM_FL_INDIRECT,
							  },
                                                          {
								  SID_UCMD_MOD_FN_NAME_SCAN_REMOVE_EXIT,
								  SID_MOD_SYM_FL_INDIRECT,
							  },
                                                          {
								  SID_UCMD_MOD_FN_NAME_SCAN_B_INIT,
								  SID_MOD_SYM_FL_INDIRECT,
							  },
                                                          {
								  SID_UCMD_MOD_FN_NAME_SCAN_ACTION_CURRENT,
								  SID_MOD_SYM_FL_INDIRECT,
							  },
                                                          {
								  SID_UCMD_MOD_FN_NAME_SCAN_ACTION_NEXT,
								  SID_MOD_SYM_FL_INDIRECT,
							  },
                                                          {
								  SID_UCMD_MOD_FN_NAME_SCAN_B_EXIT,
								  SID_MOD_SYM_FL_INDIRECT,
							  },
                                                          {
								  SID_UCMD_MOD_FN_NAME_SCAN_ERROR,
								  SID_MOD_SYM_FL_FAIL_ON_MISSING | SID_MOD_SYM_FL_INDIRECT,
							  },
                                                          SID_MOD_NULL_SYM_PARAMS};

static struct sid_mod_sym_params type_symbol_params[]  = {

        {
                SID_UCMD_MOD_FN_NAME_SCAN_A_INIT,
                SID_MOD_SYM_FL_FAIL_ON_MISSING | SID_MOD_SYM_FL_INDIRECT,
        },
        {
                SID_UCMD_MOD_FN_NAME_SCAN_PRE,
                SID_MOD_SYM_FL_INDIRECT,
        },
        {
                SID_UCMD_MOD_FN_NAME_SCAN_CURRENT,
                SID_MOD_SYM_FL_INDIRECT,
        },
        {
                SID_UCMD_MOD_FN_NAME_SCAN_NEXT,
                SID_MOD_SYM_FL_INDIRECT,
        },
        {
                SID_UCMD_MOD_FN_NAME_SCAN_POST_CURRENT,
                SID_MOD_SYM_FL_INDIRECT,
        },
        {
                SID_UCMD_MOD_FN_NAME_SCAN_POST_NEXT,
                SID_MOD_SYM_FL_INDIRECT,
        },
        {
                SID_UCMD_MOD_FN_NAME_SCAN_A_EXIT,
                SID_MOD_SYM_FL_INDIRECT,
        },

        {
                SID_UCMD_MOD_FN_NAME_SCAN_REMOVE_INIT,
                SID_MOD_SYM_FL_INDIRECT,
        },

        {
                SID_UCMD_MOD_FN_NAME_SCAN_REMOVE,
                SID_MOD_SYM_FL_INDIRECT,
        },
        {
                SID_UCMD_MOD_FN_NAME_SCAN_REMOVE_EXIT,
                SID_MOD_SYM_FL_INDIRECT,
        },
        {
                SID_UCMD_MOD_FN_NAME_SCAN_B_INIT,
                SID_MOD_SYM_FL_INDIRECT,
        },

        {
                SID_UCMD_MOD_FN_NAME_SCAN_ACTION_CURRENT,
                SID_MOD_SYM_FL_INDIRECT,
        },
        {
                SID_UCMD_MOD_FN_NAME_SCAN_ACTION_NEXT,
                SID_MOD_SYM_FL_INDIRECT,
        },
        {
                SID_UCMD_MOD_FN_NAME_SCAN_B_EXIT,
                SID_MOD_SYM_FL_INDIRECT,
        },

        {
                SID_UCMD_MOD_FN_NAME_SCAN_ERROR,
                SID_MOD_SYM_FL_FAIL_ON_MISSING | SID_MOD_SYM_FL_INDIRECT,
        },
        SID_MOD_NULL_SYM_PARAMS};

static const struct sid_kvs_res_params main_kv_store_res_params = {.backend = SID_KVS_BACKEND_BPTREE, .bptree.order = 4};

static int _init_common(sid_res_t *res, const void *kickstart_data, void **data)
{
	struct sid_ucmd_common_ctx *common_ctx;
	int                         r;

	if (!(common_ctx = mem_zalloc(sizeof(struct sid_ucmd_common_ctx)))) {
		sid_res_log_error(res, "Failed to allocate memory for common structure.");
		goto fail;
	}
	common_ctx->res = res;

	/*
	 * Set higher priority to kv_store_res compared to modules so they can
	 * still use the KV store even when destroying the whole resource tree.
	 */
	if (!(common_ctx->kvs_res = sid_res_create(common_ctx->res,
	                                           &sid_res_type_kvs,
	                                           SID_RES_FL_RESTRICT_WALK_UP | SID_RES_FL_DISALLOW_ISOLATION,
	                                           MAIN_KV_STORE_NAME,
	                                           &main_kv_store_res_params,
	                                           SID_RES_PRIO_NORMAL - 1,
	                                           SID_RES_NO_SERVICE_LINKS))) {
		sid_res_log_error(res, "Failed to create main key-value store.");
		goto fail;
	}

	if (!(common_ctx->gen_buf = sid_buf_create(&SID_BUF_SPEC(), &SID_BUF_INIT(.alloc_step = PATH_MAX), &r))) {
		sid_res_log_error_errno(res, r, "Failed to create generic buffer");
		goto fail;
	}

	_load_kv_store(res, common_ctx);
	if (_set_up_kv_store_generation(common_ctx) < 0 || _set_up_boot_id(common_ctx) < 0)
		goto fail;

	struct sid_mod_reg_res_params block_res_mod_params = {
		.directory     = SID_UCMD_BLOCK_MOD_DIR,
		.module_prefix = NULL,
		.module_suffix = ".so",
		.flags         = 0,
		.symbol_params = block_symbol_params,
		.cb_arg        = common_ctx,
	};

	struct sid_mod_reg_res_params type_res_mod_params = {
		.directory     = SID_UCMD_TYPE_MOD_DIR,
		.module_prefix = NULL,
		.module_suffix = ".so",
		.flags         = 0,
		.symbol_params = type_symbol_params,
		.cb_arg        = common_ctx,
	};

	if (!(common_ctx->block_mod_reg_res = sid_res_create(common_ctx->res,
	                                                     &sid_res_type_mod_reg,
	                                                     SID_RES_FL_RESTRICT_WALK_UP | SID_RES_FL_DISALLOW_ISOLATION,
	                                                     MODULES_BLOCK_ID,
	                                                     &block_res_mod_params,
	                                                     SID_RES_PRIO_NORMAL,
	                                                     SID_RES_NO_SERVICE_LINKS))) {
		sid_res_log_error(res, "Failed to create type module registry.");
		goto fail;
	}

	if (!(common_ctx->type_mod_reg_res = sid_res_create(common_ctx->res,
	                                                    &sid_res_type_mod_reg,
	                                                    SID_RES_FL_RESTRICT_WALK_UP | SID_RES_FL_DISALLOW_ISOLATION,
	                                                    MODULES_TYPE_ID,
	                                                    &type_res_mod_params,
	                                                    SID_RES_PRIO_NORMAL,
	                                                    SID_RES_NO_SERVICE_LINKS))) {
		sid_res_log_error(res, "Failed to create block module registry.");
		goto fail;
	}

	if ((r = sid_mod_reg_load_mods(common_ctx->block_mod_reg_res)) < 0) {
		if (r == -ENOENT)
			sid_res_log_debug(res, "Block module directory %s not present.", SID_UCMD_BLOCK_MOD_DIR);
		else if (r == -ENOMEDIUM)
			sid_res_log_debug(res, "Block module directory %s empty.", SID_UCMD_BLOCK_MOD_DIR);
		else {
			sid_res_log_error(res, "Failed to preload block modules.");
			goto fail;
		}
	}

	if ((r = sid_mod_reg_load_mods(common_ctx->type_mod_reg_res)) < 0) {
		if (r == -ENOENT)
			sid_res_log_debug(res, "Type module directory %s not present.", SID_UCMD_TYPE_MOD_DIR);
		else if (r == -ENOMEDIUM)
			sid_res_log_debug(res, "Type module directory %s empty.", SID_UCMD_TYPE_MOD_DIR);
		else {
			sid_res_log_error(res, "Failed to preload type modules.");
			goto fail;
		}
	}

	*data = common_ctx;
	return 0;
fail:
	if (common_ctx) {
		if (common_ctx->gen_buf)
			sid_buf_destroy(common_ctx->gen_buf);
		free(common_ctx);
	}

	return -1;
}

static int _destroy_common(sid_res_t *res)
{
	struct sid_ucmd_common_ctx *common_ctx = sid_res_get_data(res);

	sid_buf_destroy(common_ctx->gen_buf);
	free(common_ctx);

	return 0;
}

static int _init_ubridge(sid_res_t *res, const void *kickstart_data, void **data)
{
	struct ubridge             *ubridge = NULL;
	sid_res_ev_src_t           *ubridge_es;
	sid_res_t                  *common_res;
	struct sid_ucmd_common_ctx *common_ctx = NULL;

	if (!(ubridge = mem_zalloc(sizeof(struct ubridge)))) {
		sid_res_log_error(res, "Failed to allocate memory for ubridge structure.");
		goto fail;
	}
	ubridge->socket_fd = -1;

	if (!(ubridge->internal_res = sid_res_create(res,
	                                             &sid_res_type_aggr,
	                                             SID_RES_FL_RESTRICT_WALK_DOWN | SID_RES_FL_DISALLOW_ISOLATION,
	                                             INTERNAL_AGGREGATE_ID,
	                                             ubridge,
	                                             SID_RES_PRIO_NORMAL,
	                                             SID_RES_NO_SERVICE_LINKS))) {
		sid_res_log_error(res, "Failed to create internal ubridge resource.");
		goto fail;
	}

	if (!(common_res = sid_res_create(ubridge->internal_res,
	                                  &sid_res_type_ubr_cmn,
	                                  SID_RES_FL_NONE,
	                                  COMMON_ID,
	                                  common_ctx,
	                                  SID_RES_PRIO_NORMAL,
	                                  SID_RES_NO_SERVICE_LINKS))) {
		sid_res_log_error(res, "Failed to create ubridge common resource.");
		goto fail;
	}
	common_ctx                                              = sid_res_get_data(common_res);

	struct sid_wrk_ctl_res_params worker_control_res_params = {
		.worker_type = SID_WRK_TYPE_INTERNAL,

		.init_cb_spec =
			(struct sid_wrk_init_cb_spec) {
				.fn  = _worker_init_fn,
				.arg = common_ctx,
			},

		.channel_specs = (struct sid_wrk_chan_spec[]) {
			{
				.id = MAIN_WORKER_CHANNEL_ID,

				.wire =
					(struct sid_wrk_wire_spec) {
						.type = SID_WRK_WIRE_SOCKET,
					},

				.worker_rx =
					(struct sid_wrk_lane_spec) {
						.cb =
							(struct sid_wrk_lane_cb_spec) {
								.fn  = _worker_recv_fn,
								.arg = common_ctx,
							},
					},

				.proxy_rx =
					(struct sid_wrk_lane_spec) {
						.cb =
							(struct sid_wrk_lane_cb_spec) {
								.fn  = _worker_proxy_recv_fn,
								.arg = common_ctx,
							},
					},
			},
			SID_WRK_NULL_CHAN_SPEC,
		}};

	if (!sid_res_create(ubridge->internal_res,
	                    &sid_res_type_wrk_ctl,
	                    SID_RES_FL_NONE,
	                    SID_RES_NO_CUSTOM_ID,
	                    &worker_control_res_params,
	                    SID_RES_PRIO_NORMAL,
	                    SID_RES_NO_SERVICE_LINKS)) {
		sid_res_log_error(res, "Failed to create worker control.");
		goto fail;
	}

	if (_set_up_ubridge_socket(res, &ubridge->socket_fd) < 0) {
		sid_res_log_error(res, "Failed to set up local server socket.");
		goto fail;
	}

	if (sid_res_ev_create_io(res,
	                         &ubridge_es,
	                         ubridge->socket_fd,
	                         _on_ubridge_interface_event,
	                         0,
	                         sid_res_type_ubr.name,
	                         res)) {
		sid_res_log_error(res, "Failed to register interface with event loop.");
		goto fail;
	}

	if (_set_up_ulink(res, common_ctx, &ubridge->ulink) < 0) {
		sid_res_log_error(res, "Failed to set up udev link.");
		goto fail;
	}

	/*
	sid_res_ev_time_create(res,
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
	 * Call sid_util_kernel_cmdline_arg_get here to only read the kernel command
	 * line so we already have that preloaded for any possible workers.
	 */
	(void) sid_util_kernel_get_arg("root", NULL, NULL);

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

static int _destroy_ubridge(sid_res_t *res)
{
	struct ubridge *ubridge = sid_res_get_data(res);

	_destroy_ulink(res, &ubridge->ulink);

	if (ubridge->socket_fd != -1)
		(void) close(ubridge->socket_fd);

	free(ubridge);
	return 0;
}

const sid_res_type_t sid_res_type_ubr_cmd = {
	.name        = "command",
	.short_name  = "cmd",
	.description = "Internal resource representing single request (command) on ubridge interface.",
	.init        = _init_command,
	.destroy     = _destroy_command,
};

const sid_res_type_t sid_res_type_ubr_con = {
	.name        = "connection",
	.short_name  = "con",
	.description = "Internal resource representing single ubridge connection to handle requests.",
	.init        = _init_connection,
	.destroy     = _destroy_connection,
};

const sid_res_type_t sid_res_type_ubr_cmn = {
	.name        = "common",
	.short_name  = "cmn",
	.description = "Internal resource representing common subtree used in both main and worker process.",
	.init        = _init_common,
	.destroy     = _destroy_common,
};

const sid_res_type_t sid_res_type_ubr = {
	.name        = "ubridge",
	.short_name  = "ubr",
	.description = "Resource primarily providing bridge interface between udev and SID. ",
	.init        = _init_ubridge,
	.destroy     = _destroy_ubridge,
};
