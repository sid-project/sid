/*
 * SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _SID_RES_H
#define _SID_RES_H

#include "base/buf.h"
#include "iface/srv-lnk.h"
#include "internal/fmt.h"

#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sid_res sid_res_t;

typedef struct sid_res_type {
	const char *name;
	const char *short_name;
	const char *description;
	const char *log_prefix;
	int (*init)(sid_res_t *res, const void *kickstart_data, void **data);
	int (*destroy)(sid_res_t *res);
	unsigned int with_event_loop:1;
	unsigned int with_watchdog  :1;
} sid_res_type_t;

#include "res-type-regs.h"

/*
 * create/destroy functions and related types
 */
#define SID_RES_FL_NONE               UINT64_C(0x0000000000000000)
#define SID_RES_FL_RESTRICT_WALK_UP   UINT64_C(0x0000000000000001) /* restrict walk from child to parent */
#define SID_RES_FL_RESTRICT_WALK_DOWN UINT64_C(0x0000000000000002) /* restrict walk from parent to child */
#define SID_RES_FL_RESTRICT_MASK      UINT64_C(0x0000000000000003)
#define SID_RES_FL_DISALLOW_ISOLATION UINT64_C(0x0000000000000004)

typedef uint64_t sid_res_flags_t;

#define SID_RES_NO_PARENT          NULL
#define SID_RES_NO_CUSTOM_ID       NULL
#define SID_RES_NO_PARAMS          NULL
#define SID_RES_NO_SERVICE_LINKS   NULL
#define SID_RES_PRIO_NORMAL        0

#define SID_RES_UNLIMITED_EV_COUNT UINT64_MAX

typedef struct sid_res_srv_lnk_def {
	const char         *name;
	sid_srv_lnk_type_t  type;
	sid_srv_lnk_notif_t notification;
	sid_srv_lnk_fl_t    flags;
	void               *data;
} sid_res_srv_lnk_def_t;

#define SID_NULL_SRV_LNK                                                                                                           \
	((sid_res_srv_lnk_def_t) {.name = NULL, .type = SID_SRV_LNK_TYPE_NONE, .notification = SID_SRV_LNK_NOTIF_NONE})

/* Note: service_link_defs[] array must always be terminated by NULL_SERVICE_LINK */
sid_res_t *sid_res_create(sid_res_t            *parent_res,
                          const sid_res_type_t *type,
                          sid_res_flags_t       flags,
                          const char           *id,
                          const void           *kickstart_data,
                          int64_t               prio,
                          sid_res_srv_lnk_def_t service_link_defs[]);

/*
 * reference counting support
 */
sid_res_t *sid_res_ref(sid_res_t *res);
int        sid_res_unref(sid_res_t *res);

/*
 * basic property get/set functions
 */
void *sid_res_get_data(sid_res_t *res);

const char *sid_res_get_full_id(sid_res_t *res);
const char *sid_res_get_id(sid_res_t *res);

int     sid_res_set_prio(sid_res_t *res, int64_t prio);
int64_t sid_res_get_prio(sid_res_t *res);

#define ID(res) sid_res_get_full_id(res)

/*
 * structure/tree iterator and 'get' functions and types
 */
typedef struct sid_res_iter sid_res_iter_t;

sid_res_iter_t *sid_res_iter_create(sid_res_t *res);
sid_res_t      *sid_res_iter_current(sid_res_iter_t *iter);
sid_res_t      *sid_res_iter_next(sid_res_iter_t *iter);
sid_res_t      *sid_res_iter_previous(sid_res_iter_t *iter);
void            sid_res_iter_reset(sid_res_iter_t *iter);
void            sid_res_iter_destroy(sid_res_iter_t *iter);

typedef enum {
	/* Descendant search methods */

	_SID_RES_SEARCH_DESC_START, /* internal use */
	SID_RES_SEARCH_IMM_DESC,    /* only immediate descendants - children */
	SID_RES_SEARCH_DFS,         /* depth first search */
	SID_RES_SEARCH_WIDE_DFS,    /* IMM_DESC + DFS hybrid (DFS, but process all immediate children first before going deeper) */
	_SID_RES_SEARCH_DESC_END,   /* internal use */

	/* Ancestor search methods */

	_SID_RES_SEARCH_ANC_START, /* internal use */
	SID_RES_SEARCH_IMM_ANC,    /* only immediate ancestor - parent */
	SID_RES_SEARCH_ANC,        /* any ancestor that matches */
	SID_RES_SEARCH_TOP,        /* topmost ancestor */
	_SID_RES_SEARCH_ANC_END,   /* internal use */

	/* Compound search methods */

	_SID_RES_SEARCH_COMP_START, /* internal use */
	SID_RES_SEARCH_GENUS,       /* TOP + WIDE_DFS hybrid (go to topmost ancestor first, then search through all descendandts) */
	SID_RES_SEARCH_SIB,         /* IMM_ANC + IMM_DESC (go to parent first, then search through all its children) */
	_SID_RES_SEARCH_COMP_END,   /* internal use */

} sid_res_search_t;

bool       sid_res_match(sid_res_t *res, const sid_res_type_t *type, const char *id);
sid_res_t *sid_res_search(sid_res_t *start_res, sid_res_search_t method, const sid_res_type_t *type, const char *id);
bool       sid_res_search_match(sid_res_t *start_res, sid_res_search_t method, const sid_res_type_t *type, const char *id);
bool       sid_res_search_match_res(sid_res_t *start_res, sid_res_search_t method, sid_res_t *res);

/*
 * structure/tree modification functions
 */
#define SID_RES_ISOL_FL_NONE               UINT32_C(0x00000000)
#define SID_RES_ISOL_FL_SUBTREE            UINT32_C(0x00000001)
#define SID_RES_ISOL_FL_KEEP_SERVICE_LINKS UINT32_C(0x00000002)

typedef uint32_t sid_res_isol_fl_t;

int sid_res_add_child(sid_res_t *res, sid_res_t *child, sid_res_flags_t flags);
int sid_res_isolate(sid_res_t *res, sid_res_isol_fl_t flags);

/*
 * event loop and event handling functions and types
 */
typedef struct sid_res_ev_src sid_res_ev_src_t;

typedef int (*sid_res_ev_io_handler)(sid_res_ev_src_t *es, int fd, uint32_t revents, void *data);
typedef int (*sid_res_ev_signal_handler)(sid_res_ev_src_t *es, const struct signalfd_siginfo *si, void *data);
typedef int (*sid_res_ev_child_handler)(sid_res_ev_src_t *es, const siginfo_t *si, void *data);
typedef int (*sid_res_ev_time_handler)(sid_res_ev_src_t *es, uint64_t usec, void *data);
typedef int (*sid_res_ev_generic_handler)(sid_res_ev_src_t *es, void *data);

typedef enum {
	SID_RES_POS_ABS,
	SID_RES_POS_REL,
} sid_res_pos_t;

int sid_res_ev_create_io(sid_res_t            *res,
                         sid_res_ev_src_t    **es,
                         int                   fd,
                         sid_res_ev_io_handler handler,
                         int64_t               prio,
                         const char           *name,
                         void                 *data);

int sid_res_ev_create_signal(sid_res_t                *res,
                             sid_res_ev_src_t        **es,
                             sigset_t                  mask,
                             sid_res_ev_signal_handler handler,
                             int64_t                   prio,
                             const char               *name,
                             void                     *data);

int sid_res_ev_create_child(sid_res_t               *res,
                            sid_res_ev_src_t       **es,
                            pid_t                    pid,
                            int                      options,
                            sid_res_ev_child_handler handler,
                            int64_t                  prio,
                            const char              *name,
                            void                    *data);

int sid_res_ev_create_time(sid_res_t              *res,
                           sid_res_ev_src_t      **es,
                           clockid_t               clock,
                           sid_res_pos_t           disposition,
                           uint64_t                usec,
                           uint64_t                accuracy,
                           sid_res_ev_time_handler handler,
                           int64_t                 prio,
                           const char             *name,
                           void                   *data);

int sid_res_ev_rearm_time(sid_res_ev_src_t *es, sid_res_pos_t disposition, uint64_t usec);

int sid_res_ev_create_deferred(sid_res_t                 *res,
                               sid_res_ev_src_t         **es,
                               sid_res_ev_generic_handler handler,
                               int64_t                    prio,
                               const char                *name,
                               void                      *data);

int sid_res_ev_create_post(sid_res_t                 *res,
                           sid_res_ev_src_t         **es,
                           sid_res_ev_generic_handler handler,
                           int64_t                    prio,
                           const char                *name,
                           void                      *data);

int sid_res_ev_create_exit(sid_res_t                 *res,
                           sid_res_ev_src_t         **es,
                           sid_res_ev_generic_handler handler,
                           int64_t                    prio,
                           const char                *name,
                           void                      *data);

int sid_res_ev_set_counter(sid_res_ev_src_t *es, sid_res_pos_t disposition, uint64_t events_max);
int sid_res_ev_get_counter(sid_res_ev_src_t *es, uint64_t *events_fired, uint64_t *events_max);

int sid_res_ev_set_exit_on_failure(sid_res_ev_src_t *es, bool exit_on_failure);
int sid_res_ev_get_exit_on_failure(sid_res_ev_src_t *es);

int sid_res_ev_destroy(sid_res_ev_src_t **es);

int sid_res_ev_loop_run(sid_res_t *res);
int sid_res_ev_loop_exit(sid_res_t *res);

/*
 * logging
 */
void sid_res_log_output(sid_res_t *res, const sid_log_req_t *log_req, const char *fmt, ...);

#define SID_RES_LOG_LINE(res, l, e, ...)                                                                                           \
	sid_res_log_output(res,                                                                                                    \
	                   &((sid_log_req_t) {.pfx = NULL,                                                                         \
	                                      .ctx = &((sid_log_ctx_t) {.level_id = l,                                             \
	                                                                .errno_id = e,                                             \
	                                                                .src_file = __FILE__,                                      \
	                                                                .src_line = __LINE__,                                      \
	                                                                .src_func = __func__})}),                                  \
	                   __VA_ARGS__)

#define sid_res_log_debug(res, ...)           SID_RES_LOG_LINE(res, LOG_DEBUG, 0, __VA_ARGS__)
#define sid_res_log_info(res, ...)            SID_RES_LOG_LINE(res, LOG_INFO, 0, __VA_ARGS__)
#define sid_res_log_notice(res, ...)          SID_RES_LOG_LINE(res, LOG_NOTICE, 0, __VA_ARGS__)
#define sid_res_log_warning(res, ...)         SID_RES_LOG_LINE(res, LOG_WARNING, 0, __VA_ARGS__)
#define sid_res_log_error(res, ...)           SID_RES_LOG_LINE(res, LOG_ERR, 0, __VA_ARGS__)
#define sid_res_log_print(res, ...)           SID_RES_LOG_LINE(res, SID_LOG_PRINT, 0, __VA_ARGS__)
#define sid_res_log_error_errno(res, e, ...)  SID_RES_LOG_LINE(res, LOG_DEBUG, e, __VA_ARGS__)
#define sid_res_log_sys_error(res, x, y, ...) sid_res_log_error_errno(res, errno, "%s%s%s failed", y, *y ? ": " : "", x)

/*
 * miscellanous functions
 */
int sid_res_tree_write(sid_res_t *res, fmt_output_t format, struct sid_buf *outbuf, int level, bool add_comma);

#ifdef __cplusplus
}
#endif

#endif
