/*
 * This file is part of SID.
 *
 * Copyright (C) 2019 Red Hat, Inc. All rights reserved.
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

#ifndef _SID_SERVICE_LINK_IFACE_H
#define _SID_SERVICE_LINK_IFACE_H

#include "log/log.h"

#include <systemd/sd-daemon.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	SID_SRV_LNK_TYPE_NONE,
	SID_SRV_LNK_TYPE_SYSTEMD,
	SID_SRV_LNK_TYPE_LOGGER,
} sid_srv_lnk_type_t;

typedef enum {
	/* no notification */
	SID_SRV_LNK_NOTIF_NONE             = UINT64_C(0x0000000000000000),

	/* discard any further service notifications; no arg */
	SID_SRV_LNK_NOTIF_UNSET            = UINT64_C(0x0000000000000001),

	/* notify about service status; arg is STATUS=<message> */
	SID_SRV_LNK_NOTIF_STATUS           = UINT64_C(0x0000000000000002),

	/* notify about service reaching an error with errno; arg is 'ERRNO=<errno>' or 'ERRNO=<errno_identifier>' */
	SID_SRV_LNK_NOTIF_ERRNO            = UINT64_C(0x0000000000000004),

	/* notify about service being ready; no arg */
	SID_SRV_LNK_NOTIF_READY            = UINT64_C(0x0000000000000008),

	/* notify about service being reloaded; no arg */
	SID_SRV_LNK_NOTIF_RELOADING        = UINT64_C(0x0000000000000010),

	/* notify about service being stopped; no arg */
	SID_SRV_LNK_NOTIF_STOPPING         = UINT64_C(0x0000000000000020),

	/* notify about service being still alive; no arg */
	SID_SRV_LNK_NOTIF_WATCHDOG_REFRESH = UINT64_C(0x0000000000000040),

	/* notify about service reaching a point where watchdog action needs to be executed; no arg */
	SID_SRV_LNK_NOTIF_WATCHDOG_TRIGGER = UINT64_C(0x0000000000000080),

	/* notify with a message */
	SID_SRV_LNK_NOTIF_MESSAGE          = UINT64_C(0x0000000000000100),
} sid_srv_lnk_notif_t;

typedef enum {
	SID_SRV_LNK_FL_NONE      = UINT64_C(0x0000000000000000),
	SID_SRV_LNK_FL_CLONEABLE = UINT64_C(0x0000000000000001),
} sid_srv_lnk_fl_t;

struct sid_srv_lnk;
struct sid_srv_lnk_grp;

#define SID_SRV_LNK_KEY_STATUS              "STATUS"
#define SID_SRV_LNK_KEY_ERRNO               "ERRNO"

#define SID_SRV_LNK_KEY_ACTIVATION_TYPE     "SERVICE_ACTIVATION_TYPE"
#define SID_SRV_LNK_VAL_ACTIVATION_FD       "FD_PRELOAD"

#define SID_SRV_LNK_FD_ACTIVATION_FDS_START SD_LISTEN_FDS_START

/* int sd_listen_fds(int unset_environment) */
#define sid_srv_lnk_fd_activation_present   sd_listen_fds

/* int sd_is_socket_unix(int fd, int type, int listening, const char *path, size_t length) */
#define sid_srv_lnk_fd_is_socket_unix       sd_is_socket_unix

struct sid_srv_lnk *sid_srv_lnk_create(sid_srv_lnk_type_t type, const char *name);
struct sid_srv_lnk *sid_srv_lnk_clone(struct sid_srv_lnk *sl, const char *name);
void                sid_srv_lnk_destroy(struct sid_srv_lnk *sl);

void sid_srv_lnk_flags_set(struct sid_srv_lnk *sl, sid_srv_lnk_fl_t flags);
void sid_srv_lnk_data_set(struct sid_srv_lnk *sl, void *data);

void sid_srv_lnk_notif_add(struct sid_srv_lnk *sl, sid_srv_lnk_notif_t notification);
void sid_srv_lnk_notif_remove(struct sid_srv_lnk *sl, sid_srv_lnk_notif_t notification);

struct sid_srv_lnk_grp *sid_srv_lnk_grp_create(const char *name);
struct sid_srv_lnk_grp *sid_srv_lnk_grp_clone(struct sid_srv_lnk_grp *slg, const char *name);
struct sid_srv_lnk_grp *sid_srv_lnk_grp_merge(struct sid_srv_lnk_grp *dest_slg, struct sid_srv_lnk_grp *src_slg);
void                    sid_srv_lnk_grp_destroy(struct sid_srv_lnk_grp *slg);
void                    sid_srv_lnk_grp_destroy_with_members(struct sid_srv_lnk_grp *slg);

void sid_srv_lnk_grp_member_add(struct sid_srv_lnk_grp *slg, struct sid_srv_lnk *sl);
int  sid_srv_lnk_grp_member_remove(struct sid_srv_lnk_grp *slg, struct sid_srv_lnk *sl);

/*
 * Send service notification.
 * Arguments depend on notification type used - see comments in enum service_notification_t definition.
 */

#define SID_SRV_LNK_DEFAULT_LOG_CTX                                                                                                \
	((sid_log_ctx_t) {.level_id = LOG_DEBUG, .errno_id = 0, .src_file = __FILE__, .src_line = __LINE__, .src_func = __func__})

#define SID_SRV_LNK_DEFAULT_LOG_REQ ((sid_log_req_t) {.pfx = NULL, .ctx = &SID_SRV_LNK_DEFAULT_LOG_CTX})

int sid_srv_lnk_notify(struct sid_srv_lnk *sl, sid_srv_lnk_notif_t notification, struct sid_log_req *log_req, const char *fmt, ...);

int sid_srv_lnk_vnotify(struct sid_srv_lnk *sl,
                        sid_srv_lnk_notif_t notification,
                        struct sid_log_req *log_req,
                        const char         *fmt,
                        va_list             ap);

int sid_srv_lnk_grp_notify(struct sid_srv_lnk_grp *slg,
                           sid_srv_lnk_notif_t     notification,
                           struct sid_log_req     *log_req,
                           const char             *fmt,
                           ...);

int sid_srv_lnk_grp_vnotify(struct sid_srv_lnk_grp *slg,
                            sid_srv_lnk_notif_t     notification,
                            struct sid_log_req     *log_req,
                            const char             *fmt,
                            va_list                 ap);

#ifdef __cplusplus
}
#endif

#endif
