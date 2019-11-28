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

#include <errno.h>
#include <systemd/sd-daemon.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	SERVICE_TYPE_NONE,
	SERVICE_TYPE_SYSTEMD,
	_SERVICE_TYPE_COUNT
} service_link_type_t;

typedef enum {
	/* no notification */
	SERVICE_NOTIFICATION_NONE             = UINT64_C(0x0000000000000000),

	/* discard any further service notifications; no arg */
	SERVICE_NOTIFICATION_UNSET            = UINT64_C(0x0000000000000001),

	/* notify about service status; arg is STATUS=<message> */
	SERVICE_NOTIFICATION_STATUS           = UINT64_C(0x0000000000000002),

	/* notify about service reaching an error with errno; arg is 'ERRNO=<errno>' or 'ERRNO=<errno_identifier>' */
	SERVICE_NOTIFICATION_ERRNO            = UINT64_C(0x0000000000000004),

	/* notify about service being ready; no arg */
	SERVICE_NOTIFICATION_READY            = UINT64_C(0x0000000000000008),

	/* notify about service being reloaded; no arg */
	SERVICE_NOTIFICATION_RELOADING        = UINT64_C(0x0000000000000010),

	/* notify about service being stopped; no arg */
	SERVICE_NOTIFICATION_STOPPING         = UINT64_C(0x0000000000000020),

	/* notify about service being still alive; no arg */
	SERVICE_NOTIFICATION_WATCHDOG_REFRESH = UINT64_C(0x0000000000000040),

	/* notify about service reaching a point where watchdog action needs to be executed; no arg */
	SERVICE_NOTIFICATION_WATCHDOG_TRIGGER = UINT64_C(0x0000000000000080),
} service_link_notification_t;

struct service_link;
struct service_link_group;

#define SERVICE_KEY_STATUS           "STATUS"
#define SERVICE_KEY_ERRNO            "ERRNO"

#define SERVICE_KEY_ACTIVATION_TYPE  "SERVICE_ACTIVATION_TYPE"
#define SERVICE_VALUE_ACTIVATION_FD  "FD_PRELOAD"

#define SERVICE_FD_ACTIVATION_FDS_START SD_LISTEN_FDS_START

/* int sd_listen_fds(int unset_environment) */
#define service_fd_activation_present sd_listen_fds

/* int sd_is_socket_unix(int fd, int type, int listening, const char *path, size_t length) */
#define service_fd_is_socket_unix sd_is_socket_unix

struct service_link *service_link_create(service_link_type_t type, const char *name);
void service_link_destroy(struct service_link *sl);

int service_link_add_notification(struct service_link *sl, service_link_notification_t notification);
int service_link_remove_notification(struct service_link *sl, service_link_notification_t notification);

struct service_link_group *service_link_group_create(const char *name);
void service_link_group_destroy(struct service_link_group *slg);
void service_link_group_destroy_with_members(struct service_link_group *slg);

int service_link_group_add_member(struct service_link_group *slg, struct service_link *sl);
int service_link_group_remove_member(struct service_link_group *slg, struct service_link *sl);

/*
 * Send service notification.
 * Arguments depend on notification type used - see comments in enum service_notification_t definition.
 */
int service_link_notify(struct service_link *sl, service_link_notification_t notification, const char *fmt, ...);
int service_link_group_notify(struct service_link_group *slg, service_link_notification_t notification, const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif
