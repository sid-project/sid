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

#include "comms.h"
#include "log.h"
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define LOG_PREFIX "comms"

int comms_unix_create(const char *path, int type)
{
	struct sockaddr_un addr;
	int socket_fd;
	socklen_t addr_len;

	if ((socket_fd = socket(AF_UNIX, type, 0)) < 0) {
		log_sys_error(LOG_PREFIX, "socket", path);
		goto fail;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path));
	if (path[0] == '@')
		addr.sun_path[0] = '\0';
	addr_len = offsetof(struct sockaddr_un, sun_path) + strlen(addr.sun_path + 1) + 1;

	if (bind(socket_fd, (struct sockaddr *) &addr, addr_len)) {
		log_sys_error(LOG_PREFIX, "bind", path);
		goto fail;
	}

	if (type & (SOCK_STREAM | SOCK_SEQPACKET)) {
		if (listen(socket_fd, 0) < 0) {
			log_sys_error(LOG_PREFIX, "listen", path);
			goto fail;
		}
	}

	return socket_fd;
fail:
	if (socket_fd >= 0)
		(void) close(socket_fd);
	return -1;
}

ssize_t comms_unix_send(int socket_fd, void *buf, ssize_t buf_len, int fd_to_send)
{
	struct iovec iov;
	struct msghdr msg = {0};
	struct cmsghdr *cmsg;
	union {
		char control[CMSG_SPACE(sizeof(int))];
		struct cmsghdr alignment;
	} u;

	iov.iov_base = buf;
	iov.iov_len = buf_len;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (fd_to_send > -1) {
		msg.msg_control = u.control;
		msg.msg_controllen = sizeof(u.control);
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cmsg), &fd_to_send, sizeof(int));
	}   

	return sendmsg(socket_fd, &msg, 0); 
}

int comms_unix_recv(int socket_fd, void *buf, ssize_t buf_len, int *fd_received)
{
	ssize_t size;
	struct iovec iov;
	struct msghdr msg = {0};
	struct cmsghdr *cmsg;
	union {
		char control[CMSG_SPACE(sizeof(int))];
		struct cmsghdr alignment;
	} u;

	iov.iov_base = buf;
	iov.iov_len = buf_len;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = u.control;
	msg.msg_controllen = sizeof(u.control);

	*fd_received = -1;

	size = recvmsg(socket_fd, &msg, 0);

	if (size < 0)
		return size;

	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg &&
	    cmsg->cmsg_len == CMSG_LEN(sizeof(int)) &&
	    cmsg->cmsg_level == SOL_SOCKET &&
	    cmsg->cmsg_type == SCM_RIGHTS)
		memcpy(fd_received, CMSG_DATA(cmsg), sizeof(int));

	return size;
}
