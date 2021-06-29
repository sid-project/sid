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

#include "base/comms.h"

#include <errno.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void _comms_unix_addr_init(const char *path, size_t path_len, struct sockaddr_un *addr, socklen_t *addr_len)
{
	memset(addr, 0, sizeof(*addr));
	addr->sun_family = AF_UNIX;
	memccpy(addr->sun_path, path, path_len, sizeof(addr->sun_path));
	*addr_len = offsetof(struct sockaddr_un, sun_path) + path_len;
}

int sid_comms_unix_create(const char *path, size_t path_len, int type)
{
	int                socket_fd = -1;
	struct sockaddr_un addr;
	socklen_t          addr_len;
	int                r;

	if (!path_len) {
		r = -EINVAL;
		goto fail;
	}

	if ((socket_fd = socket(AF_UNIX, type, 0)) < 0) {
		r = -errno;
		goto fail;
	}

	_comms_unix_addr_init(path, path_len, &addr, &addr_len);

	if (bind(socket_fd, (struct sockaddr *) &addr, addr_len)) {
		r = -errno;
		goto fail;
	}

	if (type & (SOCK_STREAM | SOCK_SEQPACKET)) {
		if (listen(socket_fd, 0) < 0) {
			r = -errno;
			goto fail;
		}
	}

	return socket_fd;
fail:
	if (socket_fd >= 0)
		(void) close(socket_fd);
	return r;
}

int sid_comms_unix_init(const char *path, size_t path_len, int type)
{
	struct sockaddr_un addr;
	int                socket_fd = -1;
	socklen_t          addr_len;
	int                r;

	if (!path_len) {
		r = -EINVAL;
		goto fail;
	}

	if ((socket_fd = socket(AF_UNIX, type, 0)) < 0) {
		r = -errno;
		goto fail;
	}

	if (!(type & (SOCK_STREAM | SOCK_SEQPACKET)))
		return socket_fd;

	_comms_unix_addr_init(path, path_len, &addr, &addr_len);

	if (connect(socket_fd, (struct sockaddr *) &addr, addr_len) < 0) {
		r = -errno;
		goto fail;
	}

	return socket_fd;
fail:
	if (socket_fd >= 0)
		(void) close(socket_fd);
	return r;
}

static ssize_t _do_comms_unix_send(int socket_fd, struct iovec *iov, size_t iov_len, int fd_to_send)
{
	struct msghdr   msg = {0};
	struct cmsghdr *cmsg;
	union {
		char           control[CMSG_SPACE(sizeof(int))];
		struct cmsghdr alignment;
	} u = {0};
	ssize_t r;

	msg.msg_iov    = iov;
	msg.msg_iovlen = iov_len;

	if (fd_to_send > -1) {
		msg.msg_control    = u.control;
		msg.msg_controllen = sizeof(u.control);
		cmsg               = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level   = SOL_SOCKET;
		cmsg->cmsg_type    = SCM_RIGHTS;
		cmsg->cmsg_len     = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cmsg), &fd_to_send, sizeof(int));
	}

	if ((r = sendmsg(socket_fd, &msg, 0) < 0))
		return -errno;
	else
		return r;
}

ssize_t sid_comms_unix_send(int socket_fd, void *buf, ssize_t buf_len, int fd_to_send)
{
	struct iovec iov = {.iov_base = buf, .iov_len = buf_len};

	return _do_comms_unix_send(socket_fd, &iov, 1, fd_to_send);
}

ssize_t sid_comms_unix_send_iovec(int socket_fd, struct iovec *iov, size_t iov_len, int fd_to_send)
{
	return _do_comms_unix_send(socket_fd, iov, iov_len, fd_to_send);
}

static ssize_t _do_comms_unix_recv(int socket_fd, struct iovec *iov, size_t iov_len, int *fd_received)
{
	struct msghdr   msg = {0};
	struct cmsghdr *cmsg;
	union {
		char           control[CMSG_SPACE(sizeof(int))];
		struct cmsghdr alignment;
	} u;
	ssize_t r;

	msg.msg_iov        = iov;
	msg.msg_iovlen     = iov_len;
	msg.msg_control    = u.control;
	msg.msg_controllen = sizeof(u.control);

	*fd_received = -1;

	if ((r = recvmsg(socket_fd, &msg, 0)) < 0)
		return -errno;

	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg && cmsg->cmsg_len == CMSG_LEN(sizeof(int)) && cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS)
		memcpy(fd_received, CMSG_DATA(cmsg), sizeof(int));

	return r;
}

ssize_t sid_comms_unix_recv(int socket_fd, void *buf, ssize_t buf_len, int *fd_received)
{
	struct iovec iov = {.iov_base = buf, .iov_len = buf_len};

	return _do_comms_unix_recv(socket_fd, &iov, 1, fd_received);
}

ssize_t sid_comms_unix_recv_iovec(int socket_fd, struct iovec *iov, size_t iov_len, int *fd_received)
{
	return _do_comms_unix_recv(socket_fd, iov, iov_len, fd_received);
}
