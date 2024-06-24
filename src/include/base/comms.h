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

#ifndef _SID_COMMS_H
#define _SID_COMMS_H

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

#ifdef __cplusplus
extern "C" {
#endif

int sid_comms_unix_create(const char *path, size_t path_len, int type);
int sid_comms_unix_init(const char *path, size_t path_len, int type);

ssize_t sid_comms_unix_send(int socket_fd, void *buf, ssize_t buf_len, int fd_to_send);
ssize_t sid_comms_unix_send_iovec(int socket_fd, struct iovec *iov, size_t iov_len, int fd_to_send);

ssize_t sid_comms_unix_recv(int socket_fd, void *buf, ssize_t buf_len, int *fd_received);
ssize_t sid_comms_unix_recv_iovec(int socket_fd, struct iovec *iov, size_t iov_len, int *fd_received);

#ifdef __cplusplus
}
#endif

#endif
