/*
 * SPDX-FileCopyrightText: (C) 2017-2025 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
