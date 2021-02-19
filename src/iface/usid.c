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

#include "iface/usid.h"

#include "base/comms.h"
#include "log/log.h"

#include <string.h>
#include <unistd.h>

usid_cmd_t usid_cmd_name_to_type(const char *cmd_name)
{
	usid_cmd_t cmd;

	if (!cmd_name)
		return USID_CMD_UNDEFINED;

	for (cmd = _USID_CMD_START; cmd <= _USID_CMD_END; cmd++) {
		if (!strcmp(cmd_name, usid_cmd_names[cmd]))
			return cmd;
	}

	return USID_CMD_UNKNOWN;
}

int usid_req(const char *       prefix,
             usid_cmd_t         cmd,
             uint64_t           status,
             usid_req_data_fn_t data_fn,
             void *             data_fn_arg,
             struct buffer **   resp_buf)
{
	int            socket_fd = -1;
	struct buffer *buf       = NULL;
	ssize_t        n;
	int            r = -1;

	if (!(buf = buffer_create(&((struct buffer_spec) {.backend = BUFFER_BACKEND_MALLOC,
	                                                  .type    = BUFFER_TYPE_LINEAR,
	                                                  .mode    = BUFFER_MODE_SIZE_PREFIX}),
	                          &((struct buffer_init) {.size = 0, .alloc_step = 1, .limit = 0}),
	                          &r))) {
		log_error_errno(prefix, r, "Failed to create request buffer");
		goto out;
	}

	if (!buffer_add(buf,
	                &((struct usid_msg_header) {.status = status, .prot = USID_PROTOCOL, .cmd = cmd}),
	                USID_MSG_HEADER_SIZE,
	                &r))
		goto out;

	if (data_fn && (data_fn(buf, data_fn_arg) < 0)) {
		log_error(prefix, "Failed to add data to request.");
		goto out;
	}

	if ((socket_fd = comms_unix_init(USID_SOCKET_PATH, USID_SOCKET_PATH_LEN, SOCK_STREAM | SOCK_CLOEXEC)) < 0) {
		r = socket_fd;
		if (r != -ECONNREFUSED)
			log_error_errno(prefix, r, "Failed to initialize connection");
		goto out;
	}

	if ((n = buffer_write_all(buf, socket_fd)) < 0) {
		log_error_errno(prefix, n, "Failed to send request");
		goto out;
	}

	buffer_reset(buf);

	for (;;) {
		n = buffer_read(buf, socket_fd);
		if (n > 0) {
			if (buffer_is_complete(buf, NULL)) {
				r = 0;
				break;
			}
		} else if (n < 0) {
			if (n == -EAGAIN || n == -EINTR)
				continue;
			log_error_errno(prefix, errno, "Failed to read response");
			r = -EBADMSG;
			break;
		} else {
			if (!buffer_is_complete(buf, NULL))
				log_error(prefix, "Unexpected reponse end.");
			break;
		}
	}
out:
	if (socket_fd >= 0)
		close(socket_fd);

	if (r < 0) {
		if (buf)
			buffer_destroy(buf);
	} else
		*resp_buf = buf;

	return r;
}
