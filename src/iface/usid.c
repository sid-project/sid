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

#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

struct usid_result {
	struct buffer *buf;
	const char *   shm;
	size_t         shm_len;
};

static inline bool _needs_mem_fd(usid_cmd_t cmd)
{
	return (cmd == USID_CMD_DUMP);
}

void usid_result_free(struct usid_result *res)
{
	if (!res)
		return;
	if (res->buf)
		buffer_destroy(res->buf);
	if (res->shm != MAP_FAILED)
		munmap((void *) res->shm, res->shm_len);
	free(res);
}

int usid_result_status(struct usid_result *res, uint64_t *status)
{
	size_t                        size;
	const struct usid_msg_header *hdr;

	if (!res || !status)
		return -EINVAL;
	buffer_get_data(res->buf, (const void **) &hdr, &size);
	*status = hdr->status;
	return 0;
}

int usid_result_protocol(struct usid_result *res, uint8_t *prot)
{
	size_t                        size;
	const struct usid_msg_header *hdr;

	if (!res || !prot)
		return -EINVAL;
	buffer_get_data(res->buf, (const void **) &hdr, &size);
	*prot = hdr->prot;
	return 0;
}

const char *usid_result_data(struct usid_result *res, size_t *size_p)
{
	size_t                        size;
	const struct usid_msg_header *hdr;

	if (size_p)
		*size_p = 0;

	if (!res)
		return NULL;

	buffer_get_data(res->buf, (const void **) &hdr, &size);
	if (hdr->status & USID_CMD_STATUS_FAILURE)
		return NULL;
	else if (res->shm != MAP_FAILED) {
		if (size_p)
			*size_p = res->shm_len - BUFFER_SIZE_PREFIX_LEN;
		return res->shm + BUFFER_SIZE_PREFIX_LEN;
	} else if (size > USID_MSG_HEADER_SIZE) {
		if (size_p)
			*size_p = size - USID_MSG_HEADER_SIZE;
		return hdr->data;
	}
	return NULL;
}

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

int usid_req(usid_cmd_t cmd, uint16_t flags, uint64_t status, const void *data, size_t data_len, struct usid_result **res_p)
{
	int                 socket_fd = -1;
	struct buffer *     buf       = NULL;
	ssize_t             n;
	int                 r         = -1;
	struct usid_result *res       = NULL;
	int                 export_fd = -1;

	if (!res_p)
		return -EINVAL;
	*res_p = NULL;

	res = malloc(sizeof(*res));
	if (!res)
		return -ENOMEM;
	res->buf     = NULL;
	res->shm     = MAP_FAILED;
	res->shm_len = 0;

	if (!(buf = buffer_create(&((struct buffer_spec) {.backend = BUFFER_BACKEND_MALLOC,
	                                                  .type    = BUFFER_TYPE_LINEAR,
	                                                  .mode    = BUFFER_MODE_SIZE_PREFIX}),
	                          &((struct buffer_init) {.size = 0, .alloc_step = 1, .limit = 0}),
	                          &r)))
		goto out;
	res->buf = buf;

	if (!buffer_add(buf,
	                &((struct usid_msg_header) {.status = status, .prot = USID_PROTOCOL, .cmd = cmd, .flags = flags}),
	                USID_MSG_HEADER_SIZE,
	                &r))
		goto out;

	if (data && data_len && !buffer_add(buf, (void *) data, data_len, &r))
		goto out;

	if ((socket_fd = comms_unix_init(USID_SOCKET_PATH, USID_SOCKET_PATH_LEN, SOCK_STREAM | SOCK_CLOEXEC)) < 0) {
		r = socket_fd;
		goto out;
	}

	if ((n = buffer_write_all(buf, socket_fd)) < 0) {
		r = n;
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
			r = n;
			goto out;
		} else {
			if (!buffer_is_complete(buf, NULL)) {
				r = -EBADMSG;
				goto out;
			}
			break;
		}
	}
	if (buffer_stat(buf).usage.used < USID_MSG_HEADER_SIZE) {
		r = -EBADMSG;
		goto out;
	}
	if (_needs_mem_fd(cmd)) {
		unsigned char           byte;
		BUFFER_SIZE_PREFIX_TYPE msg_size;

		for (;;) {
			n = comms_unix_recv(socket_fd, &byte, sizeof(byte), &export_fd);
			if (n >= 0)
				break;
			if (n == -EAGAIN || n == -EINTR)
				continue;
			r = n;
			goto out;
		}
		if (read(export_fd, &msg_size, BUFFER_SIZE_PREFIX_LEN) != BUFFER_SIZE_PREFIX_LEN) {
			r = -errno;
			goto out;
		}
		if (msg_size < BUFFER_SIZE_PREFIX_LEN) {
			r = -EBADMSG;
			goto out;
		}
		if (msg_size > BUFFER_SIZE_PREFIX_LEN) {
			if ((res->shm = mmap(NULL, msg_size, PROT_READ, MAP_SHARED, export_fd, 0)) == MAP_FAILED) {
				r = -errno;
				goto out;
			}
			res->shm_len = msg_size;
		}
	}
out:
	if (export_fd >= 0)
		close(export_fd);
	if (socket_fd >= 0)
		close(socket_fd);

	if (r < 0)
		usid_result_free(res);
	else
		*res_p = res;
	return r;
}
