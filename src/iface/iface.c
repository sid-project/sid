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

#include "config.h"

#include "base/buffer.h"
#include "base/comms.h"
#include "base/util.h"
#include "iface/iface_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#define KEY_ENV_MAJOR    "MAJOR"
#define KEY_ENV_MINOR    "MINOR"

#define SYSTEM_MAX_MAJOR ((1U << 20) - 1)
#define SYSTEM_MAX_MINOR ((1U << 12) - 1)

static const char * const _cmd_names[] = {
	[SID_CMD_UNDEFINED]  = "undefined",
	[SID_CMD_UNKNOWN]    = "unknown",
	[SID_CMD_ACTIVE]     = "active",
	[SID_CMD_CHECKPOINT] = "checkpoint",
	[SID_CMD_REPLY]      = "reply",
	[SID_CMD_SCAN]       = "scan",
	[SID_CMD_VERSION]    = "version",
	[SID_CMD_DBDUMP]     = "dbdump",
	[SID_CMD_DBSTATS]    = "dbstats",
	[SID_CMD_RESOURCES]  = "resources",
	[SID_CMD_DEVICES]    = "devices",
};

struct sid_result {
	struct sid_buffer *buf;
	const char        *shm;
	size_t             shm_len;
};

static inline bool _needs_mem_fd(sid_cmd_t cmd)
{
	return (cmd == SID_CMD_DBDUMP);
}

void sid_result_free(struct sid_result *res)
{
	if (!res)
		return;
	if (res->buf)
		sid_buffer_destroy(res->buf);
	if (res->shm != MAP_FAILED)
		munmap((void *) res->shm, res->shm_len);
	free(res);
}

int sid_result_status(struct sid_result *res, uint64_t *status)
{
	size_t                       size;
	const struct sid_msg_header *hdr_p;
	struct sid_msg_header        hdr;

	if (!res || !status)
		return -EINVAL;
	sid_buffer_get_data(res->buf, (const void **) &hdr_p, &size);
	memcpy(&hdr, hdr_p, sizeof(struct sid_msg_header));
	*status = hdr.status;
	return 0;
}

int sid_result_protocol(struct sid_result *res, uint8_t *prot)
{
	size_t                       size;
	const struct sid_msg_header *hdr_p;
	struct sid_msg_header        hdr;

	if (!res || !prot)
		return -EINVAL;
	sid_buffer_get_data(res->buf, (const void **) &hdr_p, &size);
	memcpy(&hdr, hdr_p, sizeof(struct sid_msg_header));
	*prot = hdr.prot;
	return 0;
}

const char *sid_result_data(struct sid_result *res, size_t *size_p)
{
	size_t                       size;
	const struct sid_msg_header *hdr_p;
	struct sid_msg_header        hdr;

	if (size_p)
		*size_p = 0;

	if (!res)
		return NULL;

	sid_buffer_get_data(res->buf, (const void **) &hdr_p, &size);
	memcpy(&hdr, hdr_p, sizeof(struct sid_msg_header));
	if (hdr.status & SID_CMD_STATUS_FAILURE)
		return NULL;
	else if (res->shm != MAP_FAILED) {
		if (size_p)
			*size_p = res->shm_len - SID_BUFFER_SIZE_PREFIX_LEN;
		return res->shm + SID_BUFFER_SIZE_PREFIX_LEN;
	} else if (size > SID_MSG_HEADER_SIZE) {
		if (size_p)
			*size_p = size - SID_MSG_HEADER_SIZE;
		return (const char *) hdr_p + SID_MSG_HEADER_SIZE;
	}
	return NULL;
}

const char *sid_cmd_type_to_name(sid_cmd_t cmd)
{
	return _cmd_names[cmd];
}

sid_cmd_t sid_cmd_name_to_type(const char *cmd_name)
{
	sid_cmd_t cmd;

	if (!cmd_name)
		return SID_CMD_UNDEFINED;

	for (cmd = _SID_CMD_START; cmd <= _SID_CMD_END; cmd++) {
		if (!strcmp(cmd_name, _cmd_names[cmd]))
			return cmd;
	}

	return SID_CMD_UNKNOWN;
}

static int _add_devt_env_to_buffer(struct sid_buffer *buf)
{
	unsigned long long val;
	unsigned           major, minor;
	dev_t              devnum;
	int                r;

	if ((r = sid_util_env_get_ull(KEY_ENV_MAJOR, 0, SYSTEM_MAX_MAJOR, &val)) < 0)
		return r;

	major = val;

	if ((r = sid_util_env_get_ull(KEY_ENV_MINOR, 0, SYSTEM_MAX_MINOR, &val)) < 0)
		return r;

	minor  = val;

	devnum = makedev(major, minor);
	return sid_buffer_add(buf, &devnum, sizeof(devnum), NULL, NULL);
}

static int _add_checkpoint_env_to_buf(struct sid_buffer *buf, struct sid_checkpoint_data *data)
{
	const char *key, *val;
	int         i, r;

	if (!data || !data->name || (data->nr_keys && !data->keys))
		return -EINVAL;

	if ((r = _add_devt_env_to_buffer(buf)) < 0)
		goto out;

	/* add checkpoint name */
	if ((r = sid_buffer_add(buf, data->name, strlen(data->name) + 1, NULL, NULL)) < 0)
		goto out;

	/* add key=value pairs from current environment */
	for (i = 0; i < data->nr_keys; i++) {
		key = data->keys[i];
		if (!(val = getenv(key)))
			continue;

		if ((r = sid_buffer_fmt_add(buf, NULL, NULL, "%s=%s", key, val)) < 0)
			goto out;
	}

	r = 0;
out:
	return r;
}

static int _add_scan_env_to_buf(struct sid_buffer *buf)
{
	extern char **environ;
	char        **kv;
	int           r;

	if ((r = _add_devt_env_to_buffer(buf)) < 0)
		goto out;

	for (kv = environ; *kv; kv++)
		if ((r = sid_buffer_add(buf, *kv, strlen(*kv) + 1, NULL, NULL)) < 0)
			goto out;
out:
	return r;
}

int sid_req(struct sid_request *req, struct sid_result **res_p)
{
	int                socket_fd = -1;
	struct sid_buffer *buf       = NULL;
	ssize_t            n;
	int                r         = -1;
	struct sid_result *res       = NULL;
	int                export_fd = -1;

	if (!res_p)
		return -EINVAL;
	*res_p = NULL;

	if (!req)
		return -EINVAL;

	res = malloc(sizeof(*res));
	if (!res)
		return -ENOMEM;
	res->buf     = NULL;
	res->shm     = MAP_FAILED;
	res->shm_len = 0;

	if (!(buf = sid_buffer_create(&((struct sid_buffer_spec) {.backend = SID_BUFFER_BACKEND_MALLOC,
	                                                          .type    = SID_BUFFER_TYPE_LINEAR,
	                                                          .mode    = SID_BUFFER_MODE_SIZE_PREFIX}),
	                              &((struct sid_buffer_init) {.size = 0, .alloc_step = 1, .limit = 0}),
	                              &r)))
		goto out;
	res->buf = buf;

	if ((r = sid_buffer_add(
		     buf,
		     &((struct sid_msg_header) {.status = req->seqnum, .prot = SID_PROTOCOL, .cmd = req->cmd, .flags = req->flags}),
		     SID_MSG_HEADER_SIZE,
		     NULL,
		     NULL)) < 0)
		goto out;

	if (req->flags & SID_CMD_FLAGS_UNMODIFIED_DATA) {
		struct sid_unmodified_data *data = &req->data.unmodified;
		if (data->mem == NULL && data->size > 0) {
			r = -EINVAL;
			goto out;
		}
		if (data->size > 0 && ((r = sid_buffer_add(buf, (void *) data->mem, data->size, NULL, NULL)) < 0))
			goto out;
	} else {
		switch (req->cmd) {
			case SID_CMD_SCAN:
				if ((r = _add_scan_env_to_buf(buf)) < 0)
					goto out;
				break;
			case SID_CMD_CHECKPOINT:
				if ((r = _add_checkpoint_env_to_buf(buf, &req->data.checkpoint)) < 0)
					goto out;
				break;
			default:
				/* no extra data to add for other commands */
				break;
		}
	}

	if ((socket_fd = sid_comms_unix_init(SID_SOCKET_PATH, SID_SOCKET_PATH_LEN, SOCK_STREAM | SOCK_CLOEXEC)) < 0) {
		r = socket_fd;
		goto out;
	}

	if ((n = sid_buffer_write_all(buf, socket_fd)) < 0) {
		r = n;
		goto out;
	}

	sid_buffer_reset(buf);

	for (;;) {
		n = sid_buffer_read(buf, socket_fd);
		if (n > 0) {
			if (sid_buffer_is_complete(buf, NULL)) {
				r = 0;
				break;
			}
		} else if (n < 0) {
			if (n == -EAGAIN || n == -EINTR)
				continue;
			r = n;
			goto out;
		} else {
			if (!sid_buffer_is_complete(buf, NULL)) {
				r = -EBADMSG;
				goto out;
			}
			break;
		}
	}
	if (sid_buffer_count(buf) < SID_MSG_HEADER_SIZE) {
		r = -EBADMSG;
		goto out;
	}
	if (_needs_mem_fd(req->cmd)) {
		unsigned char               byte;
		SID_BUFFER_SIZE_PREFIX_TYPE msg_size;

		for (;;) {
			n = sid_comms_unix_recv(socket_fd, &byte, sizeof(byte), &export_fd);
			if (n >= 0)
				break;
			if (n == -EAGAIN || n == -EINTR)
				continue;
			r = n;
			goto out;
		}
		if ((n = sid_util_fd_read_all(export_fd, &msg_size, SID_BUFFER_SIZE_PREFIX_LEN)) != SID_BUFFER_SIZE_PREFIX_LEN) {
			if (n < 0)
				r = n;
			else
				r = -ENODATA;
			goto out;
		}
		if (msg_size < SID_BUFFER_SIZE_PREFIX_LEN) {
			r = -EBADMSG;
			goto out;
		}
		if (msg_size > SID_BUFFER_SIZE_PREFIX_LEN) {
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
		sid_result_free(res);
	else
		*res_p = res;
	return r;
}
