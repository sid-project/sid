/*
 * SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "base/buf.h"
#include "base/comms.h"
#include "base/util.h"
#include "iface/ifc-internal.h"

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
	[SID_IFC_CMD_UNDEFINED]  = "undefined",
	[SID_IFC_CMD_UNKNOWN]    = "unknown",
	[SID_IFC_CMD_ACTIVE]     = "active",
	[SID_IFC_CMD_CHECKPOINT] = "checkpoint",
	[SID_IFC_CMD_REPLY]      = "reply",
	[SID_IFC_CMD_SCAN]       = "scan",
	[SID_IFC_CMD_VERSION]    = "version",
	[SID_IFC_CMD_DBDUMP]     = "dbdump",
	[SID_IFC_CMD_DBSTATS]    = "dbstats",
	[SID_IFC_CMD_RESOURCES]  = "resources",
	[SID_IFC_CMD_DEVICES]    = "devices",
};

struct sid_ifc_rsl {
	struct sid_buf *buf;
	const char     *shm;
	size_t          shm_len;
};

static inline bool _needs_mem_fd(sid_ifc_cmd_t cmd)
{
	return (cmd == SID_IFC_CMD_DBDUMP);
}

void sid_ifc_rsl_free(struct sid_ifc_rsl *rsl)
{
	if (!rsl)
		return;

	if (rsl->buf)
		sid_buf_destroy(rsl->buf);

	if (rsl->shm != MAP_FAILED)
		(void) munmap((void *) rsl->shm, rsl->shm_len);

	free(rsl);
}

int sid_ifc_rsl_get_status(struct sid_ifc_rsl *rsl, uint64_t *status)
{
	size_t                           size;
	const struct sid_ifc_msg_header *hdr_p;
	struct sid_ifc_msg_header        hdr;
	int                              r;

	if (!rsl || !status)
		return -EINVAL;

	if ((r = sid_buf_get_data(rsl->buf, (const void **) &hdr_p, &size)) < 0)
		return r;

	memcpy(&hdr, hdr_p, sizeof(struct sid_ifc_msg_header));
	*status = hdr.status;

	return 0;
}

int sid_ifc_rsl_get_protocol(struct sid_ifc_rsl *rsl, uint8_t *prot)
{
	size_t                           size;
	const struct sid_ifc_msg_header *hdr_p;
	struct sid_ifc_msg_header        hdr;
	int                              r;

	if (!rsl || !prot)
		return -EINVAL;

	if ((r = sid_buf_get_data(rsl->buf, (const void **) &hdr_p, &size)) < 0)
		return r;

	memcpy(&hdr, hdr_p, sizeof(struct sid_ifc_msg_header));
	*prot = hdr.prot;

	return 0;
}

const char *sid_ifc_rsl_get_data(struct sid_ifc_rsl *rsl, size_t *size_p)
{
	size_t                           size;
	const struct sid_ifc_msg_header *hdr_p;
	struct sid_ifc_msg_header        hdr;

	if (size_p)
		*size_p = 0;

	if (!rsl)
		return NULL;

	if (sid_buf_get_data(rsl->buf, (const void **) &hdr_p, &size) < 0)
		return NULL;

	memcpy(&hdr, hdr_p, sizeof(struct sid_ifc_msg_header));

	if (hdr.status & SID_IFC_CMD_STATUS_FAILURE)
		return NULL;
	else if (rsl->shm != MAP_FAILED) {
		if (size_p)
			*size_p = rsl->shm_len - SID_BUF_SIZE_PREFIX_LEN;
		return rsl->shm + SID_BUF_SIZE_PREFIX_LEN;
	} else if (size > SID_IFC_MSG_HEADER_SIZE) {
		if (size_p)
			*size_p = size - SID_IFC_MSG_HEADER_SIZE;
		return (const char *) hdr_p + SID_IFC_MSG_HEADER_SIZE;
	}

	return NULL;
}

const char *sid_ifc_cmd_type_to_name(sid_ifc_cmd_t cmd)
{
	return _cmd_names[cmd];
}

sid_ifc_cmd_t sid_ifc_cmd_name_to_type(const char *cmd_name)
{
	sid_ifc_cmd_t cmd;

	if (!cmd_name)
		return SID_IFC_CMD_UNDEFINED;

	for (cmd = _SID_IFC_CMD_START; cmd <= _SID_IFC_CMD_END; cmd++) {
		if (!strcmp(cmd_name, _cmd_names[cmd]))
			return cmd;
	}

	return SID_IFC_CMD_UNKNOWN;
}

static int _add_devt_env_to_buffer(struct sid_buf *buf)
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

	return sid_buf_add(buf, &devnum, sizeof(devnum), NULL, NULL);
}

static int _add_checkpoint_env_to_buf(struct sid_buf *buf, struct sid_ifc_checkpoint_data *data)
{
	const char *key, *val;
	int         i, r;

	if (!data || !data->name || (data->nr_keys && !data->keys))
		return -EINVAL;

	if ((r = _add_devt_env_to_buffer(buf)) < 0)
		goto out;

	/* add checkpoint name */
	if ((r = sid_buf_add(buf, data->name, strlen(data->name) + 1, NULL, NULL)) < 0)
		goto out;

	/* add key=value pairs from current environment */
	for (i = 0; i < data->nr_keys; i++) {
		key = data->keys[i];
		if (!(val = getenv(key)))
			continue;

		if ((r = sid_buf_add_fmt(buf, NULL, NULL, "%s=%s", key, val)) < 0)
			goto out;
	}

	r = 0;
out:
	return r;
}

static int _add_scan_env_to_buf(struct sid_buf *buf)
{
	extern char **environ;
	char        **kv;
	int           r;

	if ((r = _add_devt_env_to_buffer(buf)) < 0)
		goto out;

	for (kv = environ; *kv; kv++)
		if ((r = sid_buf_add(buf, *kv, strlen(*kv) + 1, NULL, NULL)) < 0)
			goto out;
out:
	return r;
}

int sid_ifc_req(struct sid_ifc_req *req, struct sid_ifc_rsl **rsl_p)
{
	int                 socket_fd = -1;
	struct sid_buf     *buf       = NULL;
	ssize_t             n;
	int                 r         = -1;
	struct sid_ifc_rsl *rsl       = NULL;
	int                 export_fd = -1;

	if (!rsl_p)
		return -EINVAL;

	*rsl_p = NULL;

	if (!req)
		return -EINVAL;

	if (!(rsl = malloc(sizeof(*rsl))))
		return -ENOMEM;

	rsl->shm     = MAP_FAILED;
	rsl->shm_len = 0;

	if (!(rsl->buf = buf = sid_buf_create(&SID_BUF_SPEC(.mode = SID_BUF_MODE_SIZE_PREFIX), &SID_BUF_INIT(.alloc_step = 1), &r)))
		goto out;

	if ((r = sid_buf_add(buf,
	                     &((struct sid_ifc_msg_header) {.status = req->seqnum,
	                                                    .prot   = SID_IFC_PROTOCOL,
	                                                    .cmd    = req->cmd,
	                                                    .flags  = req->flags}),
	                     SID_IFC_MSG_HEADER_SIZE,
	                     NULL,
	                     NULL)) < 0)
		goto out;

	if (req->flags & SID_IFC_CMD_FL_UNMODIFIED_DATA) {
		struct sid_ifc_unmodified_data *data = &req->data.unmodified;

		if (data->mem == NULL && data->size > 0) {
			r = -EINVAL;
			goto out;
		}

		if (data->size > 0 && ((r = sid_buf_add(buf, (void *) data->mem, data->size, NULL, NULL)) < 0))
			goto out;
	} else {
		switch (req->cmd) {
			case SID_IFC_CMD_SCAN:
				if ((r = _add_scan_env_to_buf(buf)) < 0)
					goto out;
				break;
			case SID_IFC_CMD_CHECKPOINT:
				if ((r = _add_checkpoint_env_to_buf(buf, &req->data.checkpoint)) < 0)
					goto out;
				break;
			default:
				/* no extra data to add for other commands */
				break;
		}
	}

	if ((socket_fd = sid_comms_unix_init(SID_IFC_SOCKET_PATH, SID_IFC_SOCKET_PATH_LEN, SOCK_STREAM | SOCK_CLOEXEC)) < 0) {
		r = socket_fd;
		goto out;
	}

	if ((n = sid_buf_write_all(buf, socket_fd)) < 0) {
		r = n;
		goto out;
	}

	if ((r = sid_buf_reset(buf) < 0))
		goto out;

	for (;;) {
		n = sid_buf_read(buf, socket_fd);
		if (n > 0) {
			if (sid_buf_is_complete(buf, NULL)) {
				r = 0;
				break;
			}
		} else if (n < 0) {
			if (n == -EAGAIN || n == -EINTR)
				continue;
			r = n;
			goto out;
		} else {
			if (!sid_buf_is_complete(buf, NULL)) {
				r = -EBADMSG;
				goto out;
			}
			break;
		}
	}

	if (sid_buf_count(buf) < SID_IFC_MSG_HEADER_SIZE) {
		r = -EBADMSG;
		goto out;
	}

	if (_needs_mem_fd(req->cmd)) {
		unsigned char            byte;
		SID_BUF_SIZE_PREFIX_TYPE msg_size;

		for (;;) {
			n = sid_comms_unix_recv(socket_fd, &byte, sizeof(byte), &export_fd);
			if (n >= 0)
				break;
			if (n == -EAGAIN || n == -EINTR)
				continue;
			r = n;
			goto out;
		}
		if ((n = sid_util_fd_read_all(export_fd, &msg_size, SID_BUF_SIZE_PREFIX_LEN)) != SID_BUF_SIZE_PREFIX_LEN) {
			if (n < 0)
				r = n;
			else
				r = -ENODATA;
			goto out;
		}
		if (msg_size < SID_BUF_SIZE_PREFIX_LEN) {
			r = -EBADMSG;
			goto out;
		}
		if (msg_size > SID_BUF_SIZE_PREFIX_LEN) {
			if ((rsl->shm = mmap(NULL, msg_size, PROT_READ, MAP_SHARED, export_fd, 0)) == MAP_FAILED) {
				r = -errno;
				goto out;
			}
			rsl->shm_len = msg_size;
		}
	}
out:
	if (export_fd >= 0)
		(void) close(export_fd);

	if (socket_fd >= 0)
		(void) close(socket_fd);

	if (r < 0)
		sid_ifc_rsl_free(rsl);
	else
		*rsl_p = rsl;

	return r;
}
