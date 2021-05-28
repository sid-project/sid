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

#ifndef _SID_USID_IFACE_H
#define _SID_USID_IFACE_H

#include "base/buffer.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define USID_PROTOCOL        2
#define USID_SOCKET_PATH     "\0sid-ubridge.socket"
#define USID_SOCKET_PATH_LEN (sizeof(USID_SOCKET_PATH) - 1)

typedef enum
{
	_USID_CMD_START     = 0,
	USID_CMD_UNDEFINED  = _USID_CMD_START, /* virtual cmd if cmd not defined at all */
	USID_CMD_UNKNOWN    = 1,               /* virtual cmd if cmd defined, but not recognized */
	USID_CMD_ACTIVE     = 2,
	USID_CMD_CHECKPOINT = 3,
	USID_CMD_REPLY      = 4,
	USID_CMD_SCAN       = 5,
	USID_CMD_VERSION    = 6,
	USID_CMD_DUMP       = 7,
	USID_CMD_STATS      = 8,
	USID_CMD_TREE       = 9,
	_USID_CMD_END       = USID_CMD_TREE,
} usid_cmd_t;

static const char *const usid_cmd_names[] = {
	[USID_CMD_UNDEFINED]  = "undefined",
	[USID_CMD_UNKNOWN]    = "unknown",
	[USID_CMD_ACTIVE]     = "active",
	[USID_CMD_CHECKPOINT] = "checkpoint",
	[USID_CMD_REPLY]      = "reply",
	[USID_CMD_SCAN]       = "scan",
	[USID_CMD_VERSION]    = "version",
	[USID_CMD_DUMP]       = "dump",
	[USID_CMD_STATS]      = "stats",
	[USID_CMD_TREE]       = "tree",
};

bool usid_cmd_root_only[] = {
	[USID_CMD_UNDEFINED]  = false,
	[USID_CMD_UNKNOWN]    = false,
	[USID_CMD_ACTIVE]     = false,
	[USID_CMD_CHECKPOINT] = true,
	[USID_CMD_REPLY]      = false,
	[USID_CMD_SCAN]       = true,
	[USID_CMD_VERSION]    = false,
	[USID_CMD_DUMP]       = true,
	[USID_CMD_STATS]      = true,
	[USID_CMD_TREE]       = true,
};

#define USID_CMD_STATUS_MASK_OVERALL UINT64_C(0x0000000000000001)
#define USID_CMD_STATUS_SUCCESS      UINT64_C(0x0000000000000000)
#define USID_CMD_STATUS_FAILURE      UINT64_C(0x0000000000000001)

#define USID_CMD_FLAGS_FMT_MASK  UINT16_C(0x0003)
#define USID_CMD_FLAGS_FMT_TABLE UINT16_C(0x0000)
#define USID_CMD_FLAGS_FMT_JSON  UINT16_C(0x0001)
#define USID_CMD_FLAGS_FMT_ENV   UINT16_C(0x0002)

struct usid_msg_header {
	uint64_t status;
	uint8_t  prot;
	uint8_t  cmd;
	uint16_t flags;
	char     data[];
} __attribute__((packed));

struct usid_msg {
	size_t                  size; /* header + data */
	struct usid_msg_header *header;
};

#define USID_MSG_HEADER_SIZE sizeof(struct usid_msg_header)

typedef int (*usid_req_data_fn_t)(struct buffer *buf, void *data);

usid_cmd_t usid_cmd_name_to_type(const char *cmd_name);
int        usid_req(const char *       prefix,
                    usid_cmd_t         cmd,
                    uint16_t           flags,
                    uint64_t           status,
                    usid_req_data_fn_t data_fn,
                    void *             data_fn_arg,
                    struct buffer **   resp_buf,
                    int *              resp_fd);

#ifdef __cplusplus
}
#endif

#endif
