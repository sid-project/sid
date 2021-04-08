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

#define USID_PROTOCOL        1
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

#define COMMAND_STATUS_MASK_OVERALL UINT64_C(0x0000000000000001)
#define COMMAND_STATUS_SUCCESS      UINT64_C(0x0000000000000000)
#define COMMAND_STATUS_FAILURE      UINT64_C(0x0000000000000001)

struct usid_msg_header {
	uint64_t status;
	uint8_t  prot;
	uint8_t  cmd;
	char     data[];
} __attribute__((packed));

struct usid_msg {
	size_t                  size; /* header + data */
	struct usid_msg_header *header;
};

struct usid_version {
	uint16_t major;
	uint16_t minor;
	uint16_t release;
} __attribute__((packed));

struct usid_dump_header {
	uint64_t seqnum;
	uint64_t flags;
	uint32_t data_count; /* the number of data iovs */
} __attribute__((packed));

struct usid_stats {
	uint64_t key_size;
	uint64_t value_int_size;
	uint64_t value_int_data_size;
	uint64_t value_ext_size;
	uint64_t value_ext_data_size;
	uint64_t meta_size;
	uint32_t nr_kv_pairs;
} __attribute__((packed));

#define USID_MSG_HEADER_SIZE sizeof(struct usid_msg_header)
#define USID_VERSION_SIZE    sizeof(struct usid_version)
#define USID_STATS_SIZE      sizeof(struct usid_stats)

typedef int (*usid_req_data_fn_t)(struct buffer *buf, void *data);

usid_cmd_t usid_cmd_name_to_type(const char *cmd_name);
int        usid_req(const char *       prefix,
                    usid_cmd_t         cmd,
                    uint64_t           status,
                    usid_req_data_fn_t data_fn,
                    void *             data_fn_arg,
                    struct buffer **   resp_buf);

#ifdef __cplusplus
}
#endif

#endif
