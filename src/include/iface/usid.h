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

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	_USID_CMD_START     = 0,
	USID_CMD_UNDEFINED  = _USID_CMD_START, /* virtual cmd if cmd not defined at all */
	USID_CMD_UNKNOWN    = 1,               /* virtual cmd if cmd defined, but not recognized */
	USID_CMD_ACTIVE     = 2,
	USID_CMD_CHECKPOINT = 3,
	USID_CMD_REPLY      = 4,
	USID_CMD_SCAN       = 5,
	USID_CMD_VERSION    = 6,
	_USID_CMD_END       = USID_CMD_VERSION,
} usid_cmd_t;

static const char * const usid_cmd_names[] = {
	[USID_CMD_UNDEFINED]  = "undefined",
	[USID_CMD_UNKNOWN]    = "unknown",
	[USID_CMD_ACTIVE]     = "active",
	[USID_CMD_CHECKPOINT] = "checkpoint",
	[USID_CMD_REPLY]      = "reply",
	[USID_CMD_SCAN]       = "scan",
	[USID_CMD_VERSION]    = "version",
};

struct usid_msg_header {
	uint64_t status;
	uint8_t prot;
	uint8_t cmd;
	char data[];
} __attribute__((packed));

struct usid_msg {
	size_t size; /* header + data */
	struct usid_msg_header *header;
};

struct usid_version {
	uint16_t major;
	uint16_t minor;
	uint16_t release;
} __attribute__((packed));

#define USID_MSG_HEADER_SIZE sizeof(struct usid_msg_header)
#define USID_VERSION_SIZE sizeof(struct usid_version)

usid_cmd_t usid_cmd_name_to_type(const char *cmd_name);

#ifdef __cplusplus
}
#endif

#endif
