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

#ifndef _SID_IFACE_H
#define _SID_IFACE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SID_PROTOCOL 2

typedef enum
{
	_SID_CMD_START     = 0,
	SID_CMD_UNDEFINED  = _SID_CMD_START, /* virtual cmd if cmd not defined at all */
	SID_CMD_UNKNOWN    = 1,              /* virtual cmd if cmd defined, but not recognized */
	SID_CMD_ACTIVE     = 2,
	SID_CMD_CHECKPOINT = 3,
	SID_CMD_REPLY      = 4,
	SID_CMD_SCAN       = 5,
	SID_CMD_VERSION    = 6,
	SID_CMD_DBDUMP     = 7,
	SID_CMD_DBSTATS    = 8,
	SID_CMD_RESOURCES  = 9,
	_SID_CMD_END       = SID_CMD_RESOURCES,
} sid_cmd_t;

#define SID_CMD_STATUS_MASK_OVERALL UINT64_C(0x0000000000000001)
#define SID_CMD_STATUS_SUCCESS      UINT64_C(0x0000000000000000)
#define SID_CMD_STATUS_FAILURE      UINT64_C(0x0000000000000001)

#define SID_CMD_FLAGS_FMT_MASK        UINT16_C(0x0003)
#define SID_CMD_FLAGS_FMT_TABLE       UINT16_C(0x0000)
#define SID_CMD_FLAGS_FMT_JSON        UINT16_C(0x0001)
#define SID_CMD_FLAGS_FMT_ENV         UINT16_C(0x0002)
#define SID_CMD_FLAGS_UNMODIFIED_DATA UINT16_C(0x0004)

struct sid_checkpoint_data {
	char *       name;
	char **      keys;
	unsigned int nr_keys;
};

struct sid_unmodified_data {
	char * mem;
	size_t size;
};

struct sid_request {
	sid_cmd_t cmd;
	uint64_t  flags;
	uint64_t  seqnum;
	union {
		struct sid_checkpoint_data checkpoint;
		struct sid_unmodified_data unmodified;
	} data;
};

struct sid_result;

const char *sid_cmd_type_to_name(sid_cmd_t cmd);
sid_cmd_t   sid_cmd_name_to_type(const char *cmd_name);
int         sid_req(struct sid_request *req, struct sid_result **res);
void        sid_result_free(struct sid_result *res);
int         sid_result_status(struct sid_result *res, uint64_t *status);
int         sid_result_protocol(struct sid_result *res, uint8_t *prot);
const char *sid_result_data(struct sid_result *res, size_t *size_p);
#ifdef __cplusplus
}
#endif

#endif
