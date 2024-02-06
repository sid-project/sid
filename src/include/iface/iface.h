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

#define SID_IFC_PROTOCOL 2

typedef enum {
	_SID_IFC_CMD_START     = 0,
	SID_IFC_CMD_UNDEFINED  = _SID_IFC_CMD_START, /* virtual cmd if cmd not defined at all */
	SID_IFC_CMD_UNKNOWN    = 1,                  /* virtual cmd if cmd defined, but not recognized */
	SID_IFC_CMD_ACTIVE     = 2,
	SID_IFC_CMD_CHECKPOINT = 3,
	SID_IFC_CMD_REPLY      = 4,
	SID_IFC_CMD_SCAN       = 5,
	SID_IFC_CMD_VERSION    = 6,
	SID_IFC_CMD_DBDUMP     = 7,
	SID_IFC_CMD_DBSTATS    = 8,
	SID_IFC_CMD_RESOURCES  = 9,
	SID_IFC_CMD_DEVICES    = 10,
	_SID_IFC_CMD_END       = SID_IFC_CMD_DEVICES,
} sid_ifc_cmd_t;

#define SID_IFC_CMD_STATUS_MASK_OVERALL UINT64_C(0x0000000000000001)
#define SID_IFC_CMD_STATUS_SUCCESS      UINT64_C(0x0000000000000000)
#define SID_IFC_CMD_STATUS_FAILURE      UINT64_C(0x0000000000000001)

#define SID_IFC_CMD_FL_FMT_MASK         UINT16_C(0x0003)
#define SID_IFC_CMD_FL_FMT_TABLE        UINT16_C(0x0000)
#define SID_IFC_CMD_FL_FMT_JSON         UINT16_C(0x0001)
#define SID_IFC_CMD_FL_FMT_ENV          UINT16_C(0x0002)
#define SID_IFC_CMD_FL_UNMODIFIED_DATA  UINT16_C(0x0004)

struct sid_ifc_checkpoint_data {
	char        *name;
	char       **keys;
	unsigned int nr_keys;
};

struct sid_ifc_unmodified_data {
	char  *mem;
	size_t size;
};

struct sid_ifc_request {
	sid_ifc_cmd_t cmd;
	uint64_t      flags;
	uint64_t      seqnum;

	union {
		struct sid_ifc_checkpoint_data checkpoint;
		struct sid_ifc_unmodified_data unmodified;
	} data;
};

struct sid_ifc_result;

const char   *sid_ifc_cmd_type_to_name(sid_ifc_cmd_t cmd);
sid_ifc_cmd_t sid_ifc_cmd_name_to_type(const char *cmd_name);
int           sid_ifc_req(struct sid_ifc_request *req, struct sid_ifc_result **res);
void          sid_ifc_result_free(struct sid_ifc_result *res);
int           sid_ifc_result_status_get(struct sid_ifc_result *res, uint64_t *status);
int           sid_ifc_result_protocol_get(struct sid_ifc_result *res, uint8_t *prot);
const char   *sid_ifc_result_data_get(struct sid_ifc_result *res, size_t *size_p);
#ifdef __cplusplus
}
#endif

#endif
