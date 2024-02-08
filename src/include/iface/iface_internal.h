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

#ifndef _SID_IFACE_INTERNAL_H
#define _SID_IFACE_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include "internal/comp-attrs.h"

#include "iface/iface.h"

struct sid_ifc_msg_header {
	uint64_t status;
	uint8_t  prot;
	uint8_t  cmd;
	uint16_t flags;
} __packed;

#define SID_IFC_MSG_HEADER_SIZE sizeof(struct sid_ifc_msg_header)

#define SID_IFC_SOCKET_PATH     "\0sid-ubridge.socket"
#define SID_IFC_SOCKET_PATH_LEN (sizeof(SID_IFC_SOCKET_PATH) - 1)

#ifdef __cplusplus
}
#endif

#endif
