/*
 * SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _SID_IFC_INTERNAL_H
#define _SID_IFC_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include "internal/comp-attrs.h"

#include "iface/ifc.h"

struct sid_ifc_msg_header {
	uint64_t status;
	uint8_t  prot;
	uint8_t  cmd;
	uint16_t flags;
} __packed;

#define SID_IFC_MSG_HEADER(...) ((struct sid_ifc_msg_header) {__VA_ARGS__})

#define SID_IFC_MSG_HEADER_SIZE sizeof(struct sid_ifc_msg_header)

#define SID_IFC_SOCKET_PATH     "\0sid-ubridge.socket"
#define SID_IFC_SOCKET_PATH_LEN (sizeof(SID_IFC_SOCKET_PATH) - 1)

#ifdef __cplusplus
}
#endif

#endif
