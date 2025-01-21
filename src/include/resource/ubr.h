/*
 * SPDX-FileCopyrightText: (C) 2017-2025 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _SID_UBR_H
#define _SID_UBR_H

#include "resource/res.h"

#ifdef __cplusplus
extern "C" {
#endif

int sid_ubr_cmd_dbdump(sid_res_t *ubridge_res, const char *file_path);

#ifdef __cplusplus
}
#endif

#endif
