/*
 * SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _SID_MEM_H
#define _SID_MEM_H

#include "internal/comp-attrs.h"

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/* align memory pointer 'p' upwards to 'a' bytes */
#define MEM_ALIGN_UP(p, a)     (((uintptr_t) (p) + (a) - 1) & ~((a) - 1))

/* get padding in bytes needed to align memory pointer 'p' upwards to 'a' bytes */
#define MEM_ALIGN_UP_PAD(p, a) (-((uintptr_t) (p)) & ((a) - 1))

void *mem_zalloc(size_t size) __malloc;
void *mem_freen(void *mem);

#ifdef __cplusplus
}
#endif

#endif
