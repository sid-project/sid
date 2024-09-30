/*
 * SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "internal/mem.h"

#include <string.h>

void *mem_zalloc(size_t size)
{
	void *p;

	if ((p = malloc(size)))
		memset(p, 0, size);

	return p;
}

void *mem_freen(void *mem)
{
	free(mem);
	return NULL;
}
