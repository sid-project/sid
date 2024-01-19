/*
 * This file is part of SID.
 *
 * Copyright (C) 2017-2020 Red Hat, Inc. All rights reserved.
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

#ifndef _SID_BUFFER_COMMON_H
#define _SID_BUFFER_COMMON_H

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SID_BUFFER_SIZE_PREFIX_TYPE uint32_t
#define SID_BUFFER_SIZE_PREFIX_LEN  (sizeof(uint32_t))

typedef enum {
	SID_BUFFER_BACKEND_MALLOC,
	SID_BUFFER_BACKEND_MEMFD,
	SID_BUFFER_BACKEND_FILE,
} sid_buffer_backend_t;

typedef enum {
	SID_BUFFER_TYPE_LINEAR,
	SID_BUFFER_TYPE_VECTOR,
} sid_buffer_type_t;

typedef enum {
	SID_BUFFER_MODE_PLAIN,       /* plain buffer */
	SID_BUFFER_MODE_SIZE_PREFIX, /* has uint32_t size prefix */
} sid_buffer_mode_t;

struct sid_buffer_spec {
	sid_buffer_backend_t backend;
	sid_buffer_type_t    type;
	sid_buffer_mode_t    mode;

	union {
		struct {
			const char *path;
		} file;
	} ext;
};

struct sid_buffer_init {
	size_t size;
	size_t alloc_step;
	size_t limit;
};

struct sid_buffer_usage {
	size_t allocated;
	size_t used;
};

struct sid_buffer_stat {
	struct sid_buffer_spec  spec;
	struct sid_buffer_init  init;
	struct sid_buffer_usage usage;
};

#ifdef __cplusplus
}
#endif

#endif
