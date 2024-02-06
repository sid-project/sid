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

#define SID_BUF_SIZE_PREFIX_TYPE uint32_t
#define SID_BUF_SIZE_PREFIX_LEN  (sizeof(SID_BUF_SIZE_PREFIX_TYPE))

typedef enum {
	SID_BUF_BACKEND_MALLOC,
	SID_BUF_BACKEND_MEMFD,
	SID_BUF_BACKEND_FILE,
} sid_buf_backend_t;

typedef enum {
	SID_BUF_TYPE_LINEAR,
	SID_BUF_TYPE_VECTOR,
} sid_buf_type_t;

typedef enum {
	SID_BUF_MODE_PLAIN,       /* plain buffer */
	SID_BUF_MODE_SIZE_PREFIX, /* has SID_BUF_SIZE_PREFIX_TYPE size prefix */
} sid_buf_mode_t;

struct sid_buf_spec {
	sid_buf_backend_t backend;
	sid_buf_type_t    type;
	sid_buf_mode_t    mode;

	union {
		struct {
			const char *path;
		} file;
	} ext;
};

struct sid_buf_init {
	size_t size;
	size_t alloc_step;
	size_t limit;
};

struct sid_buf_usage {
	size_t allocated;
	size_t used;
};

struct sid_buf_stat {
	struct sid_buf_spec  spec;
	struct sid_buf_init  init;
	struct sid_buf_usage usage;
};

#ifdef __cplusplus
}
#endif

#endif
