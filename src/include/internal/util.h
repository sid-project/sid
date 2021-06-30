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

#ifndef _SID_INTERNAL_UTIL_H
#define _SID_INTERNAL_UTIL_H

#include "internal/common.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <uuid/uuid.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 *   All functions that need to use allocated memory and they provide a
 *   possibility to use preallocated memory contain 'util_mem_t *mem'
 *   parameter to pass this preallocated memory for use.
 *   If 'mem' or 'mem->base' is NULL, the functions allocate the memory
 *   by themselves.
 */
typedef struct util_mem {
	void * base;
	size_t size;
} util_mem_t;

/*
 * Process-related utilities.
 */
int util_process_pid_to_str(pid_t pid, char *buf, size_t buf_size);

/*
 * Udev-related utilities.
 */
udev_action_t  util_udev_str_to_udev_action(const char *str);
udev_devtype_t util_udev_str_to_udev_devtype(const char *str);

/*
 * String-related utilities.
 */
#define UTIL_STR_DEFAULT_DELIMS " \t\r\n\v\f"
#define UTIL_STR_DEFAULT_QUOTES "\"\'"

char *util_str_rstr(const char *haystack, const char *needle);
char *util_str_combstr(const char *haystack, const char *prefix, const char *needle, const char *suffix, bool ignorecase);

typedef int (*util_str_token_fn_t)(const char *token, size_t len, void *data);
int util_str_iterate_tokens(const char *        str,
                            const char *        delims,
                            const char *        quotes,
                            util_str_token_fn_t token_fn,
                            void *              token_fn_data);

char *util_str_comb_to_str(util_mem_t *mem, const char *prefix, const char *str, const char *suffix);

char **util_str_comb_to_strv(util_mem_t *mem,
                             const char *prefix,
                             const char *str,
                             const char *suffix,
                             const char *delims,
                             const char *quotes);
char **util_strv_copy(util_mem_t *mem, const char **strv);

char *util_str_copy_substr(util_mem_t *mem, const char *str, size_t start, size_t len);

/*
 * Time-related utilities.
 */
uint64_t util_time_get_now_usec(clockid_t clock_id);

/*
 * UUID-related utilities.
 */
#define UTIL_UUID_STR_SIZE UUID_STR_LEN

char *util_uuid_gen_str(util_mem_t *mem);

/*
 * Kernel cmdline-related utilities.
 */
/* Note: util_cmdline_get_arg reads kernel config line only once, then it is stored in internal static variable. */
bool util_cmdline_get_arg(const char *arg, char **value, int *ret_code);

#ifdef __cplusplus
}
#endif

#endif
