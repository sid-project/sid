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

#ifndef _SID_BASE_UTIL_H
#define _SID_BASE_UTIL_H

#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Environment-related utilities.
 */
int sid_util_env_ull_get(const char *key, unsigned long long min, unsigned long long max, unsigned long long *val);

/*
 * fd-related utilities
 */
ssize_t sid_util_fd_read_all(int fd, void *buf, size_t len);

/*
 * Kernel cmdline-related utilities.
 */

/* Note: sid_util_kernel_cmdline_arg_get reads kernel config line only once, then it is stored in internal static variable. */
bool sid_util_kernel_cmdline_arg_get(const char *arg, char **value, int *ret_code);

/*
 * sysfs-related utilities.
 */

int sid_util_sysfs_get(const char *path, char *buf, size_t buf_size, size_t *char_count);

#ifdef __cplusplus
}
#endif

#endif
