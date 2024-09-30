/*
 * SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
int sid_util_env_get_ull(const char *key, unsigned long long min, unsigned long long max, unsigned long long *val);

/*
 * fd-related utilities
 */
ssize_t sid_util_fd_read_all(int fd, void *buf, size_t len);

/*
 * Kernel-related utilities.
 */

/* Note: sid_util_kernel_get_arg reads kernel config line only once, then it is stored in internal static variable. */
bool sid_util_kernel_get_arg(const char *arg, char **value, int *ret_code);

/*
 * sysfs-related utilities.
 */

int sid_util_sysfs_get(const char *path, char *buf, size_t buf_size, size_t *char_count);

#ifdef __cplusplus
}
#endif

#endif
