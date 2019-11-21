/*
 * This file is part of SID.
 *
 * Copyright (C) 2017-2018 Red Hat, Inc. All rights reserved.
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

#ifndef _SID_UTIL_H
#define _SID_UTIL_H

#include "types.h"

#include <stdio.h>
#include <stdint.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <uuid/uuid.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UTIL_UUID_STR_SIZE UUID_STR_LEN

int util_pid_to_str(pid_t pid, char *buf, size_t buf_size);

udev_action_t util_str_to_udev_action(const char *str);
udev_devtype_t util_str_to_udev_devtype(const char *str);

uint64_t util_get_now_usec(clockid_t clock_id);

char *util_strrstr(const char *haystack, const char *needle);

char *util_gen_uuid_str(char *buf, size_t buf_len);

int util_get_env_ull(const char *key, unsigned long long min, unsigned long long max, unsigned long long *val);

#ifdef __cplusplus
}
#endif

#endif
