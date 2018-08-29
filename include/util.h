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

#ifdef __cplusplus
extern "C" {
#endif

int util_pid_to_string(pid_t pid, char *buf, size_t buf_size);
int util_create_full_dir_path(const char *path);
udev_action_t util_get_udev_action_from_string(const char *str);
const char *util_get_string_from_udev_action(udev_action_t udev_action);
uint64_t util_get_now_usec(clockid_t clock_id);

#ifdef __cplusplus
}
#endif

#endif
