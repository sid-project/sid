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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "util.h"

int util_pid_to_string(pid_t pid, char *buf, size_t buf_size)
{
	int size;

	size = snprintf(buf, buf_size - 1, "%d", pid);

	if (size < 0 || size > (buf_size - 1))
		return -1;

	return 0;
}

int util_create_full_dir_path(const char *path)
{
	char *path_copy, *s, *e;
	struct stat st;
	int r;

	if (!(s = path_copy = strdup(path)))
		return -ENOMEM;

	for (;;) {
		/* handle multiple '/' */
		s += strspn(s, "/");

		/* handle '/' at the end of the path */
		if (!*s)
			break;

		if ((e = strchr(s, '/')))
			*e = '\0';

		if (mkdir(path_copy, 0777) < 0) {
			if (errno == EEXIST) {
				if (stat(path_copy, &st) < 0) {
					r = -errno;
					goto out;
				}
				if (!S_ISDIR(st.st_mode)) {
					r = -ENOTDIR;
					goto out;
				}
			} else {
				r = -errno;
				goto out;
			}
		}

		if ((s = e))
			*e = '/';
		else
			break;
	}
out:
	free(path_copy);
	return r;
}
