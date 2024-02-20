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

#include "base/util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Environment-related utilities.
 */

int sid_util_env_ull_get(const char *key, unsigned long long min, unsigned long long max, unsigned long long *val)
{
	unsigned long long ret;
	char              *env_val;
	char              *p;

	if (!(env_val = getenv(key)))
		return -ENOKEY;

	errno = 0;
	ret   = strtoull(env_val, &p, 10);
	if (errno || !p || *p)
		return -EINVAL;

	if (min != max)
		if (ret < min || ret > max)
			return -ERANGE;

	*val = ret;
	return 0;
}

/*
 * fd-related utilites
 */

ssize_t sid_util_fd_read_all(int fd, void *buf, size_t len)
{
	ssize_t n, total = 0;

	while (len) {
		n = read(fd, buf, len);
		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			return -errno;
		}
		if (!n)
			return total;
		buf   += n;
		total += n;
		len   -= n;
	}
	return total;
}

/*
 * Kernel cmdline-related utilities.
 */

static int _get_proc_cmdline(char *buf, off_t size)
{
	int     fd, r = 0;
	off_t   len = 0;
	ssize_t bytes;

	if (!buf || !size)
		return -EINVAL;

	fd = open("/proc/cmdline", O_RDONLY);
	if (fd < 0) {
		return (errno) ? -errno : -1;
	}
	while (len < size) {
		bytes = read(fd, buf + len, size - len);
		if (!bytes)
			break;
		if (bytes < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			r = (errno) ? -errno : -1;
			goto out;
		}
		len += bytes;
	}
out:
	close(fd);
	if (r)
		memset(buf, 0, size);
	return r;
}

#define DELIM " \t\n"

bool sid_util_kernel_cmdline_arg_get(const char *arg, char **value, int *ret_code)
{
	int         r = 0;
	static char buf[4097];
	char       *ptr, *limit, *next, *val, *end;

	if (!arg) {
		r = -EINVAL;
		goto out;
	}

	if (buf[0] == '\0')
		r = _get_proc_cmdline(buf, 4096);

	if (r)
		goto out;

	end  = buf + strlen(buf);
	next = buf;
	while (next) {
		while (*next && strchr(DELIM, *next))
			next++;
		if (!*next)
			goto out;
		ptr  = next;
		next = strpbrk(ptr, DELIM);
		val  = strchr(ptr, '=');
		if (next && val >= next)
			val = NULL;
		limit = (val) ?: (next) ?: end;
		if (strlen(arg) != limit - ptr || strncmp(arg, ptr, limit - ptr))
			continue;
		if (value) {
			if (!val) {
				r = -EINVAL;
				goto out;
			}
			limit  = (next) ?: end;
			*value = strndup(val, limit - val);
			if (!*value) {
				r = -ENOMEM;
				goto out;
			}
		}
		r = 1;
		break;
	}

out:
	if (ret_code)
		*ret_code = (r < 0) ? r : 0;
	return (r > 0);
}

/*
 * sysfs-related utilities
 */

int sid_util_sysfs_get(const char *path, char *buf, size_t buf_size, size_t *char_count)
{
	FILE  *fp;
	size_t len;
	int    r = -1;

	if (!(fp = fopen(path, "r"))) {
		r = -errno;
		goto out;
	}

	if (!(fgets(buf, buf_size, fp))) {
		r = -EIO;
		goto out;
	}

	if ((len = strlen(buf)) && buf[len - 1] == '\n')
		buf[--len] = '\0';

	if (char_count)
		*char_count = len + 1;

	r = 0;
out:
	if (fp)
		fclose(fp);

	return r;
}
