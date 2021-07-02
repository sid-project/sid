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

#include "base/common.h"

#include "base/util.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * Environment-related utilities.
 */

int sid_util_env_get_ull(const char *key, unsigned long long min, unsigned long long max, unsigned long long *val)
{
	unsigned long long ret;
	char *             env_val;
	char *             p;

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
		buf += n;
		total += n;
		len -= n;
	}
	return total;
}
