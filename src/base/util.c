/*
 * This file is part of SID.
 *
 * Copyright (C) 2017-2019 Red Hat, Inc. All rights reserved.
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

#include "base/mem.h"
#include "base/util.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

/*
 * Process-related utilities.
 */

int util_process_pid_to_str(pid_t pid, char *buf, size_t buf_size)
{
	int size;

	size = snprintf(buf, buf_size, "%d", pid);

	if (size < 0 || size >= buf_size)
		return -1;

	return 0;
}

/*
 * Udev-related utilities.
 */

static const char *udev_action_str[] = {[UDEV_ACTION_ADD]     = "add",
                                        [UDEV_ACTION_CHANGE]  = "change",
                                        [UDEV_ACTION_REMOVE]  = "remove",
                                        [UDEV_ACTION_MOVE]    = "move",
                                        [UDEV_ACTION_ONLINE]  = "online",
                                        [UDEV_ACTION_OFFLINE] = "offline",
                                        [UDEV_ACTION_BIND]    = "bind",
                                        [UDEV_ACTION_UNBIND]  = "unbind",
                                        [UDEV_ACTION_UNKNOWN] = "unknown"
                                       };

udev_action_t util_udev_str_to_udev_action(const char *str)
{
	if (!strcasecmp(str, udev_action_str[UDEV_ACTION_ADD]))
		return UDEV_ACTION_ADD;
	else if (!strcasecmp(str, udev_action_str[UDEV_ACTION_CHANGE]))
		return UDEV_ACTION_CHANGE;
	else if (!strcasecmp(str, udev_action_str[UDEV_ACTION_REMOVE]))
		return UDEV_ACTION_REMOVE;
	else if (!strcasecmp(str, udev_action_str[UDEV_ACTION_MOVE]))
		return UDEV_ACTION_MOVE;
	else if (!strcasecmp(str, udev_action_str[UDEV_ACTION_ONLINE]))
		return UDEV_ACTION_ONLINE;
	else if (!strcasecmp(str, udev_action_str[UDEV_ACTION_OFFLINE]))
		return UDEV_ACTION_OFFLINE;
	else if (!strcasecmp(str, udev_action_str[UDEV_ACTION_BIND]))
		return UDEV_ACTION_BIND;
	else if (!strcasecmp(str, udev_action_str[UDEV_ACTION_UNBIND]))
		return UDEV_ACTION_UNBIND;
	else
		return UDEV_ACTION_UNKNOWN;
}

static const char *udev_devtype_str[] = {[UDEV_DEVTYPE_DISK]      = "disk",
                                         [UDEV_DEVTYPE_PARTITION] = "partition",
                                         [UDEV_DEVTYPE_UNKNOWN]   = "unknown"
                                        };

udev_devtype_t util_udev_str_to_udev_devtype(const char *str)
{
	if (!strcasecmp(str, udev_devtype_str[UDEV_DEVTYPE_DISK]))
		return UDEV_DEVTYPE_DISK;
	else if (!strcasecmp(str, udev_devtype_str[UDEV_DEVTYPE_PARTITION]))
		return UDEV_DEVTYPE_PARTITION;
	else
		return UDEV_DEVTYPE_UNKNOWN;
}

/*
 * String-related utilities.
 */

char *util_str_rstr(const char *haystack, const char *needle)
{
	size_t haystack_len, needle_len, pos;

	haystack_len = strlen(haystack);
	needle_len = strlen(needle);

	if (needle_len > haystack_len)
		return NULL;

	for (pos = haystack_len - needle_len; pos > 0; pos--)
		if (!strncmp(haystack + pos, needle, needle_len))
			return (char *) haystack + pos;

	return NULL;
}

const char *_get_quote(const char *str, const char *quotes, const char quote)
{
	const char *prev;
	size_t esc_count;

	if (!(str = quote ? strchr(str, quote) : strpbrk(str, quotes)))
		return NULL;

	for (esc_count = 0, prev = str - 1; prev >= str && *prev == '\\'; prev--)
		esc_count++;

	if (esc_count % 2 == 0)
		/* even number of escapes before quote char do not escape it - return the quote */
		return str;

	/* odd number of escapes before quote char do escape it - look for another quote char */
	return _get_quote(str + 1, quotes, quote);
}

int util_str_iterate_tokens(const char *str, const char *delims, const char *quotes, util_str_token_fn_t token_fn, void *token_fn_data)
{
	const char *start_quote, *end_quote;
	size_t len;
	int r;

	if (!str)
		return 0;

	if (!delims)
		delims = "";

	if (!quotes)
		quotes = "";

	while (str[0]) {
		str += strspn(str, delims); /* ignore delims at start */

		if (!(start_quote = _get_quote(str, quotes, 0))) {
			/* we don't have any more quotes - read tokens up to the end of the string */
			while (str[0]) {
				len = strcspn(str, delims); /* token */
				if ((r = token_fn(str, len, token_fn_data)) < 0)
					return r;
				str += len;
				str += strspn(str, delims); /* delims */
			}
			break;
		}

		/* we always require opening and closing quotes to match - it's an error otherwise */
		if (!(end_quote = _get_quote(start_quote + 1, quotes, start_quote[0])))
			return -EINVAL;

		/* we do have quotes - read tokens up to the start quote first */
		while (str < start_quote) {
			len = strcspn(str, delims); /* token */
			if ((r = token_fn(str, len, token_fn_data)) < 0)
				return r;
			str += len;
			str += strspn(str, delims);  /* delims */
		}

		/* skip the start quote */
		str++;

		/* read the word between start and end quote */
		token_fn(str, end_quote - start_quote - 1, token_fn_data);

		/* continue further with the part after the end quote */
		str = end_quote + 1;
	}

	return 0;
}

struct token_counter {
	size_t tokens;
	size_t chars;
};

static int _count_token(const char *token, size_t len, void *data)
{
	struct token_counter *counter = data;

	counter->tokens++;
	counter->chars += len;

	return 0;
}

struct strv_iter {
	char **strv;
	size_t i;
	char *s;
};

static int _copy_token_to_strv(const char *token, size_t len, void *data)
{
	struct strv_iter *copier = data;

	memcpy(copier->s, token, len);
	copier->strv[copier->i] = copier->s;
	copier->s += len;
	*copier->s = '\0';

	copier->s++;
	copier->i++;

	return 0;
}

static size_t _get_strv_header_size(struct token_counter *counter)
{
	/* 'counter.tokens' to include NULL item at the end of the vector */
	return (counter->tokens + 1) * sizeof(char *);
}

static size_t _get_strv_full_mem_size(struct token_counter *counter)
{
	/*
	 * Complete memory needed is:
	 *   - memory for storing the vector itself ('vector header') where the vector is NULL-terminated
	 *   - memory for storing the strings where each string is NULL-terminated
	 */
	return _get_strv_header_size(counter) + counter->chars + counter->tokens;
}

char **util_str_comb_to_strv(const char *prefix, const char *str, const char *suffix, const char *delims, const char *quotes)
{
	struct token_counter counter = {0};
	struct strv_iter copier = {0};

	if (util_str_iterate_tokens(prefix, delims, quotes, _count_token, &counter) < 0 ||
	    util_str_iterate_tokens(str, delims, quotes, _count_token, &counter) < 0 ||
	    util_str_iterate_tokens(suffix, delims, quotes, _count_token, &counter) < 0)
		goto fail;

	if (!(copier.strv = malloc(_get_strv_full_mem_size(&counter))))
		goto fail;

	copier.s = (char *) copier.strv + _get_strv_header_size(&counter);

	if (util_str_iterate_tokens(prefix, delims, quotes, _copy_token_to_strv, &copier) < 0 ||
	    util_str_iterate_tokens(str, delims, quotes, _copy_token_to_strv, &copier) < 0 ||
	    util_str_iterate_tokens(suffix, delims, quotes, _copy_token_to_strv, &copier) < 0)
		goto fail;

	copier.strv[counter.tokens] = NULL;
	return copier.strv;
fail:
	return freen(copier.strv);
}

char **util_strv_copy(const char **strv)
{
	const char **p;
	struct token_counter counter = {0};
	struct strv_iter copier = {0};
	char *mem;

	for (p = strv; *p; p++) {
		if (_count_token(*p, strlen(*p), &counter) < 0)
			return NULL;
	}

	if (!(mem = malloc(_get_strv_full_mem_size(&counter))))
		return NULL;

	copier.strv = (char **) mem;
	copier.s = mem + _get_strv_header_size(&counter);

	for (p = strv; *p; p++) {
		if (_copy_token_to_strv(*p, strlen(*p), &copier) < 0)
			return freen(mem);
	}

	return copier.strv;
}

/*
 * Time-related utilities.
 */

uint64_t util_time_get_now_usec(clockid_t clock_id)
{
	struct timespec ts;

	clock_gettime(clock_id, &ts);
	return (uint64_t) ts.tv_sec * 1000000 + (uint64_t) ts.tv_nsec / 1000;
}

/*
 * UUID-related utilities.
 */

char *util_uuid_gen_str(char *buf, size_t buf_len)
{
	uuid_t uu;
	char *str;

	if (buf) {
		if (buf_len < UUID_STR_LEN)
			return NULL;
		str = buf;
	} else {
		if (!(str = malloc(UUID_STR_LEN)))
			return NULL;
	}

	uuid_generate(uu);
	uuid_unparse(uu, str);

	return str;
}

/*
 * Environment-related utilities.
 */

int util_env_get_ull(const char *key, unsigned long long min, unsigned long long max, unsigned long long *val)
{
	unsigned long long ret;
	char *env_val;
	char *p;

	if (!(env_val = getenv(key)))
		return -ENOKEY;

	errno = 0;
	ret = strtoull(env_val, &p, 10);
	if (errno || !p || *p)
		return -EINVAL;

	if (min != max)
		if (ret < min || ret > max)
			return -ERANGE;

	*val = ret;
	return 0;
}

/*
 * Kernel cmdline-related utilities.
 */

int _get_proc_cmdline(char *buf, off_t size)
{
	int fd, r = 0;
	off_t len = 0;
	ssize_t bytes;

	if (!buf || !size)
		return -EINVAL;

	fd = open("/proc/cmdline", O_RDONLY);
	if (fd < 0) {
		return (errno)? -errno : -1;
	}
	while (len < size) {
		bytes = read(fd, buf + len, size - len);
		if (!bytes)
			break;
		if (bytes < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			r = (errno)? -errno : -1;
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
bool util_cmdline_get_arg(const char *arg, char **value, int *ret_code)
{
	int r = 0;
	static char buf[4097];
	char *ptr, *limit, *next, *val, *end;

	if (!arg) {
		r = -EINVAL;
		goto out;
	}

	if (buf[0] == '\0')
		r = _get_proc_cmdline(buf, 4096);
	if (r)
		goto out;

	end = buf + strlen(buf);
	next = buf;
	while (next) {
		while (*next && strchr(DELIM, *next))
			next++;
		if (!*next)
			goto out;
		ptr = next;
		next = strpbrk(ptr, DELIM);
		val = strchr(ptr, '=');
		if (next && val >= next)
			val = NULL;
		limit = (val)?: (next)?: end;
		if (strlen(arg) != limit - ptr ||
		    strncmp(arg, ptr, limit - ptr))
			continue;
		if (value) {
			if (!val) {
				r = -EINVAL;
				goto out;
			}
			limit = (next)?: end;
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
		*ret_code = (r < 0)? r : 0;
	return (r > 0);
}
