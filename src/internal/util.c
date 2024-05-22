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

#include "internal/common.h"

#include "internal/util.h"

#include "internal/mem.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SYSTEM_PROC_BOOT_ID_PATH SYSTEM_PROC_PATH "/sys/kernel/random/boot_id"

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
                                        [UDEV_ACTION_UNKNOWN] = "unknown"};

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

const char *util_udev_action_to_str(const udev_action_t action)
{
	return udev_action_str[action];
}

static const char *udev_devtype_str[] = {
	[UDEV_DEVTYPE_DISK]      = UDEV_VALUE_DEVTYPE_DISK,
	[UDEV_DEVTYPE_PARTITION] = UDEV_VALUE_DEVTYPE_PARTITION,
	[UDEV_DEVTYPE_UNKNOWN]   = UDEV_VALUE_DEVTYPE_UNKNOWN,
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

const char *util_udev_devtype_to_str(udev_devtype_t devtype)
{
	return udev_devtype_str[devtype];
}

/*
 * String-related utilities.
 */

/*
 * Parse input string 'str' and get key-value pair.
 *
 * The format is:
 *     [<space>]key[<space>]=[<space>][<quote>]value[<quote>][<space>]
 *
 * The <space> is equal to UTIL_STR_DEFAULT_DELIMS.
 * The <quote> is one of UTIL_STR_DEFAULT_QUOTES.
 * The quotes are optional.
 * All spaces are skipped unless they are inside quotes.
 *
 * The input string 'str' is modified in place (chars changed to '\0' as necessary).
 *
 * Returns:
 *    0 on success ('key' and 'val' contain recognized key-value pair and
 *                  they are pointers to the original input string 'str')
 *   -ENODATA on empty string (spaces ignored)
 *   -EINVAL  on invalid format
 */
int util_str_kv_get(char *str, char **key, char **val)
{
	char *p, *k, *v;

	if (UTIL_STR_EMPTY(str))
		return -ENODATA;

	/* skip any spaces before key */
	str += strspn(str, UTIL_STR_DEFAULT_DELIMS);
	if (UTIL_STR_END(str))
		return -ENODATA;

	/* get the key */
	if (str[0] == '=')
		/* no key */
		return -EINVAL;
	k    = str;
	str += strcspn(str, UTIL_STR_DEFAULT_DELIMS "=");
	p    = str;
	if (str[0] != '=') {
		/* skip any spaces between key and '=' */
		str += strspn(str, UTIL_STR_DEFAULT_DELIMS);
		if (str[0] != '=')
			/* missing '=' */
			return -EINVAL;
	}
	UTIL_STR_END_PUT(p);
	str++;

	/* skip any spaces between '=' and value */
	str += strspn(str, UTIL_STR_DEFAULT_DELIMS);

	if ((p = strchr(UTIL_STR_DEFAULT_QUOTES, str[0]))) {
		/* get quoted value */
		v = ++str;
		if (!(str = strchr(str, p[0])))
			/* missing end quote */
			return -EINVAL;
		UTIL_STR_END_PUT(str);
		str++;
		if (UTIL_STR_END(str))
			/* finished - nothing else beyond the quoted value */
			goto out;
		/* skip any spaces beyond quoted value */
		str += strspn(str, UTIL_STR_DEFAULT_DELIMS);
	} else {
		/* get unquoted value */
		v    = str;
		str += strcspn(str, UTIL_STR_DEFAULT_DELIMS UTIL_STR_DEFAULT_QUOTES);
		if (UTIL_STR_END(str))
			/* finished - nothing else beyond the unquoted value */
			goto out;
		if (strchr(UTIL_STR_DEFAULT_QUOTES, str[0]))
			/* a quote in the middle of the unquoted value */
			return -EINVAL;
		p    = str;
		/* skip any spaces beyond unquoted value */
		str += strspn(str, UTIL_STR_DEFAULT_DELIMS);
		UTIL_STR_END_PUT(p);
	}

	if (!(UTIL_STR_END(str)))
		/* a garbage beyond the value */
		return -EINVAL;
out:
	*key = k;
	*val = v;
	return 0;
}

char *util_str_rstr(const char *haystack, const char *needle)
{
	size_t haystack_len, needle_len, pos;

	haystack_len = strlen(haystack);
	needle_len   = strlen(needle);

	if (needle_len > haystack_len)
		return NULL;

	for (pos = haystack_len - needle_len; pos > 0; pos--)
		if (!strncmp(haystack + pos, needle, needle_len))
			return (char *) haystack + pos;

	return NULL;
}

char *util_str_combstr(const char *haystack, const char *prefix, const char *needle, const char *suffix, bool ignorecase)
{
	size_t haystack_len, prefix_len, needle_len, suffix_len;
	bool   prefix_match, suffix_match;
	char  *needle_in_haystack;

	haystack_len = strlen(haystack);
	prefix_len   = prefix ? strlen(prefix) : 0;
	needle_len   = needle ? strlen(needle) : 0;
	suffix_len   = suffix ? strlen(suffix) : 0;

	if (prefix_len + needle_len + suffix_len > haystack_len)
		return NULL;

	if (ignorecase) {
		prefix_match       = !prefix_len || (strncasecmp(haystack, prefix, prefix_len) == 0);
		suffix_match       = !suffix_len || (strncasecmp(haystack + haystack_len - suffix_len, suffix, suffix_len) == 0);
		needle_in_haystack = needle ? strcasestr(haystack + prefix_len, needle) : NULL;
	} else {
		prefix_match       = !prefix_len || (strncmp(haystack, prefix, prefix_len) == 0);
		suffix_match       = !suffix_len || (strncmp(haystack + haystack_len - suffix_len, suffix, suffix_len) == 0);
		needle_in_haystack = needle ? strstr(haystack + prefix_len, needle) : NULL;
	}

	if (needle) {
		if (prefix_match && suffix_match && needle_in_haystack)
			return needle_in_haystack;
	} else {
		if (prefix_match && suffix_match)
			return (char *) haystack;
	}

	return NULL;
}

char *util_str_len_cpy(const char *str, size_t len, char *buf, size_t buf_size)
{
	char *cpy;

	/* We need to typecast 'size_t len' to int for the print formatter, check it fits! */
	if (len > INT_MAX)
		return NULL;

	if (buf) {
		/* Check we can fit 'len' bytes into buf, including the '\0' at the end! */
		if (!buf_size || (len > (buf_size - 1)))
			return NULL;

		if (snprintf(buf, buf_size, "%.*s", (int) len, str) < 0)
			cpy = NULL;
		else
			cpy = buf;
	} else {
		if (asprintf(&cpy, "%.*s", (int) len, str) < 0)
			cpy = NULL;
	}

	return cpy;
}

int util_str_tokens_iterate(const char         *str,
                            const char         *delims,
                            const char         *quotes,
                            util_str_token_fn_t token_fn,
                            void               *token_fn_data)
{
	const char *end_quote;
	size_t      len;
	int         r;
	bool        merge_back = false;
	size_t      quotes_len = quotes ? strlen(quotes) : 0;
	size_t      delims_len = delims ? strlen(delims) : 0;
	char        quote_or_delim[quotes_len + delims_len + 1];

	if (!str)
		return 0;

	if (!delims)
		delims = "";

	if (!quotes)
		quotes = "";

	snprintf(quote_or_delim, sizeof(quote_or_delim), "%s%s", quotes, delims);

	while (!UTIL_STR_END(str)) {
		str += strspn(str, delims); /* ignore delims at start */
		if (UTIL_STR_END(str))
			break;

		if (strchr(quotes, str[0])) {
			/* opening and closing quotes must match - it's an error otherwise */
			if (!(end_quote = strchr(str + 1, str[0])))
				return -EINVAL;
			/* skip the start quote */
			str++;
			if ((r = token_fn(str, end_quote - str, merge_back, token_fn_data)) < 0)
				return r;
			str = end_quote + 1;
		} else {
			len = strcspn(str, quote_or_delim); /* token */
			if ((r = token_fn(str, len, merge_back, token_fn_data)) < 0)
				return r;
			str += len;
		}
		/* If there is not a delimiter between the tokens, merge back */
		merge_back = (!strchr(delims, str[0]));
	}

	return 0;
}

char *util_str_comb_to_str(util_mem_t *mem, const char *prefix, const char *str, const char *suffix)
{
	size_t prefix_len = prefix ? strlen(prefix) : 0;
	size_t str_len    = str ? strlen(str) : 0;
	size_t suffix_len = suffix ? strlen(suffix) : 0;
	char  *p, *ret_str;

	if (mem) {
		if (prefix_len + str_len + suffix_len + 1 > mem->size)
			return NULL;

		ret_str = mem->base;
	} else {
		if (!(ret_str = malloc(prefix_len + str_len + suffix_len + 1)))
			return NULL;
	}

	p = ret_str;

	if (prefix_len) {
		memcpy(p, prefix, prefix_len);
		p += prefix_len;
	}

	if (str_len) {
		memcpy(p, str, str_len);
		p += str_len;
	}

	if (suffix_len) {
		memcpy(p, suffix, suffix_len);
		p += suffix_len;
	}

	UTIL_STR_END_PUT(p);
	return ret_str;
}

struct token_counter {
	size_t tokens;
	size_t chars;
};

static int _count_token(const char *token, size_t len, bool merge_back, void *data)
{
	struct token_counter *counter = data;

	if (!merge_back)
		counter->tokens++;
	counter->chars += len;

	return 0;
}

struct strv_iter {
	char **strv;
	size_t i;
	char  *s;
};

static int _copy_token_to_strv(const char *token, size_t len, bool merge_back, void *data)
{
	struct strv_iter *copier = data;

	if (merge_back && copier->i) {
		copier->s--;
		copier->i--;
	} else
		copier->strv[copier->i] = copier->s;

	memcpy(copier->s, token, len);
	copier->s += len;
	UTIL_STR_END_PUT(copier->s);

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

char **util_str_comb_to_strv(util_mem_t *mem,
                             const char *prefix,
                             const char *str,
                             const char *suffix,
                             const char *delims,
                             const char *quotes)
{
	struct token_counter counter = {0};
	struct strv_iter     copier  = {0};

	if (util_str_tokens_iterate(prefix, delims, quotes, _count_token, &counter) < 0 ||
	    util_str_tokens_iterate(str, delims, quotes, _count_token, &counter) < 0 ||
	    util_str_tokens_iterate(suffix, delims, quotes, _count_token, &counter) < 0)
		goto fail;

	if (mem) {
		if (_get_strv_full_mem_size(&counter) > mem->size)
			goto fail;

		copier.strv = mem->base;
	} else {
		if (!(copier.strv = malloc(_get_strv_full_mem_size(&counter))))
			goto fail;
	}

	copier.s = (char *) copier.strv + _get_strv_header_size(&counter);

	if (util_str_tokens_iterate(prefix, delims, quotes, _copy_token_to_strv, &copier) < 0 ||
	    util_str_tokens_iterate(str, delims, quotes, _copy_token_to_strv, &copier) < 0 ||
	    util_str_tokens_iterate(suffix, delims, quotes, _copy_token_to_strv, &copier) < 0)
		goto fail;

	copier.strv[counter.tokens] = NULL;
	return copier.strv;
fail:
	if (mem)
		return NULL;
	else
		return mem_freen(copier.strv);
}

char **util_str_vec_copy(util_mem_t *mem, const char **strv)
{
	const char         **p;
	struct token_counter counter = {0};
	struct strv_iter     copier  = {0};
	char                *ret_strv;

	for (p = strv; *p; p++) {
		if (_count_token(*p, strlen(*p), false, &counter) < 0)
			return NULL;
	}

	if (mem) {
		if (_get_strv_full_mem_size(&counter) > mem->size)
			return NULL;

		ret_strv = mem->base;
	} else {
		if (!(ret_strv = malloc(_get_strv_full_mem_size(&counter))))
			return NULL;
	}

	copier.strv = (char **) ret_strv;
	copier.s    = ret_strv + _get_strv_header_size(&counter);

	for (p = strv; *p; p++) {
		if (_copy_token_to_strv(*p, strlen(*p), false, &copier) < 0) {
			if (mem)
				return NULL;
			else
				return mem_freen(copier.strv);
		}
	}

	return copier.strv;
}

char *util_str_substr_copy(util_mem_t *mem, const char *str, size_t offset, size_t len)
{
	size_t str_len = strlen(str);

	if ((offset + len) > str_len)
		return NULL;

	if (!mem)
		return strndup(str + offset, len);

	if (len + 1 > mem->size)
		return NULL;

	memcpy(mem->base, str + offset, len);
	UTIL_STR_END_PUT((char *) mem->base + len);

	return mem->base;
}

/*
 * Time-related utilities.
 */

uint64_t util_time_now_usec_get(clockid_t clock_id)
{
	struct timespec ts;

	clock_gettime(clock_id, &ts);
	return (uint64_t) ts.tv_sec * 1000000 + (uint64_t) ts.tv_nsec / 1000;
}

/*
 * UUID-related utilities.
 */

static char *_get_uuid_mem(util_mem_t *mem)
{
	if (mem) {
		if (mem->size < UUID_STR_LEN)
			return NULL;

		return mem->base;
	} else
		return malloc(UUID_STR_LEN);
}

char *util_uuid_str_gen(util_mem_t *mem)
{
	uuid_t uu;
	char  *str;

	if (!(str = _get_uuid_mem(mem)))
		return NULL;

	uuid_generate(uu);
	uuid_unparse(uu, str);

	return str;
}

char *util_uuid_boot_id_get(util_mem_t *mem, int *ret_code)
{
	char *buf;
	FILE *f = NULL;
	int   r = 0;

	if (!(buf = _get_uuid_mem(mem))) {
		r = -ENOMEM;
		goto out;
	}

	if (!(f = fopen(SYSTEM_PROC_BOOT_ID_PATH, "r"))) {
		r = -errno;
		goto out;
	}

	if (!fgets(buf, UUID_STR_LEN, f)) {
		r = -1;
		goto out;
	}
out:
	if (f)
		fclose(f);

	if (r < 0) {
		if (!mem)
			free(buf);
		buf = NULL;
	}

	if (ret_code)
		*ret_code = r;

	return buf;
}
