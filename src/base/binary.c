/*
 * Base64 encoding/decoding (RFC1341)
 * Copyright (c) 2005-2011, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2021 Red Hat, Inc. All rights reserved.
 *
 * This software may be distributed under the terms of the BSD license.
 * See BSD_LICENSE for more details.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "base/binary.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

static const unsigned char base64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * base64_len_encode - Size necessary for base64_encode
 * @in_len: Length of the data to be encoded
 * Returns: output length needed to store the base64 encoded data, including
 * padding and NULL bytes, or 0 if the buffer overflowed.
 */

size_t base64_len_encode(size_t in_len)
{
	size_t out_len = 1; /* NULL termination */

	if (!in_len)
		return out_len;
	out_len += ((in_len - 1) / 3 + 1) * 4; /* 4 bytes for every 3 (rounded up) */
	if (out_len < in_len)
		return 0;
	return out_len;
}

/**
 * base64_encode - Base64 encode
 * @src: Data to be encoded
 * @in_len: Length of the data to be encoded
 * @dest: pre-allocated buffer to store the encoded data
 * @out_len: Length of the encoded data
 * Returns: buffer of out_len bytes of encoded data
 *
 * Returned buffer is nul terminated to make it easier to use as a C string.
 */
int base64_encode(const unsigned char *src, size_t in_len, unsigned char *dest, size_t out_len)
{
	unsigned char *      pos;
	const unsigned char *end, *in;
	size_t               check_size;

	check_size = base64_len_encode(in_len);
	if ((in_len && !src) || !dest || check_size == 0 || check_size > out_len)
		return -EINVAL;

	end = src + in_len;
	in  = src;
	pos = dest;
	while (end - in >= 3) {
		*pos++ = base64_table[in[0] >> 2];
		*pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
		*pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
		*pos++ = base64_table[in[2] & 0x3f];
		in += 3;
	}

	if (end - in) {
		*pos++ = base64_table[in[0] >> 2];
		if (end - in == 1) {
			*pos++ = base64_table[(in[0] & 0x03) << 4];
			*pos++ = '=';
		} else {
			*pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
			*pos++ = base64_table[(in[1] & 0x0f) << 2];
		}
		*pos++ = '=';
	}

	*pos = '\0';
	return 0;
}

/**
 * base64_decode - Base64 decode
 * @src: Data to be decoded
 * @len: Length of the data to be decoded
 * @out_len: Pointer to output length variable
 * Returns: Allocated buffer of out_len bytes of decoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer.
 */
unsigned char *base64_decode(const unsigned char *src, size_t len, size_t *out_len)
{
	unsigned char dtable[256], *out, *pos, block[4], tmp;
	size_t        i, count, olen;
	int           pad = 0;

	memset(dtable, 0x80, 256);
	for (i = 0; i < sizeof(base64_table) - 1; i++)
		dtable[base64_table[i]] = (unsigned char) i;
	dtable['='] = 0;

	count = 0;
	for (i = 0; i < len; i++) {
		if (dtable[src[i]] != 0x80)
			count++;
	}

	if (count == 0 || count % 4)
		return NULL;

	olen = count / 4 * 3;
	pos = out = malloc(olen);
	if (out == NULL)
		return NULL;

	count = 0;
	for (i = 0; i < len; i++) {
		tmp = dtable[src[i]];
		if (tmp == 0x80)
			continue;

		if (src[i] == '=')
			pad++;
		block[count] = tmp;
		count++;
		if (count == 4) {
			*pos++ = (block[0] << 2) | (block[1] >> 4);
			*pos++ = (block[1] << 4) | (block[2] >> 2);
			*pos++ = (block[2] << 6) | block[3];
			count  = 0;
			if (pad) {
				if (pad == 1)
					pos--;
				else if (pad == 2)
					pos -= 2;
				else {
					/* Invalid padding */
					free(out);
					return NULL;
				}
				break;
			}
		}
	}

	*out_len = pos - out;
	return out;
}
