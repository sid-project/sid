/*
 * Base64 encoding/decoding (RFC1341)
 * Copyright (c) 2005, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See BSD_LICENSE for more details.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef BASE64_H
#define BASE64_H

#include <stddef.h>

size_t         base64_len_encode(size_t in_len);
int            base64_encode(const unsigned char *src, size_t len, unsigned char *dest, size_t out_len);
unsigned char *base64_decode(const unsigned char *src, size_t len, size_t *out_len);

#endif /* BASE64_H */
