/*
 * Base64 encoding/decoding (RFC1341)
 * Copyright (c) 2005, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See BSD_LICENSE for more details.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SID_CONV_BASE64_H
#define SID_CONV_BASE64_H

#include <stddef.h>

size_t         sid_conv_base64_encoded_len(size_t in_len);
int            sid_conv_base64_encode(const unsigned char *src, size_t len, unsigned char *dest, size_t out_len);
unsigned char *sid_conv_base64_decode(const unsigned char *src, size_t len, size_t *out_len);

#endif /* SID_CONV_BASE64_H */
