/*
 * SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _SID_BMP_H
#define _SID_BMP_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct bmp;

struct bmp *bmp_create(size_t bit_count, bool invert, int *ret_code);
void        bmp_destroy(struct bmp *bmp);
int         bmp_set_bit(struct bmp *bmp, size_t bit_pos);
int         bmp_unset_bit(struct bmp *bmp, size_t bit_pos);
bool        bmp_bit_is_set(struct bmp *bmp, size_t bit_pos, int *ret_code);
size_t      bmp_get_bit_count(struct bmp *bmp);
size_t      bmp_get_bit_set_count(struct bmp *bmp);

#ifdef __cplusplus
}
#endif

#endif
