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

#ifndef _SID_BITMAP_H
#define _SID_BITMAP_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct bitmap;

struct bitmap *bitmap_create(size_t bit_count, bool invert, int *ret_code);
void           bitmap_destroy(struct bitmap *bitmap);
int            bitmap_bit_set(struct bitmap *bitmap, size_t bit_pos);
int            bitmap_bit_unset(struct bitmap *bitmap, size_t bit_pos);
bool           bitmap_bit_is_set(struct bitmap *bitmap, size_t bit_pos, int *ret_code);
size_t         bitmap_get_bit_count(struct bitmap *bitmap);
size_t         bitmap_get_bit_set_count(struct bitmap *bitmap);

#ifdef __cplusplus
}
#endif

#endif
