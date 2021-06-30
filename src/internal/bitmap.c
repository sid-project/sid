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

#include "internal/bitmap.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

struct bitmap {
	size_t   bit_count;
	size_t   bit_set_count;
	unsigned mem[];
} __attribute__((packed));

#define BLOCK_SIZE     sizeof(unsigned)
#define BITS_PER_BLOCK (BLOCK_SIZE * CHAR_BIT)
static unsigned BLOCK_SHIFT = 0;

static unsigned _log2n_recursive(unsigned n)
{
	return n > 1 ? _log2n_recursive(n / 2) + 1 : 0;
}

__attribute__((constructor)) static void _init_bitmap()
{
	BLOCK_SHIFT = _log2n_recursive(BITS_PER_BLOCK);
}

struct bitmap *bitmap_create(size_t bit_count, bool invert, int *ret_code)
{
	size_t         mem_size;
	struct bitmap *bitmap = NULL;
	int            r      = 0;

	if (!bit_count) {
		r = -EINVAL;
		goto out;
	}

	mem_size = ((bit_count - 1) / BITS_PER_BLOCK + 1) * BLOCK_SIZE;

	if (!(bitmap = malloc(sizeof(struct bitmap) + mem_size))) {
		r = -ENOMEM;
		goto out;
	}

	bitmap->bit_count = bit_count;

	if (invert) {
		memset(bitmap->mem, UCHAR_MAX, mem_size);
		bitmap->bit_set_count = bit_count;
	} else {
		memset(bitmap->mem, 0, mem_size);
		bitmap->bit_set_count = 0;
	}
out:
	if (ret_code)
		*ret_code = r;
	return bitmap;
}

void bitmap_destroy(struct bitmap *bitmap)
{
	free(bitmap);
}

int _get_coord(struct bitmap *bitmap, size_t bit_pos, unsigned *block, unsigned *bit)
{
	if (bit_pos >= bitmap->bit_count)
		return -ERANGE;

	*block = bit_pos >> BLOCK_SHIFT;
	*bit   = 1 << (bit_pos & (BITS_PER_BLOCK - 1));

	return 0;
}

int bitmap_bit_set(struct bitmap *bitmap, size_t bit_pos)
{
	unsigned block, bit;
	int      r;

	if ((r = _get_coord(bitmap, bit_pos, &block, &bit)) < 0)
		return r;

	if (!(bitmap->mem[block] & bit)) {
		bitmap->mem[block] |= bit;
		bitmap->bit_set_count++;
	}

	return 0;
}

int bitmap_bit_unset(struct bitmap *bitmap, size_t bit_pos)
{
	unsigned block, bit;
	int      r;

	if ((r = _get_coord(bitmap, bit_pos, &block, &bit)) < 0)
		return r;

	if (bitmap->mem[block] & bit) {
		bitmap->mem[block] &= ~bit;
		bitmap->bit_set_count--;
	}

	return 0;
}

bool bitmap_bit_is_set(struct bitmap *bitmap, size_t bit_pos, int *ret_code)
{
	unsigned block, bit;
	int      r;

	if ((r = _get_coord(bitmap, bit_pos, &block, &bit)) < 0) {
		if (ret_code)
			*ret_code = r;
		return 0;
	}

	return bitmap->mem[block] & bit;
}

size_t bitmap_get_bit_count(struct bitmap *bitmap)
{
	return bitmap->bit_count;
}

size_t bitmap_get_bit_set_count(struct bitmap *bitmap)
{
	return bitmap->bit_set_count;
}
