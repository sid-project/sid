/*
 * SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "internal/comp-attrs.h"

#include "internal/bmp.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

struct bmp {
	size_t   bit_count;
	size_t   bit_set_count;
	unsigned mem[];
} __packed;

#define BLOCK_SIZE     sizeof(unsigned)
#define BITS_PER_BLOCK (BLOCK_SIZE * CHAR_BIT)
static unsigned BLOCK_SHIFT = 0;

static unsigned _log2n_recursive(unsigned n)
{
	return n > 1 ? _log2n_recursive(n / 2) + 1 : 0;
}

__constructor static void _init_bmp()
{
	BLOCK_SHIFT = _log2n_recursive(BITS_PER_BLOCK);
}

struct bmp *bmp_create(size_t bit_count, bool invert, int *ret_code)
{
	size_t      mem_size;
	struct bmp *bmp = NULL;
	int         r   = 0;

	if (!bit_count) {
		r = -EINVAL;
		goto out;
	}

	mem_size = ((bit_count - 1) / BITS_PER_BLOCK + 1) * BLOCK_SIZE;

	if (!(bmp = malloc(sizeof(struct bmp) + mem_size))) {
		r = -ENOMEM;
		goto out;
	}

	bmp->bit_count = bit_count;

	if (invert) {
		memset(bmp->mem, UCHAR_MAX, mem_size);
		bmp->bit_set_count = bit_count;
	} else {
		memset(bmp->mem, 0, mem_size);
		bmp->bit_set_count = 0;
	}
out:
	if (ret_code)
		*ret_code = r;
	return bmp;
}

void bmp_destroy(struct bmp *bmp)
{
	free(bmp);
}

static int _get_coord(struct bmp *bmp, size_t bit_pos, unsigned *block, unsigned *bit)
{
	if (bit_pos >= bmp->bit_count)
		return -ERANGE;

	*block = bit_pos >> BLOCK_SHIFT;
	*bit   = 1 << (bit_pos & (BITS_PER_BLOCK - 1));

	return 0;
}

int bmp_set_bit(struct bmp *bmp, size_t bit_pos)
{
	unsigned block, bit;
	int      r;

	if ((r = _get_coord(bmp, bit_pos, &block, &bit)) < 0)
		return r;

	if (!(bmp->mem[block] & bit)) {
		bmp->mem[block] |= bit;
		bmp->bit_set_count++;
	}

	return 0;
}

int bmp_unset_bit(struct bmp *bmp, size_t bit_pos)
{
	unsigned block, bit;
	int      r;

	if ((r = _get_coord(bmp, bit_pos, &block, &bit)) < 0)
		return r;

	if (bmp->mem[block] & bit) {
		bmp->mem[block] &= ~bit;
		bmp->bit_set_count--;
	}

	return 0;
}

bool bmp_bit_is_set(struct bmp *bmp, size_t bit_pos, int *ret_code)
{
	unsigned block, bit;
	int      r;

	if ((r = _get_coord(bmp, bit_pos, &block, &bit)) < 0) {
		if (ret_code)
			*ret_code = r;
		return 0;
	}

	return bmp->mem[block] & bit;
}

size_t bmp_get_bit_count(struct bmp *bmp)
{
	return bmp->bit_count;
}

size_t bmp_get_bit_set_count(struct bmp *bmp)
{
	return bmp->bit_set_count;
}
