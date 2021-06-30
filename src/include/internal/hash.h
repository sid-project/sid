/*
 * This file is part of SID.
 *
 * Copyright (C) 2001-2004 Sistina Software, Inc. All rights reserved.
 * Copyright (C) 2004-2021 Red Hat, Inc. All rights reserved.
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

/*
 * Code adopted and redacted from lvm2 source tree (https://sourceware.org/lvm2).
 */

#ifndef _SID_HASH_H
#define _SID_HASH_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

struct hash_table;
struct hash_node;

typedef void (*hash_iterate_fn)(void *data);

struct hash_table *hash_create(unsigned size_hint);
void               hash_wipe(struct hash_table *t);
void               hash_destroy(struct hash_table *t);

int   hash_insert(struct hash_table *t, const void *key, uint32_t key_len, void *data, size_t data_len);
void *hash_lookup(struct hash_table *t, const void *key, uint32_t key_len, size_t *data_len);
void  hash_remove(struct hash_table *t, const void *key, uint32_t key_len);

unsigned hash_get_num_entries(struct hash_table *t);
size_t   hash_get_size(struct hash_table *t, size_t *meta_size, size_t *data_size);
void     hash_iter(struct hash_table *t, hash_iterate_fn f);

struct hash_node *hash_get_first(struct hash_table *t);
struct hash_node *hash_get_next(struct hash_table *t, struct hash_node *n);

char *hash_get_key(struct hash_table *t, struct hash_node *n, uint32_t *key_len);
void *hash_get_data(struct hash_table *t, struct hash_node *n, size_t *data_len);

/*
 * hash_insert() replaces the data of an existing
 * entry with a matching key if one exists.  Otherwise
 * it adds a new entry.
 *
 * hash_insert_allow_multiple() inserts a new entry if
 * another entry with the same key already exists.
 * data_len is the size of the data being inserted.
 *
 * If two entries with the same key exist,
 * (added using hash_insert_allow_multiple), then:
 * . hash_lookup() returns the first one it finds, and
 *   hash_lookup_with_data() returns the one with a matching
 *   data_len/data.
 * . hash_remove() removes the first one it finds, and
 *   hash_remove_with_data() removes the one with a matching
 *   data_len/data.
 *
 * If a single entry with a given key exists, and it has
 * zero data_len, then:
 * . hash_lookup() returns it
 * . hash_lookup_with_data(data_len=0) returns it
 * . hash_remove() removes it
 * . hash_remove_with_data(data_len=0) removes it
 *
 * hash_lookup_with_count() is a single call that will
 * both lookup a key's data and check if there is more
 * than one entry with the given key.
 *
 * (It is not meant to retrieve all the entries with the
 * given key.  In the common case where a single entry exists
 * for the key, it is useful to have a single call that will
 * both look up the data and indicate if multiple data
 * exist for the key.)
 *
 * hash_lookup_with_count:
 * . If no entries exist, the function returns NULL, and
 *   the count is set to 0.
 * . If only one entry exists, the data of that entry is
 *   returned and count is set to 1.
 * . If N entries exists, the data of the first entry is
 *   returned and count is set to N.
 */

int   hash_insert_allow_multiple(struct hash_table *t, const char *key, uint32_t key_len, void *data, size_t data_len);
void *hash_lookup_with_data(struct hash_table *t, const char *key, uint32_t key_len, void *data, size_t data_len);
void *hash_lookup_with_count(struct hash_table *t, const char *key, uint32_t key_len, size_t *data_len, unsigned *count);
void  hash_remove_with_data(struct hash_table *t, const char *key, uint32_t key_len, void *data, size_t data_len);

#define hash_iterate(v, h) for (v = hash_get_first((h)); v; v = hash_get_next((h), v))

/*
 * THE FUNCTIONS BELOW ARE EXTRA TO ORIGINAL CODE TAKEN FROM LVM2 SOURCE TREE AND ITS dm_hash_table IMPLEMENTATION.
 */

/*
 * hash_update_fn_t callback type to define hash_update's hash_update_fn callback function.
 * Function of this type returns:
 * 	0 for hash table to keep old_data
 * 	1 for hash table to update old_data with new_data (new_data may be modified and/or newly allocated by this function)
 */
typedef int (*hash_update_fn_t)(const void *key,
                                uint32_t    key_len,
                                void *      old_data,
                                size_t      old_data_len,
                                void **     new_data,
                                size_t *    new_data_len,
                                void *      hash_update_fn_arg);

/*
 * hash_update function calls hash_update_fn callback with hash_update_fn_arg right before the update
 * and based on callback's return value, it either keeps the old data or updates with new data.
 */
int hash_update(struct hash_table *t,
                const void *       key,
                uint32_t           key_len,
                void **            data,
                size_t *           data_len,
                hash_update_fn_t   hash_update_fn,
                void *             hash_update_fn_arg);

#ifdef __cplusplus
}
#endif

#endif
