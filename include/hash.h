/*
 * This file is part of SID.
 *
 * Copyright (C) 2001-2004 Sistina Software, Inc. All rights reserved.
 * Copyright (C) 2004-2018 Red Hat, Inc. All rights reserved.
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
 * Code adopted from lvm2 source tree (https://sourceware.org/lvm2).
 */

#ifndef _SID_HASH_H
#define _SID_HASH_H

#include <stdint.h>

struct hash_table;
struct hash_node;

typedef void (*hash_iterate_fn) (void *data);

struct hash_table *hash_create(unsigned size_hint);
void hash_destroy(struct hash_table *t);
void hash_wipe(struct hash_table *t);

void *hash_lookup(struct hash_table *t, const char *key);
int hash_insert(struct hash_table *t, const char *key, void *data);
void hash_remove(struct hash_table *t, const char *key);

void *hash_lookup_binary(struct hash_table *t, const void *key, uint32_t len);
int hash_insert_binary(struct hash_table *t, const void *key, uint32_t len, void *data);
void hash_remove_binary(struct hash_table *t, const void *key, uint32_t len);

unsigned hash_get_num_entries(struct hash_table *t);
void hash_iter(struct hash_table *t, hash_iterate_fn f);

char *hash_get_key(struct hash_table *t, struct hash_node *n);
void *hash_get_data(struct hash_table *t, struct hash_node *n);
struct hash_node *hash_get_first(struct hash_table *t);
struct hash_node *hash_get_next(struct hash_table *t, struct hash_node *n);

/*
 * hash_insert() replaces the value of an existing
 * entry with a matching key if one exists.  Otherwise
 * it adds a new entry.
 *
 * hash_insert_with_val() inserts a new entry if
 * another entry with the same key already exists.
 * val_len is the size of the data being inserted.
 *
 * If two entries with the same key exist,
 * (added using hash_insert_allow_multiple), then:
 * . hash_lookup() returns the first one it finds, and
 *   hash_lookup_with_val() returns the one with a matching
 *   val_len/val.
 * . hash_remove() removes the first one it finds, and
 *   hash_remove_with_val() removes the one with a matching
 *   val_len/val.
 *
 * If a single entry with a given key exists, and it has
 * zero val_len, then:
 * . hash_lookup() returns it
 * . hash_lookup_with_val(val_len=0) returns it
 * . hash_remove() removes it
 * . hash_remove_with_val(val_len=0) removes it
 *
 * hash_lookup_with_count() is a single call that will
 * both lookup a key's value and check if there is more
 * than one entry with the given key.
 *
 * (It is not meant to retrieve all the entries with the
 * given key.  In the common case where a single entry exists
 * for the key, it is useful to have a single call that will
 * both look up the value and indicate if multiple values
 * exist for the key.)
 *
 * hash_lookup_with_count:
 * . If no entries exist, the function returns NULL, and
 *   the count is set to 0.
 * . If only one entry exists, the value of that entry is
 *   returned and count is set to 1.
 * . If N entries exists, the value of the first entry is
 *   returned and count is set to N.
 */

void *hash_lookup_with_val(struct hash_table *t, const char *key, const void *val, uint32_t val_len);
void hash_remove_with_val(struct hash_table *t, const char *key, const void *val, uint32_t val_len);
int hash_insert_allow_multiple(struct hash_table *t, const char *key, const void *val, uint32_t val_len);
void *hash_lookup_with_count(struct hash_table *t, const char *key, int *count);


#define hash_iterate(v, h) \
	for (v = hash_get_first((h)); v; \
	     v = hash_get_next((h), v))


/*
 * THE FUNCTIONS BELOW ARE EXTRA TO ORIGINAL CODE TAKEN FROM LVM2 SOURCE TREE AND ITS dm_hash_table IMPLEMENTATION.
 */

/*
 * Function to call if there's an existing key found to decide whether to keep old_data or use new_data for the key.
 * The function returns:
 * 	0 for hash table to keep old_data
 * 	1 for hash table to update old_data with new_data
 */
typedef int (* hash_dup_key_resolver_t) (const void *key, uint32_t key_len, void *old_data, void *new_data, void *arg);

/*
 * hash_update_binary:
 *   - If key is not in the hash table, it creates a new node the same way as hash_insert_binary.
 *   - If key is in the hash table, it calls dup_key_resolver and based on its return value, it either keeps old data or updates with new data.
 */
int hash_update_binary(struct hash_table *t, const void *key, uint32_t len, void *data,
		       hash_dup_key_resolver_t dup_key_resolver, void *dup_key_resolver_arg);

#ifdef __cplusplus
}
#endif

#endif
