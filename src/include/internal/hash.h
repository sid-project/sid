/*
 * SPDX-FileCopyrightText: (C) 2001-2004 Sistina Software, Inc.
 * SPDX-FileCopyrightText: (C) 2004-2024 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

typedef void (*hash_iterate_fn_t)(const void *key, uint32_t key_len, void *data, size_t data_len);

struct hash_table *hash_create(unsigned size_hint);
void               hash_wipe(struct hash_table *t);
void               hash_destroy(struct hash_table *t);

int   hash_add(struct hash_table *t, const void *key, uint32_t key_len, void *data, size_t data_len);
void *hash_lookup(struct hash_table *t, const void *key, uint32_t key_len, size_t *data_len);
void  hash_del(struct hash_table *t, const void *key, uint32_t key_len);

unsigned hash_get_entry_count(struct hash_table *t);
size_t   hash_get_size(struct hash_table *t, size_t *meta_size, size_t *data_size);
void     hash_iter(struct hash_table *t, hash_iterate_fn_t f);

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
 * . hash_del() removes the first one it finds, and
 *   hash_del_with_data() removes the one with a matching
 *   data_len/data.
 *
 * If a single entry with a given key exists, and it has
 * zero data_len, then:
 * . hash_lookup() returns it
 * . hash_lookup_with_data(data_len=0) returns it
 * . hash_del() removes it
 * . hash_del_with_data(data_len=0) removes it
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

int   hash_add_allow_multiple(struct hash_table *t, const char *key, uint32_t key_len, void *data, size_t data_len);
void *hash_lookup_with_data(struct hash_table *t, const char *key, uint32_t key_len, void *data, size_t data_len);
void *hash_lookup_with_count(struct hash_table *t, const char *key, uint32_t key_len, size_t *data_len, unsigned *count);
void  hash_del_with_data(struct hash_table *t, const char *key, uint32_t key_len, void *data, size_t data_len);

#define hash_iterate(v, h) for (v = hash_get_first((h)); v; v = hash_get_next((h), v))

/*
 * THE FUNCTIONS BELOW ARE EXTRA TO ORIGINAL CODE TAKEN FROM LVM2 SOURCE TREE AND ITS dm_hash_table IMPLEMENTATION.
 */

typedef enum {
	HASH_UPDATE_SKIP,   /* skip new value (keep old value) */
	HASH_UPDATE_WRITE,  /* write new value (overwrite old value) */
	HASH_UPDATE_REMOVE, /* remove old value */
} hash_update_action_t;

/*
 * hash_update_cb_fn_t callback type to define hash_update's hash_update_fn callback function.
 * Function of this type returns:
 * 	0 for hash table to keep old_data
 * 	1 for hash table to update old_data with new_data (new_data may be modified and/or newly allocated by this function)
 */
typedef hash_update_action_t (*hash_update_cb_fn_t)(const void *key,
                                                    uint32_t    key_len,
                                                    void       *old_data,
                                                    size_t      old_data_len,
                                                    void      **new_data,
                                                    size_t     *new_data_len,
                                                    void       *arg);

/*
 * hash_update function calls hash_update_fn callback with hash_update_fn_arg right before the update
 * and based on callback's return value, it either keeps the old data or updates with new data.
 */
int hash_update(struct hash_table  *t,
                const void         *key,
                uint32_t            key_len,
                void              **data,
                size_t             *data_len,
                hash_update_cb_fn_t hash_update_fn,
                void               *hash_update_fn_arg);

#ifdef __cplusplus
}
#endif

#endif
