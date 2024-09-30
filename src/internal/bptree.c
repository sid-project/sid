/*
 * SPDX-FileCopyrightText: (C) 2018 Amittai Aviram  http://www.amittai.com
 * SPDX-FileCopyrightText: (C) 2022-2024 Red Hat, Inc.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * Changes from original version from Amittai Aviram
 * (http://www.amittai.com/prose/bpt.c), version 1.16.1:
 *
 *   - edited code to comply with SID's code naming and organization
 *   - added 'bptree.h' interface with 'bptree_t' type to represent whole tree
 *   - removed 'main' function and all 'printf' calls inside code for more library-based approach
 *   - removed tree printing functionality
 *   - removed original range finding functionality (replaced with iterator interface)
 *   - changed value type in 'bptree_record_t' from 'int' to generic 'void * data'
 *   - also store 'data_size' in 'bptree_record_t'
 *   - added 'bptree_update' function with 'bptree_update_cb_fn_t' callback
 *   - copy key on insert and use reference counting so only a single key
 *     copy is used if key is referenced in leaf and/or internal nodes
 *   - added 'bptree_iter_*' iterator interface
 *   - track memory usage for both bptree's metadata and data and expose this
 *     information through 'bptree_get_size'
 *   - track number of record entries and expose this information through
 *     'bptree_get_num_entries'
 *   - added reference counting for records
 *   - added 'bptree_insert_alias' to insert alias for a key which then shares
 *     the same record with the original key
 *   - added 'bptree_destroy_with_fn' to call custom fn before each record
 *     is unreferenced/removed
 */

#include "internal/bptree.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

typedef struct bptree_record {
	size_t   data_size;
	void    *data;
	unsigned ref_count;
} bptree_record_t;

typedef struct bptree_key {
	const char *key;
	unsigned    ref_count;
} bptree_key_t;

/*
 * Type representing a node in the B+ tree.
 *
 * This type is general enough to serve for both the leaf and the internal
 * node. The heart of the node is the array of keys and the array of
 * corresponding pointers. The relation between keys and pointers differs
 * between leaves and internal nodes.
 *
 * In a leaf, the index* of each key equals the index of its corresponding
 * pointer, with a maximum of order - 1 key-pointer pairs. The last pointer
 * points to the leaf to the right (or NULL in the case of the rightmost
 * leaf).
 *
 * In an internal node, the first pointer refers to lower nodes with keys
 * less than the smallest key in the keys array. Then, with indices i
 * starting at 0, the pointer at i + 1 points to the subtree with keys
 * greater than or equal to the key in this node at index i.
 *
 * The num_keys field is used to keep track of the number of valid keys.
 *
 * In an internal node, the number of valid pointers is always num_keys + 1.
 *
 * In a leaf, the number of valid pointers to data is always num_keys.
 * The last leaf pointer points to the next leaf.
 */

typedef struct bptree_node {
	void              **pointers;
	bptree_key_t      **bkeys;
	struct bptree_node *parent;
	bool                is_leaf;
	int                 num_keys;
} bptree_node_t;

typedef enum {
	LOOKUP_EXACT,
	LOOKUP_PREFIX,
} bptree_lookup_method_t;

typedef struct bptree_iter {
	bptree_lookup_method_t method;
	bptree_t              *bptree;
	const char            *key_start;
	const char            *key_end;
	size_t                 key_start_len;
	bptree_node_t         *c;
	int                    i;
} bptree_iter_t;

/*
 * Type representing whole B+ tree with its global properties.
 *
 * The order determines the maximum and minimum number of entries
 * (keys and pointers) in any node. Every node has at most order - 1 keys
 * and at least (roughly speaking) half that number. Every leaf has as many
 * pointers to data as keys, and every internal node has one more pointer
 * to a subtree than the number of keys.
 */

typedef struct bptree {
	bptree_node_t *root;
	int            order;
	size_t         meta_size;
	size_t         data_size;
	size_t         num_entries;
} bptree_t;

static bptree_node_t *_insert_into_parent(bptree_t       *bptree,
                                          bptree_node_t **node_list,
                                          bptree_node_t  *left,
                                          bptree_key_t   *bkey,
                                          bptree_node_t  *right);
static bptree_node_t *_delete_entry(bptree_t *bptree, bptree_node_t *n, bptree_key_t *bkey, void *pointer);

/*
 * Create new tree.
 */
bptree_t *bptree_create(int order)
{
	bptree_t *bptree;

	if (order <= 3)
		return NULL;

	if (!(bptree = malloc(sizeof(bptree_t))))
		return NULL;

	bptree->root        = NULL;
	bptree->order       = order;
	bptree->meta_size   = sizeof(*bptree);
	bptree->data_size   = 0;
	bptree->num_entries = 0;

	return bptree;
}

/*
 * Utility function to give the height of the tree, which is the
 * number of edges of the path from the root to any leaf.
 */
int bptree_get_height(bptree_t *bptree)
{
	int            h = 0;
	bptree_node_t *c = bptree->root;

	if (!c)
		return 0;

	while (!c->is_leaf) {
		c = c->pointers[0];
		h++;
	}

	return h;
}

size_t bptree_get_size(bptree_t *bptree, size_t *meta_size, size_t *data_size)
{
	if (meta_size)
		*meta_size = bptree->meta_size;

	if (data_size)
		*data_size = bptree->data_size;

	return bptree->meta_size + bptree->data_size;
}

size_t bptree_get_entry_count(bptree_t *bptree)
{
	return bptree->num_entries;
}

/*
 * Traces the path from the root to a leaf, searching by key.
 * Returns the leaf containing the given key.
 */
static bptree_node_t *_find_leaf(bptree_t *bptree, const char *key)
{
	int            i;
	bptree_node_t *c;

	if (!bptree->root)
		return NULL;

	c = bptree->root;

	while (!c->is_leaf) {
		i = 0;

		while (i < c->num_keys) {
			if (strcmp(key, c->bkeys[i]->key) > 0)
				i++;
			else
				break;
		}

		c = (bptree_node_t *) c->pointers[i];
	}

	return c;
}

/*
 * Looks up and returns the record to which a key refers.
 */
static bptree_record_t *_find(bptree_t              *bptree,
                              const char            *key,
                              bptree_lookup_method_t method,
                              bptree_node_t        **leaf_out,
                              int                   *i_out,
                              bptree_key_t         **bkey_out)
{
	int            i;
	bptree_node_t *leaf;
	size_t         key_len;

	if (!bptree->root) {
		if (leaf_out)
			*leaf_out = NULL;
		if (bkey_out)
			*bkey_out = NULL;
		return NULL;
	}

	leaf    = _find_leaf(bptree, key);

	key_len = (method == LOOKUP_PREFIX) ? strlen(key) : 0;

	/*
	 * If root != NULL, leaf must have a value,
	 * even if it does not contain the desired key.
	 * (The leaf holds the range of keys that would
	 * include the desired key.)
	 */

	for (i = 0; i < leaf->num_keys; i++) {
		if (method == LOOKUP_EXACT) {
			if (!strcmp(key, leaf->bkeys[i]->key))
				break;
		} else {
			if (!strncmp(key, leaf->bkeys[i]->key, key_len))
				break;
		}
	}

	if (leaf_out)
		*leaf_out = leaf;

	if (i == leaf->num_keys) {
		if (i_out)
			*i_out = 0;
		if (bkey_out)
			*bkey_out = NULL;
		return NULL;
	} else {
		if (i_out)
			*i_out = i;
		if (bkey_out)
			*bkey_out = leaf->bkeys[i];
		return (bptree_record_t *) leaf->pointers[i];
	}
}

/*
 * Looks up and returns the data to which a key refers.
 */
void *bptree_lookup(bptree_t *bptree, const char *key, size_t *data_size, unsigned *data_ref_count)
{
	bptree_record_t *rec;

	if (!(rec = _find(bptree, key, LOOKUP_EXACT, NULL, NULL, NULL)))
		return NULL;

	if (data_size)
		*data_size = rec->data_size;
	if (data_ref_count)
		*data_ref_count = rec->ref_count;

	return rec->data;
}

/*
 * Finds the appropriate place to split a node that is too big into two.
 */
static int _cut(int length)
{
	return (length + 1) / 2;
}

static bptree_record_t *_make_record(bptree_t *bptree, void *data, size_t data_size)
{
	bptree_record_t *rec;

	if (!(rec = malloc(sizeof(bptree_record_t))))
		return NULL;

	rec->data_size     = data_size;
	rec->data          = data;
	rec->ref_count     = 0;

	bptree->meta_size += sizeof(*rec);
	bptree->data_size += data_size;
	bptree->num_entries++;

	return rec;
}

static void _destroy_record(bptree_t *bptree, bptree_record_t *rec)
{
	bptree->meta_size -= sizeof(*rec);
	bptree->data_size -= rec->data_size;
	bptree->num_entries--;

	free(rec);
}

static bptree_record_t *_ref_record(bptree_record_t *rec)
{
	rec->ref_count++;
	return rec;
}

static void _unref_record(bptree_t *bptree, bptree_record_t *rec)
{
	if (--rec->ref_count > 0)
		return;

	_destroy_record(bptree, rec);
}

static bptree_key_t *_make_bkey(bptree_t *bptree, const char *key)
{
	bptree_key_t *bkey;

	if (!(bkey = malloc(sizeof(bptree_key_t))))
		return NULL;

	if (!(bkey->key = strdup(key))) {
		free(bkey);
		return NULL;
	}

	bkey->ref_count    = 0;

	bptree->meta_size += (sizeof(*bkey) + strlen(key) + 1);

	return bkey;
}

static void _destroy_bkey(bptree_t *bptree, bptree_key_t *bkey)
{
	bptree->meta_size -= (sizeof(*bkey) + strlen(bkey->key) + 1);

	free((void *) bkey->key);
	free(bkey);
}

static bptree_key_t *_ref_bkey(bptree_key_t *bkey)
{
	bkey->ref_count++;
	return bkey;
}

static bptree_key_t *_unref_bkey(bptree_t *bptree, bptree_key_t *bkey)
{
	--bkey->ref_count;

	if (bkey->ref_count == 0)
		_destroy_bkey(bptree, bkey);

	return NULL;
}

/*
 * Creates a new general node, which can be adapted
 * to serve as either a leaf or an internal node.
 */
static bptree_node_t *_make_node(bptree_t *bptree)
{
	bptree_node_t *new_node;
	size_t         pointers_size;
	size_t         bkeys_size;

	if (!(new_node = malloc(sizeof(bptree_node_t))))
		return NULL;

	bkeys_size = (bptree->order - 1) * sizeof(bptree_key_t *);
	if (!(new_node->bkeys = malloc(bkeys_size))) {
		free(new_node);
		return NULL;
	}

	pointers_size = bptree->order * sizeof(void *);
	if (!(new_node->pointers = malloc(pointers_size))) {
		free(new_node->bkeys);
		free(new_node);
		return NULL;
	}

	new_node->is_leaf   = false;
	new_node->num_keys  = 0;
	new_node->parent    = NULL;

	bptree->meta_size  += (sizeof(*new_node) + pointers_size + bkeys_size);

	return new_node;
}

static void _destroy_node(bptree_t *bptree, bptree_node_t *n)
{
	bptree->meta_size -= (sizeof(*n) + ((bptree->order - 1) * sizeof(bptree_key_t *)) + (bptree->order * sizeof(void *)));

	free(n->bkeys);
	free(n->pointers);
	free(n);
}

static bptree_node_t *_make_node_list(bptree_t *bptree, size_t count)
{
	bptree_node_t *old_node;
	bptree_node_t *new_node = NULL;

	while (count--) {
		old_node = new_node;
		if (!(new_node = _make_node(bptree)))
			goto fail;
		new_node->pointers[0] = old_node;
	}
	return new_node;

fail:
	while (old_node) {
		new_node = old_node;
		old_node = old_node->pointers[0];
		_destroy_node(bptree, new_node);
	}
	return NULL;
}

static bptree_node_t *_get_node_from_list(bptree_node_t **node_list)
{
	bptree_node_t *node = *node_list;

	assert(node);
	*node_list        = node->pointers[0];
	node->pointers[0] = NULL;
	return node;
}

static size_t _number_of_nodes_needed(bptree_t *bptree, bptree_node_t *node)
{
	size_t count = 0;

	while (node && node->num_keys == bptree->order - 1) {
		count++;
		node = node->parent;
	}
	if (!node)
		count++;
	return count;
}

/*
 * Helper function used in insert_into_parent to find the index of the
 * parent's pointer to the node to the left of the key to be inserted.
 */
static int _get_left_index(bptree_node_t *parent, bptree_node_t *left)
{
	int left_index = 0;

	while (left_index <= parent->num_keys && parent->pointers[left_index] != left)
		left_index++;

	return left_index;
}

/*
 * Inserts a new pointer to a record and its corresponding key into a leaf.
 * Returns the altered leaf.
 */
static bptree_node_t *_insert_into_leaf(bptree_node_t *leaf, bptree_key_t *bkey, bptree_record_t *pointer)
{
	int i, insertion_point = 0;

	while (insertion_point < leaf->num_keys && strcmp(leaf->bkeys[insertion_point]->key, bkey->key) <= 0) {
		insertion_point++;
	}

	for (i = leaf->num_keys; i > insertion_point; i--) {
		leaf->bkeys[i]    = leaf->bkeys[i - 1];
		leaf->pointers[i] = leaf->pointers[i - 1];
	}

	leaf->bkeys[insertion_point]    = _ref_bkey(bkey);
	leaf->pointers[insertion_point] = _ref_record(pointer);
	leaf->num_keys++;

	return leaf;
}

/*
 * Inserts a new key and pointer to a new record into a leaf so as to
 * exceed the tree's order, causing the leaf to be split in half.
 */
static bptree_node_t *_insert_into_leaf_after_splitting(bptree_t        *bptree,
                                                        bptree_node_t  **node_list,
                                                        bptree_node_t   *leaf,
                                                        bptree_key_t    *bkey,
                                                        bptree_record_t *pointer)
{
	bptree_node_t *new_leaf;
	bptree_key_t  *new_bkey;
	int            insertion_index, split, i, j;

	new_leaf          = _get_node_from_list(node_list);
	new_leaf->is_leaf = true;

	insertion_index   = 0;
	while (insertion_index < bptree->order - 1 && strcmp(leaf->bkeys[insertion_index]->key, bkey->key) <= 0)
		insertion_index++;

	split              = _cut(bptree->order - 1);
	leaf->num_keys     = split;
	new_leaf->num_keys = bptree->order - split;

	i                  = insertion_index < split ? split - 1 : split;
	for (j = 0; j < new_leaf->num_keys; j++) {
		if (split + j == insertion_index) {
			new_leaf->pointers[j] = _ref_record(pointer);
			new_leaf->bkeys[j]    = _ref_bkey(bkey);
			continue;
		}
		new_leaf->pointers[j] = leaf->pointers[i];
		new_leaf->bkeys[j]    = leaf->bkeys[i];
		i++;
	}

	if (insertion_index < split) {
		for (i = split - 1; i > insertion_index; i--) {
			leaf->pointers[i] = leaf->pointers[i - 1];
			leaf->bkeys[i]    = leaf->bkeys[i - 1];
		}
		leaf->pointers[insertion_index] = _ref_record(pointer);
		leaf->bkeys[insertion_index]    = _ref_bkey(bkey);
	}

	new_leaf->pointers[bptree->order - 1] = leaf->pointers[bptree->order - 1];
	leaf->pointers[bptree->order - 1]     = new_leaf;

	for (i = leaf->num_keys; i < bptree->order - 1; i++)
		leaf->pointers[i] = NULL;

	for (i = new_leaf->num_keys; i < bptree->order - 1; i++)
		new_leaf->pointers[i] = NULL;

	new_leaf->parent = leaf->parent;
	new_bkey         = leaf->bkeys[leaf->num_keys - 1];

	return _insert_into_parent(bptree, node_list, leaf, new_bkey, new_leaf);
}

/*
 * Inserts a new key and pointer to a node into a node into
 * which these can fit without violating the B+ tree properties.
 */
static bptree_node_t *
	_insert_into_node(bptree_t *bptree, bptree_node_t *n, int left_index, bptree_key_t *bkey, bptree_node_t *right)
{
	int i;

	for (i = n->num_keys; i > left_index; i--) {
		n->pointers[i + 1] = n->pointers[i];
		n->bkeys[i]        = n->bkeys[i - 1];
	}

	n->pointers[left_index + 1] = right;
	n->bkeys[left_index]        = _ref_bkey(bkey);
	n->num_keys++;

	return bptree->root;
}

/*
 * Inserts a new key and pointer to a node* into a node, causing the
 * node's size to exceed the order, and causing the node to split into two.
 */
static bptree_node_t *_insert_into_node_after_splitting(bptree_t       *bptree,
                                                        bptree_node_t **node_list,
                                                        bptree_node_t  *old_node,
                                                        int             left_index,
                                                        bptree_key_t   *bkey,
                                                        bptree_node_t  *right)
{
	int            i, j, k, split;
	bptree_node_t *new_node, *child;
	bptree_key_t  *bk_prime;
	bptree_node_t *n;

	/*
	 * Create the new node and copy half the keys
	 * and pointers to it.
	 */
	split              = _cut(bptree->order);
	new_node           = _get_node_from_list(node_list);
	old_node->num_keys = split - 1;
	new_node->num_keys = bptree->order - split;

	j                  = left_index + 1 < split ? split - 1 : split;
	k                  = left_index < split ? split - 1 : split;
	for (i = 0; i < new_node->num_keys; i++) {
		if (split + i == left_index) {
			new_node->pointers[i] = old_node->pointers[j];
			new_node->bkeys[i]    = _ref_bkey(bkey);
			j++;
		} else if (split + i == left_index + 1) {
			new_node->pointers[i] = right;
			new_node->bkeys[i]    = old_node->bkeys[k];
			k++;
		} else {
			new_node->pointers[i] = old_node->pointers[j];
			new_node->bkeys[i]    = old_node->bkeys[k];
			j++;
			k++;
		}
	}
	if (split + i == left_index + 1)
		new_node->pointers[i] = right;
	else
		new_node->pointers[i] = old_node->pointers[j];

	// adjust the keys and pointers on the old node
	if (left_index < split) {
		for (i = split - 1; i > left_index; i--) {
			old_node->pointers[i] = i > left_index + 1 ? old_node->pointers[i - 1] : right;
			old_node->bkeys[i]    = old_node->bkeys[i - 1];
		}
		old_node->bkeys[left_index] = _ref_bkey(bkey);
	}
	bk_prime         = old_node->bkeys[old_node->num_keys];

	/*
	 * The bk_prime will be moved up one level in the tree and removed
	 * from current level after splitting. To avoid dropping the
	 * ref_count to 0 and hence premature freeing of the whole bk_prime,
	 * first, we will insert it into parent and then unref it at the end
	 * of this function.
	 */

	new_node->parent = old_node->parent;

	for (i = 0; i <= new_node->num_keys; i++) {
		child         = new_node->pointers[i];
		child->parent = new_node;
	}

	/*
	 * Insert a new key into the parent of the two nodes resulting
	 * from the split, with the old node to the left and the new
	 * to the right.
	 */

	n = _insert_into_parent(bptree, node_list, old_node, bk_prime, new_node);
	_unref_bkey(bptree, bk_prime);

	return n;
}

/*
 * Creates a new root for two subtrees and inserts
 * the appropriate key into the new root.
 */
static bptree_node_t *_insert_into_new_root(bptree_t       *bptree,
                                            bptree_node_t **node_list,
                                            bptree_node_t  *left,
                                            bptree_key_t   *bkey,
                                            bptree_node_t  *right)
{
	bptree->root              = _get_node_from_list(node_list);

	bptree->root->bkeys[0]    = _ref_bkey(bkey);
	bptree->root->pointers[0] = left;
	bptree->root->pointers[1] = right;
	bptree->root->num_keys++;
	bptree->root->parent = NULL;

	left->parent         = bptree->root;
	right->parent        = bptree->root;

	return bptree->root;
}

/*
 * Inserts a new node (leaf or internal node) into the B+ tree.
 * Returns the root of the tree after insertion.
 */
static bptree_node_t *_insert_into_parent(bptree_t       *bptree,
                                          bptree_node_t **node_list,
                                          bptree_node_t  *left,
                                          bptree_key_t   *bkey,
                                          bptree_node_t  *right)
{
	int            left_index;
	bptree_node_t *parent;

	parent = left->parent;

	/* Case: new root. */

	if (!parent)
		return _insert_into_new_root(bptree, node_list, left, bkey, right);

	/* Case: leaf or node. (Remainder of function body.) */

	/* Find the parent's pointer to the left node. */

	left_index = _get_left_index(parent, left);

	/* Simple case: the new key fits into the node. */

	if (parent->num_keys < bptree->order - 1)
		return _insert_into_node(bptree, parent, left_index, bkey, right);

	/* Harder case: split a node in order to preserve the B+ tree properties. */

	return _insert_into_node_after_splitting(bptree, node_list, parent, left_index, bkey, right);
}

/*
 * First insertion: start a new tree.
 */
static bptree_node_t *_create_root(bptree_t *bptree, bptree_key_t *bkey, bptree_record_t *pointer)
{
	bptree_node_t *leaf;

	if (!(leaf = _make_node(bptree)))
		return NULL;
	leaf->is_leaf                             = true;

	bptree->root                              = leaf;
	bptree->root->bkeys[0]                    = _ref_bkey(bkey);
	bptree->root->pointers[0]                 = _ref_record(pointer);
	bptree->root->pointers[bptree->order - 1] = NULL;
	bptree->root->parent                      = NULL;
	bptree->root->num_keys++;

	return bptree->root;
}

static int _insert(bptree_t *bptree, bptree_key_t *bkey, bptree_record_t *rec)
{
	bptree_node_t *leaf, *node_list;
	size_t         count;

	leaf  = _find_leaf(bptree, bkey->key);
	count = _number_of_nodes_needed(bptree, leaf);

	/* Case: leaf has room for key and record pointer. */

	if (count == 0) {
		_insert_into_leaf(leaf, bkey, rec);
		return 0;
	}

	/* Case: leaf must be split. */
	if (!(node_list = _make_node_list(bptree, count)))
		return -1;

	_insert_into_leaf_after_splitting(bptree, &node_list, leaf, bkey, rec);
	assert(!node_list);

	return 0;
}

/*
 * Main insertion function.
 * Inserts a key and associated data into the B+ tree, causing the tree
 * to be adjusted however necessary to maintain the B+ tree properties.
 */
int bptree_add(bptree_t *bptree, const char *key, void *data, size_t data_size)
{
	bptree_record_t *rec;
	bptree_key_t    *bkey;

	if ((rec = _find(bptree, key, LOOKUP_EXACT, NULL, NULL, NULL))) {
		rec->data          = data;
		bptree->data_size -= rec->data_size;
		rec->data_size     = data_size;
		bptree->data_size += rec->data_size;
		return 0;
	}

#ifndef __clang_analyzer__
	/* FIXME: clang analyzer incorrectly thinks there's a memory leak
	 * with 'bkey' and 'rec' even though we're destroying them on each
	 * possible error path before completing the '_insert' call.
	 * Otherwise, when calling '_insert', the 'bkey' and 'rec' are
	 * used in the tree, so there's no memory leak.
	 */
	if (!(bkey = _make_bkey(bptree, key)))
		return -1;

	if (!(rec = _make_record(bptree, data, data_size))) {
		_destroy_bkey(bptree, bkey);
		return -1;
	}

	/* Case: the tree does not exist yet. Start a new tree. */

	if (!bptree->root) {
		if (!_create_root(bptree, bkey, rec)) {
			_destroy_bkey(bptree, bkey);
			_destroy_record(bptree, rec);
			return -1;
		}

		return 0;
	}

	/* Case: the tree already exists. Insert into the tree. */

	if (_insert(bptree, bkey, rec) < 0) {
		_destroy_bkey(bptree, bkey);
		_destroy_record(bptree, rec);
		return -1;
	}
#endif /* __clang_analyzer */

	return 0;
}

int bptree_add_alias(bptree_t *bptree, const char *key, const char *alias, bool force)
{
	bptree_record_t *rec;
	bptree_record_t *rec_alias;
	bptree_node_t   *leaf;
	int              i;
	bptree_key_t    *bkey;

	if (!(rec = _find(bptree, key, LOOKUP_EXACT, NULL, NULL, NULL)))
		return -1;

	if ((rec_alias = _find(bptree, alias, LOOKUP_EXACT, &leaf, &i, NULL))) {
		if (rec != rec_alias) {
			if (!force)
				return -1;

			leaf->pointers[i] = _ref_record(rec);
			_unref_record(bptree, rec_alias);
		}
		return 0;
	}

#ifndef __clang_analyzer__
	/* FIXME: clang analyzer incorrectly thinks there's a memory leak
	 * with 'bkey' even though we're destroying it on each possible
	 * error path before completing the '_insert' call.
	 * Otherwise, when calling '_insert', the 'bkey' is used in the
	 * tree, so there's no memory leak.
	 */
	if (!(bkey = _make_bkey(bptree, alias)))
		return -1;

	if (_insert(bptree, bkey, rec) < 0) {
		_destroy_bkey(bptree, bkey);
		return -1;
	}
#endif /* __clang_analyzer */

	return 0;
}

int bptree_update(bptree_t             *bptree,
                  const char           *key,
                  void                **data,
                  size_t               *data_size,
                  bptree_update_cb_fn_t bptree_update_fn,
                  void                 *bptree_update_fn_arg)
{
	bptree_node_t         *key_leaf;
	bptree_record_t       *rec;
	bptree_key_t          *bkey;
	bptree_update_action_t act;
	int                    r = 0;

	rec                      = _find(bptree, key, LOOKUP_EXACT, &key_leaf, NULL, &bkey);

	if (bptree_update_fn) {
		if (rec)
			act = bptree_update_fn(key,
			                       rec->data,
			                       rec->data_size,
			                       rec->ref_count,
			                       data,
			                       data_size,
			                       bptree_update_fn_arg);
		else
			act = bptree_update_fn(key, NULL, 0, 0, data, data_size, bptree_update_fn_arg);
	} else {
		if (data)
			act = BPTREE_UPDATE_WRITE;
		else
			act = BPTREE_UPDATE_REMOVE;
	}

	switch (act) {
		case BPTREE_UPDATE_WRITE:
			if (rec) {
				rec->data          = data ? *data : NULL;
				bptree->data_size -= rec->data_size;
				rec->data_size     = data_size ? *data_size : 0;
				bptree->data_size += rec->data_size;
			} else
				r = bptree_add(bptree, key, data ? *data : NULL, data_size ? *data_size : 0);
			break;

		case BPTREE_UPDATE_REMOVE:
			if (rec && key_leaf) {
				(void) _delete_entry(bptree, key_leaf, bkey, rec);
				_unref_record(bptree, rec);
			}
			break;

		case BPTREE_UPDATE_SKIP:
			break;
	}

	return r;
}

/*
 * Utility function for deletion.
 * Retrieves the index of a node's nearest neighbor (sibling) to the left
 * if one exists. If not (the node is the leftmost child), returns -1 to
 * signify this special case.
 */
static int _get_neighbor_index(bptree_node_t *n)
{
	int i;

	/*
	 * Return the index of the key to the left of the pointer in the
	 * parent pointing to n. If n is the leftmost child, this means
	 * return -1.
	 */
	for (i = 0; i <= n->parent->num_keys; i++) {
		if (n->parent->pointers[i] == n)
			return i - 1;
	}

	return -1;
}

static bptree_node_t *_remove_entry_from_node(bptree_t *bptree, bptree_node_t *n, bptree_key_t *bkey, bptree_node_t *pointer)
{
	int           i            = 0, num_pointers;
	bptree_key_t *swapped_bkey = NULL;

	/* Remove the key and shift other keys accordingly. */
	while (n->bkeys[i] != bkey)
		i++;

	/* If the last key in a leaf is deleted, swap it out for the previous
	 * key, in the internal nodes. This does not apply in case we have
	 * only the root node left (that is, the leaf node has no parent). */
	if (n->parent && n->is_leaf && i == n->num_keys - 1)
		swapped_bkey = n->bkeys[i - 1];

	_unref_bkey(bptree, bkey);

	for (++i; i < n->num_keys; i++)
		n->bkeys[i - 1] = n->bkeys[i];

	/*
	 * Remove the pointer and shift other pointers accordingly.
	 * First determine number of pointers.
	 */
	num_pointers = n->is_leaf ? n->num_keys : n->num_keys + 1;
	i            = 0;

	while (n->pointers[i] != pointer)
		i++;

	for (++i; i < num_pointers; i++)
		n->pointers[i - 1] = n->pointers[i];

	/* One key fewer. */
	n->num_keys--;

	/*
	 * Set the other pointers to NULL for tidiness.
	 * A leaf uses the last pointer to point to the next leaf.
	 */
	if (n->is_leaf)
		for (i = n->num_keys; i < bptree->order - 1; i++)
			n->pointers[i] = NULL;
	else
		for (i = n->num_keys + 1; i < bptree->order; i++)
			n->pointers[i] = NULL;

	if (swapped_bkey) {
		bptree_node_t *p;

		for (p = n->parent; p; p = p->parent) {
			for (i = 0; i < p->num_keys; i++) {
				if (p->bkeys[i] == bkey) {
#ifndef __clang_analyzer__
					/* FIXME: clang analyzer things there's the
					 * 'bkey' used after free. However, the 'bkey'
					 * is reference-counted and if it's used more
					 * than once in the tree (in internal nodes),
					 * we can call `_unref_bkey` more than once
					 * if we're traversing the tree from leaf up
					 * to the root node.
					 */
					_unref_bkey(bptree, bkey);
#endif /* __clang_analyzer__ */
					p->bkeys[i] = _ref_bkey(swapped_bkey);
					goto out;
				}
			}
		}
	}
out:
	return n;
}

static bptree_node_t *_adjust_root(bptree_t *bptree)
{
	bptree_node_t *new_root;

	/*
	 * Case: nonempty root.
	 * Key and pointer have already been deleted, so nothing to be done.
	 */

	if (bptree->root->num_keys > 0)
		return bptree->root;

	/* Case: empty root. */

	/* If it has a child, promote the first (only) child as the new root. */

	if (!bptree->root->is_leaf) {
		new_root         = bptree->root->pointers[0];
		new_root->parent = NULL;
	}

	/* If it is a leaf (has no children), then the whole tree is empty. */

	else
		new_root = NULL;

	_destroy_node(bptree, bptree->root);
	bptree->root = new_root;
	return new_root;
}

/*
 * Coalesces a node that has becometoo small after deletion with
 * a neighboring node that can accept the additional entries without
 * exceeding the maximum.
 */
static bptree_node_t *
	_coalesce_nodes(bptree_t *bptree, bptree_node_t *n, bptree_node_t *neighbor, int neighbor_index, bptree_key_t *bk_prime)
{
	int            i, j, neighbor_insertion_index, n_end;
	bptree_node_t *tmp, *c;

	/*
	 * Swap neighbor with node if node is on the extreme left
	 * and neighbor is to its right.
	 */

	if (neighbor_index == -1) {
		tmp      = n;
		n        = neighbor;
		neighbor = tmp;
	}

	/*
	 * Starting point in the neighbor for copying keys and pointers
	 * from n. Recall that n and neighbor have swapped places in the
	 * special case of n being a leftmost child.
	 */

	neighbor_insertion_index = neighbor->num_keys;

	/*
	 * Case: nonleaf node.
	 * Append k_prime and the following pointer.
	 * Append all pointers and keys from the neighbor.
	 */

	if (!n->is_leaf) {
		/* Append bk_prime. */

		neighbor->bkeys[neighbor_insertion_index] = _ref_bkey(bk_prime);
		neighbor->num_keys++;

		n_end = n->num_keys;

		for (i = neighbor_insertion_index + 1, j = 0; j < n_end; i++, j++) {
			neighbor->bkeys[i]    = n->bkeys[j];
			neighbor->pointers[i] = n->pointers[j];
			neighbor->num_keys++;
			n->num_keys--;
		}

		/*
		 * The number of pointers is always one more
		 * than the number of keys.
		 */

		neighbor->pointers[i] = n->pointers[j];

		/* All children must now point up to the same parent. */

		for (i = 0; i < neighbor->num_keys + 1; i++)
			((bptree_node_t *) neighbor->pointers[i])->parent = neighbor;
	}

	/*
	 * In a leaf, append the keys and pointers of n to the neighbor.
	 * Set the neighbor's last pointer to point to* what had been
	 * n's right neighbor.
	 */

	else {
		for (i = neighbor_insertion_index, j = 0; j < n->num_keys; i++, j++) {
			neighbor->bkeys[i]    = n->bkeys[j];
			neighbor->pointers[i] = n->pointers[j];
			neighbor->num_keys++;
		}

		neighbor->pointers[bptree->order - 1] = n->pointers[bptree->order - 1];
	}

	c = _delete_entry(bptree, n->parent, bk_prime, n);
	_destroy_node(bptree, n);
	return c;
}

/*
 * Redistributes entries between two nodes when one has become too small
 * after deletion but its neighbor is too big to append the small node's
 * entries without exceeding the maximum
 */
static bptree_node_t *_redistribute_nodes(bptree_t      *bptree,
                                          bptree_node_t *n,
                                          bptree_node_t *neighbor,
                                          int            neighbor_index,
                                          int            k_prime_index,
                                          bptree_key_t  *bk_prime)
{
	int i;

	/*
	 * Case: n has a neighbor to the left.
	 * Pull the neighbor's last key-pointer pair over
	 * from the neighbor's right end to n's left end.
	 */

	if (neighbor_index != -1) {
		if (!n->is_leaf)
			n->pointers[n->num_keys + 1] = n->pointers[n->num_keys];

		for (i = n->num_keys; i > 0; i--) {
			n->bkeys[i]    = n->bkeys[i - 1];
			n->pointers[i] = n->pointers[i - 1];
		}

		if (n->is_leaf) {
			n->pointers[0]                             = neighbor->pointers[neighbor->num_keys - 1];
			neighbor->pointers[neighbor->num_keys - 1] = NULL;
			n->bkeys[0]                                = neighbor->bkeys[neighbor->num_keys - 1];
			n->parent->bkeys[k_prime_index]            = _ref_bkey(neighbor->bkeys[neighbor->num_keys - 2]);
			_unref_bkey(bptree, bk_prime);
		} else {
			n->pointers[0]                             = neighbor->pointers[neighbor->num_keys];
			((bptree_node_t *) n->pointers[0])->parent = n;
			neighbor->pointers[neighbor->num_keys]     = NULL;
			n->bkeys[0]                                = bk_prime;
			n->parent->bkeys[k_prime_index]            = neighbor->bkeys[neighbor->num_keys - 1];
		}
	}

	/*
	 * Case: n is the leftmost child.
	 * Take a key-pointer pair from the neighbor to the right.
	 * Move the neighbor's leftmost key-pointer pair to n's rightmost position.
	 */

	else {
		if (n->is_leaf) {
			n->bkeys[n->num_keys]           = neighbor->bkeys[0];
			n->pointers[n->num_keys]        = neighbor->pointers[0];
			n->parent->bkeys[k_prime_index] = _ref_bkey(n->bkeys[n->num_keys]);
			_unref_bkey(bptree, bk_prime);
		} else {
			n->bkeys[n->num_keys]                                    = bk_prime;
			n->pointers[n->num_keys + 1]                             = neighbor->pointers[0];
			((bptree_node_t *) n->pointers[n->num_keys + 1])->parent = n;
			n->parent->bkeys[k_prime_index]                          = neighbor->bkeys[0];
		}

		for (i = 0; i < neighbor->num_keys - 1; i++) {
			neighbor->bkeys[i]    = neighbor->bkeys[i + 1];
			neighbor->pointers[i] = neighbor->pointers[i + 1];
		}

		if (!n->is_leaf)
			neighbor->pointers[i] = neighbor->pointers[i + 1];
	}

	/*
	 * n now has one more key and one more pointer;
	 * the neighbor has one fewer of each.
	 */

	n->num_keys++;
	neighbor->num_keys--;

	return bptree->root;
}

/*
 * Deletes an entry from the B+ tree.
 * Removes the key and pointer from the leaf, and then makes all
 * appropriate changes to preserve the B+ tree properties.
 */
static bptree_node_t *_delete_entry(bptree_t *bptree, bptree_node_t *n, bptree_key_t *bkey, void *pointer)
{
	int            min_keys;
	bptree_node_t *neighbor;
	int            neighbor_index;
	int            k_prime_index;
	bptree_key_t  *bk_prime;
	int            capacity;

	/* Remove key and pointer from node. */

	n = _remove_entry_from_node(bptree, n, bkey, pointer);

	/* Case: deletion from the root. */

	if (n == bptree->root)
		return _adjust_root(bptree);

	/*
	 * Case: deletion from a node below the root.
	 * (Rest of function body.)
	 */

	/*
	 * Determine minimum allowable size of node, to be preserved
	 * after deletion.
	 */

	min_keys = n->is_leaf ? _cut(bptree->order - 1) : _cut(bptree->order) - 1;

	/*
	 * Case: node stays at or above minimum. (The simple case.)
	 */

	if (n->num_keys >= min_keys)
		return bptree->root;

	/*
	 * Case: node falls below minimum. Either coalescence
	 * or redistribution is needed.
	 */

	/*
	 * Find the appropriate neighbor node with which to coalesce.
	 * Also find the key (k_prime) in the parent between the pointer
	 * to node n and the pointer to the neighbor.
	 */

	neighbor_index = _get_neighbor_index(n);
	k_prime_index  = neighbor_index == -1 ? 0 : neighbor_index;
	bk_prime       = n->parent->bkeys[k_prime_index];
	neighbor       = neighbor_index == -1 ? n->parent->pointers[1] : n->parent->pointers[neighbor_index];

	capacity       = n->is_leaf ? bptree->order : bptree->order - 1;

	/* Coalescence. */

	if (neighbor->num_keys + n->num_keys < capacity)
		return _coalesce_nodes(bptree, n, neighbor, neighbor_index, bk_prime);

	/* Redistribution. */

	else
		return _redistribute_nodes(bptree, n, neighbor, neighbor_index, k_prime_index, bk_prime);
}

/*
 * Main deletion function.
 */
int bptree_del(bptree_t *bptree, const char *key)
{
	bptree_node_t   *key_leaf = NULL;
	bptree_record_t *rec      = NULL;
	bptree_key_t    *bkey     = NULL;

	rec                       = _find(bptree, key, LOOKUP_EXACT, &key_leaf, NULL, &bkey);

	/* CHANGE */

	if (rec && key_leaf) {
		(void) _delete_entry(bptree, key_leaf, bkey, rec);
		_unref_record(bptree, rec);
	}

	return 0;
}

static void _destroy_tree_nodes(bptree_t *bptree, bptree_node_t *n, bptree_iterate_fn_t fn, void *fn_arg)
{
	bptree_record_t *rec;
	int              i;

	if (n->is_leaf) {
		for (i = 0; i < n->num_keys; i++) {
			if (fn) {
				rec = n->pointers[i];
				fn(n->bkeys[i]->key, rec->data, rec->data_size, rec->ref_count, fn_arg);
			}
			_unref_bkey(bptree, n->bkeys[i]);
			_unref_record(bptree, n->pointers[i]);
		}
	} else {
		for (i = 0; i < n->num_keys + 1; i++) {
			_destroy_tree_nodes(bptree, n->pointers[i], fn, fn_arg);
			if (i < n->num_keys)
				_unref_bkey(bptree, n->bkeys[i]);
		}
	}

	_destroy_node(bptree, n);
}

int bptree_destroy(bptree_t *bptree)
{
	if (bptree->root)
		_destroy_tree_nodes(bptree, bptree->root, NULL, NULL);
	free(bptree);
	return 0;
}

int bptree_destroy_with_fn(bptree_t *bptree, bptree_iterate_fn_t fn, void *fn_arg)
{
	if (bptree->root)
		_destroy_tree_nodes(bptree, bptree->root, fn, fn_arg);
	free(bptree);
	return 0;
}

static bptree_node_t *_get_first_leaf_node(bptree_t *bptree)
{
	bptree_node_t *c;

	if (!(c = bptree->root))
		return NULL;

	while (!c->is_leaf)
		c = c->pointers[0];

	return c;
}

static bptree_iter_t *
	_do_bptree_iter_create(bptree_t *bptree, bptree_lookup_method_t method, const char *key_start, const char *key_end)
{
	bptree_iter_t *iter;

	if (!(iter = malloc(sizeof(bptree_iter_t))))
		return NULL;

	iter->method        = method;
	iter->bptree        = bptree;
	iter->key_start     = key_start;
	iter->key_end       = key_end;
	iter->key_start_len = method == LOOKUP_PREFIX ? strlen(key_start) : 0;
	iter->c             = NULL;
	iter->i             = 0;

	return iter;
}

bptree_iter_t *bptree_iter_create(bptree_t *bptree, const char *key_start, const char *key_end)
{
	return _do_bptree_iter_create(bptree, LOOKUP_EXACT, key_start, key_end);
}

bptree_iter_t *bptree_iter_create_prefix(bptree_t *bptree, const char *prefix)
{
	return _do_bptree_iter_create(bptree, LOOKUP_PREFIX, prefix, NULL);
}

void *bptree_iter_current(bptree_iter_t *iter, const char **key, size_t *data_size, unsigned *data_ref_count)
{
	bptree_record_t *rec;

	if (iter->c) {
		rec = iter->c->pointers[iter->i];

		if (key)
			*key = iter->c->bkeys[iter->i]->key;
		if (data_size)
			*data_size = rec->data_size;
		if (data_ref_count)
			*data_ref_count = rec->ref_count;

		return rec->data;
	} else {
		if (key)
			*key = NULL;
		if (data_size)
			*data_size = 0;
		if (data_ref_count)
			*data_ref_count = 0;

		return NULL;
	}
}

const char *bptree_iter_current_key(bptree_iter_t *iter)
{
	if (iter->c)
		return iter->c->bkeys[iter->i]->key;
	else
		return NULL;
}

void *bptree_iter_next(bptree_iter_t *iter, const char **key, size_t *data_size, unsigned *data_ref_count)
{
	if (iter->c) {
		if (iter->i < (iter->c->num_keys - 1))
			iter->i++;
		else {
			iter->c = iter->c->pointers[iter->bptree->order - 1];
			iter->i = 0;
		}
	} else {
		if (iter->key_start)
			(void) _find(iter->bptree, iter->key_start, iter->method, &iter->c, &iter->i, NULL);
		else {
			iter->c = _get_first_leaf_node(iter->bptree);
			iter->i = 0;
		}
	}

	if (iter->c) {
		switch (iter->method) {
			case LOOKUP_EXACT:
				if (iter->key_end) {
					if (strcmp(iter->c->bkeys[iter->i]->key, iter->key_end) > 0) {
						iter->c = NULL;
						iter->i = 0;
					}
				}
				break;
			case LOOKUP_PREFIX:
				if (iter->key_start) {
					if (strncmp(iter->c->bkeys[iter->i]->key, iter->key_start, iter->key_start_len) != 0) {
						iter->c = NULL;
						iter->i = 0;
					}
				}
				break;
		}
	}

	return bptree_iter_current(iter, key, data_size, data_ref_count);
}

void bptree_iter_reset(bptree_iter_t *iter, const char *key_start, const char *key_end)
{
	iter->c         = NULL;
	iter->i         = 0;
	iter->method    = LOOKUP_EXACT;
	iter->key_start = key_start;
	iter->key_end   = key_end;
}

void bptree_iter_reset_prefix(bptree_iter_t *iter, const char *prefix)
{
	iter->c             = NULL;
	iter->i             = 0;
	iter->method        = LOOKUP_PREFIX;
	iter->key_start     = prefix;
	iter->key_end       = NULL;
	iter->key_start_len = strlen(prefix);
}

void bptree_iter(bptree_t *bptree, const char *key_start, const char *key_end, bptree_iterate_fn_t fn, void *fn_arg)
{
	bptree_iter_t iter = {.bptree = bptree, .key_start = key_start, .key_end = key_end, .c = NULL, .i = 0};
	const char   *key;
	void         *data;
	size_t        data_size;
	unsigned      data_ref_count;

	do {
		data = bptree_iter_next(&iter, &key, &data_size, &data_ref_count);

		if (!key)
			break;

		fn(key, data, data_size, data_ref_count, fn_arg);
	} while (true);
}

void bptree_iter_destroy(bptree_iter_t *iter)
{
	free(iter);
}
