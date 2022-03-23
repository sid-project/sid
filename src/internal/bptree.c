/*
 *  Copyright (c) 2018 Amittai Aviram  http://www.amittai.com  All rights reserved.
 *  Copyright (c) 2022 Red Hat, Inc. All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice,
 *  this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice,
 *  this list of conditions and the following disclaimer in the documentation
 *  and/or other materials provided with the distribution.

 *  3. The name of the copyright holder may not be used to endorse
 *  or promote products derived from this software without specific
 *  prior written permission.

 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
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
 *   - added 'bptree_update' function with 'bptree_update_fn_t' callback
 *   - copy key on insert and use reference counting so only a single key
 *     copy is used if key is referenced in leaf and/or internal nodes
 *   - added 'bptree_iter_*' iterator interface
 *   - track memory usage for both bptree's metadata and data and expose this
 *     information through 'bptree_get_size'
 */

#include "internal/bptree.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

typedef struct bptree_record {
	size_t data_size;
	void * data;
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
	void **             pointers;
	bptree_key_t **     bkeys;
	struct bptree_node *parent;
	bool                is_leaf;
	int                 num_keys;
} bptree_node_t;

typedef struct bptree_iter {
	bptree_t *     bptree;
	const char *   key_start;
	const char *   key_end;
	bptree_node_t *c;
	int            i;
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
} bptree_t;

static bptree_node_t *_insert_into_parent(bptree_t *bptree, bptree_node_t *left, bptree_key_t *bkey, bptree_node_t *right);
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

	bptree->root      = NULL;
	bptree->order     = order;
	bptree->meta_size = sizeof(*bptree);
	bptree->data_size = 0;

	return bptree;
}

/*
 * Utility function to give the height of the tree, which length
 * in number of edges of the path from the root to any leaf.
 */
int bptree_get_height(bptree_t *bptree)
{
	int            h = 0;
	bptree_node_t *c = bptree->root;

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

	i = 0;
	c = bptree->root;

	while (!c->is_leaf) {
		i = 0;

		while (i < c->num_keys) {
			if (strcmp(key, c->bkeys[i]->key) >= 0)
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
bptree_record_t *_find(bptree_t *bptree, const char *key, bptree_node_t **leaf_out, int *i_out, bptree_key_t **bkey_out)
{
	int            i;
	bptree_node_t *leaf;

	if (!bptree->root) {
		if (leaf_out)
			*leaf_out = NULL;
		if (bkey_out)
			*bkey_out = NULL;
		return NULL;
	}

	leaf = _find_leaf(bptree, key);

	/*
	 * If root != NULL, leaf must have a value,
	 * even if it does not contain the desired key.
	 * (The leaf holds the range of keys that would
	 * include the desired key.)
	 */

	for (i = 0; i < leaf->num_keys; i++) {
		if (!strcmp(leaf->bkeys[i]->key, key))
			break;
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
void *bptree_lookup(bptree_t *bptree, const char *key, size_t *data_size)
{
	bptree_record_t *rec;

	if (!(rec = _find(bptree, key, NULL, NULL, NULL)))
		return NULL;

	if (data_size)
		*data_size = rec->data_size;

	return rec->data;
}

/*
 * Finds the appropriate place to split a node that is too big into two.
 */
static int _cut(int length)
{
	if (length % 2 == 0)
		return length / 2;
	else
		return length / 2 + 1;
}

static bptree_record_t *_make_record(bptree_t *bptree, void *data, size_t data_size)
{
	bptree_record_t *rec;

	if (!(rec = malloc(sizeof(bptree_record_t))))
		return NULL;

	rec->data_size = data_size;
	rec->data      = data;

	bptree->meta_size += sizeof(*rec);
	bptree->data_size += data_size;

	return rec;
}

static void _destroy_record(bptree_t *bptree, bptree_record_t *rec)
{
	bptree->meta_size -= sizeof(*rec);
	bptree->data_size -= rec->data_size;

	free(rec);
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

	bkey->ref_count = 0;

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

	new_node->is_leaf  = false;
	new_node->num_keys = 0;
	new_node->parent   = NULL;

	bptree->meta_size += (sizeof(*new_node) + pointers_size + bkeys_size);

	return new_node;
}

static void _destroy_node(bptree_t *bptree, bptree_node_t *n)
{
	bptree->meta_size -= (sizeof(*n) + ((bptree->order - 1) * sizeof(bptree_key_t *)) + (bptree->order * sizeof(void *)));

	free(n->bkeys);
	free(n->pointers);
	free(n);
}

/*
 * Creates a new leaf by creating a node and then adapting it appropriately.
 */
static bptree_node_t *_make_leaf(bptree_t *bptree)
{
	bptree_node_t *leaf;

	if ((leaf = _make_node(bptree)))
		leaf->is_leaf = true;

	return leaf;
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

	while (insertion_point < leaf->num_keys && strcmp(leaf->bkeys[insertion_point]->key, bkey->key) < 0) {
		insertion_point++;
	}

	for (i = leaf->num_keys; i > insertion_point; i--) {
		leaf->bkeys[i]    = leaf->bkeys[i - 1];
		leaf->pointers[i] = leaf->pointers[i - 1];
	}

	leaf->bkeys[insertion_point]    = _ref_bkey(bkey);
	leaf->pointers[insertion_point] = pointer;
	leaf->num_keys++;

	return leaf;
}

/*
 * Inserts a new key and pointer to a new record into a leaf so as to
 * exceed the tree's order, causing the leaf to be split in half.
 */
static bptree_node_t *
	_insert_into_leaf_after_splitting(bptree_t *bptree, bptree_node_t *leaf, bptree_key_t *bkey, bptree_record_t *pointer)
{
	bptree_node_t *new_leaf;
	bptree_key_t **temp_bkeys;
	void **        temp_pointers;
	bptree_key_t * new_bkey;
	int            insertion_index, split, i, j;

	if (!(new_leaf = _make_leaf(bptree)))
		return NULL;

	// FIXME: try to optimize to avoid allocating temporary key and pointer arrays
	if (!(temp_bkeys = malloc(bptree->order * sizeof(bptree_key_t *))))
		return NULL;

	if (!(temp_pointers = malloc(bptree->order * sizeof(void *))))
		return NULL;

	insertion_index = 0;
	while (insertion_index < bptree->order - 1 && strcmp(leaf->bkeys[insertion_index]->key, bkey->key) < 0)
		insertion_index++;

	for (i = 0, j = 0; i < leaf->num_keys; i++, j++) {
		if (j == insertion_index)
			j++;

		temp_bkeys[j]    = leaf->bkeys[i];
		temp_pointers[j] = leaf->pointers[i];
	}

	temp_bkeys[insertion_index]    = _ref_bkey(bkey);
	temp_pointers[insertion_index] = pointer;

	leaf->num_keys = 0;

	split = _cut(bptree->order - 1);

	for (i = 0; i < split; i++) {
		leaf->pointers[i] = temp_pointers[i];
		leaf->bkeys[i]    = temp_bkeys[i];
		leaf->num_keys++;
	}

	for (i = split, j = 0; i < bptree->order; i++, j++) {
		new_leaf->pointers[j] = temp_pointers[i];
		new_leaf->bkeys[j]    = temp_bkeys[i];
		new_leaf->num_keys++;
	}

	free(temp_pointers);
	free(temp_bkeys);

	new_leaf->pointers[bptree->order - 1] = leaf->pointers[bptree->order - 1];
	leaf->pointers[bptree->order - 1]     = new_leaf;

	for (i = leaf->num_keys; i < bptree->order - 1; i++)
		leaf->pointers[i] = NULL;

	for (i = new_leaf->num_keys; i < bptree->order - 1; i++)
		new_leaf->pointers[i] = NULL;

	new_leaf->parent = leaf->parent;
	new_bkey         = new_leaf->bkeys[0];

	return _insert_into_parent(bptree, leaf, new_bkey, new_leaf);
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
static bptree_node_t *_insert_into_node_after_splitting(bptree_t *     bptree,
                                                        bptree_node_t *old_node,
                                                        int            left_index,
                                                        bptree_key_t * bkey,
                                                        bptree_node_t *right)
{
	int             i, j, split;
	bptree_node_t * new_node, *child;
	bptree_key_t *  bk_prime;
	bptree_key_t ** temp_bkeys;
	bptree_node_t **temp_pointers;
	bptree_node_t * n;

	/*
	 * First create a temporary set of keys and pointers to hold
	 * everything in order, including the new key and pointer,
	 * inserted in their correct places.
	 *
	 * Then create a new node and copy half of the keys and
	 * pointers to the old node and the other half to the new.
	 */

	// FIXME: try to optimize to avoid allocating temporary key and pointer arrays
	if (!(temp_pointers = malloc((bptree->order + 1) * sizeof(bptree_node_t *))))
		return NULL;

	if (!(temp_bkeys = malloc(bptree->order * sizeof(bptree_key_t *))))
		return NULL;

	for (i = 0, j = 0; i < old_node->num_keys + 1; i++, j++) {
		if (j == left_index + 1)
			j++;

		temp_pointers[j] = old_node->pointers[i];
	}

	for (i = 0, j = 0; i < old_node->num_keys; i++, j++) {
		if (j == left_index)
			j++;

		temp_bkeys[j] = old_node->bkeys[i];
	}

	temp_pointers[left_index + 1] = right;
	temp_bkeys[left_index]        = _ref_bkey(bkey);

	/*
	 * Create the new node and copy half the keys
	 * and pointers to the old and half to the new.
	 */
	split              = _cut(bptree->order);
	new_node           = _make_node(bptree);
	old_node->num_keys = 0;

	for (i = 0; i < split - 1; i++) {
		old_node->pointers[i] = temp_pointers[i];
		old_node->bkeys[i]    = temp_bkeys[i];
		old_node->num_keys++;
	}

	old_node->pointers[i] = temp_pointers[i];
	bk_prime              = temp_bkeys[split - 1];

	/*
	 * The bk_prime will be moved up one level in the tree and removed
	 * from current level after splitting. To avoid dropping the
	 * ref_count to 0 and hence premature freeing of the whole bk_prime,
	 * first, we will insert it into parent and then unref it at the end
	 * of this function.
	 */

	for (++i, j = 0; i < bptree->order; i++, j++) {
		new_node->pointers[j] = temp_pointers[i];
		new_node->bkeys[j]    = temp_bkeys[i];
		new_node->num_keys++;
	}

	new_node->pointers[j] = temp_pointers[i];

	free(temp_pointers);
	free(temp_bkeys);

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

	n = _insert_into_parent(bptree, old_node, bk_prime, new_node);
	_unref_bkey(bptree, bk_prime);

	return n;
}

/*
 * Creates a new root for two subtrees and inserts
 * the appropriate key into the new root.
 */
static bptree_node_t *_insert_into_new_root(bptree_t *bptree, bptree_node_t *left, bptree_key_t *bkey, bptree_node_t *right)
{
	bptree->root = _make_node(bptree);

	bptree->root->bkeys[0]    = _ref_bkey(bkey);
	bptree->root->pointers[0] = left;
	bptree->root->pointers[1] = right;
	bptree->root->num_keys++;
	bptree->root->parent = NULL;

	left->parent  = bptree->root;
	right->parent = bptree->root;

	return bptree->root;
}

/*
 * Inserts a new node (leaf or internal node) into the B+ tree.
 * Returns the root of the tree after insertion.
 */
static bptree_node_t *_insert_into_parent(bptree_t *bptree, bptree_node_t *left, bptree_key_t *bkey, bptree_node_t *right)
{
	int            left_index;
	bptree_node_t *parent;

	parent = left->parent;

	/* Case: new root. */

	if (!parent)
		return _insert_into_new_root(bptree, left, bkey, right);

	/* Case: leaf or node. (Remainder of function body.) */

	/* Find the parent's pointer to the left node. */

	left_index = _get_left_index(parent, left);

	/* Simple case: the new key fits into the node. */

	if (parent->num_keys < bptree->order - 1)
		return _insert_into_node(bptree, parent, left_index, bkey, right);

	/* Harder case: split a node in order to preserve the B+ tree properties. */

	return _insert_into_node_after_splitting(bptree, parent, left_index, bkey, right);
}

/*
 * First insertion: start a new tree.
 */
bptree_node_t *_create_root(bptree_t *bptree, bptree_key_t *bkey, bptree_record_t *pointer)
{
	bptree_node_t *leaf;

	if (!(leaf = _make_leaf(bptree)))
		return NULL;

	bptree->root                              = leaf;
	bptree->root->bkeys[0]                    = _ref_bkey(bkey);
	bptree->root->pointers[0]                 = pointer;
	bptree->root->pointers[bptree->order - 1] = NULL;
	bptree->root->parent                      = NULL;
	bptree->root->num_keys++;

	return bptree->root;
}

/*
 * Main insertion function.
 * Inserts a key and associated data into the B+ tree, causing the tree
 * to be adjusted however necessary to maintain the B+ tree properties.
 */
int bptree_insert(bptree_t *bptree, const char *key, void *data, size_t data_size)
{
	bptree_record_t *rec;
	bptree_node_t *  leaf;
	bptree_key_t *   bkey;

	if ((rec = _find(bptree, key, NULL, NULL, NULL))) {
		rec->data = data;
		bptree->data_size -= rec->data_size;
		rec->data_size = data_size;
		bptree->data_size += rec->data_size;
		return 0;
	}

	if (!(bkey = _make_bkey(bptree, key)))
		return -1;

	if (!(rec = _make_record(bptree, data, data_size))) {
		_destroy_bkey(bptree, bkey);
		return -1;
	}

	/* Case: the tree does not exist yet. Start a new tree. */

	if (!bptree->root)
		return _create_root(bptree, bkey, rec) ? 0 : -1;

	/* Case: the tree already exists. (Rest of function body.) */

	leaf = _find_leaf(bptree, key);

	/* Case: leaf has room for key and record pointer. */

	if (leaf->num_keys < bptree->order - 1)
		return _insert_into_leaf(leaf, bkey, rec) ? 0 : -1;

	/* Case: leaf must be split. */

	return _insert_into_leaf_after_splitting(bptree, leaf, bkey, rec) ? 0 : -1;
}

int bptree_update(bptree_t *         bptree,
                  const char *       key,
                  void **            data,
                  size_t *           data_size,
                  bptree_update_fn_t bptree_update_fn,
                  void *             bptree_update_fn_arg)
{
	bptree_record_t *rec = _find(bptree, key, NULL, NULL, NULL);

	if (rec) {
		if (!bptree_update_fn || bptree_update_fn(key, rec->data, rec->data_size, data, data_size, bptree_update_fn_arg)) {
			rec->data = data ? *data : NULL;
			bptree->data_size -= rec->data_size;
			rec->data_size = data_size ? *data_size : 0;
			bptree->data_size += rec->data_size;
		}
		return 0;
	} else {
		if (!bptree_update_fn || bptree_update_fn(key, NULL, 0, data, data_size, bptree_update_fn_arg))
			return bptree_insert(bptree, key, data ? *data : NULL, data_size ? *data_size : 0);
	}

	return 0;
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
	int i, num_pointers;

	/* Remove the key and shift other keys accordingly. */
	// TODO: no need to look for the key with strcmp, we already have the shared bkey so compare bkey pointers directly
	i = 0;
	while (strcmp(n->bkeys[i]->key, bkey->key))
		i++;

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

		for (i = 0; i < neighbor->num_keys + 1; i++) {
			tmp         = (bptree_node_t *) neighbor->pointers[i];
			tmp->parent = neighbor;
		}
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
static bptree_node_t *_redistribute_nodes(bptree_t *     bptree,
                                          bptree_node_t *n,
                                          bptree_node_t *neighbor,
                                          int            neighbor_index,
                                          int            k_prime_index,
                                          bptree_key_t * bk_prime)
{
	int            i;
	bptree_node_t *tmp;

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

		if (!n->is_leaf) {
			n->pointers[0]                         = neighbor->pointers[neighbor->num_keys];
			tmp                                    = (bptree_node_t *) n->pointers[0];
			tmp->parent                            = n;
			neighbor->pointers[neighbor->num_keys] = NULL;
			n->bkeys[0]                            = bk_prime;
			_unref_bkey(bptree, n->parent->bkeys[k_prime_index]);
			n->parent->bkeys[k_prime_index] = _ref_bkey(neighbor->bkeys[neighbor->num_keys - 1]);
		} else {
			n->pointers[0]                             = neighbor->pointers[neighbor->num_keys - 1];
			neighbor->pointers[neighbor->num_keys - 1] = NULL;
			n->bkeys[0]                                = neighbor->bkeys[neighbor->num_keys - 1];
			_unref_bkey(bptree, n->parent->bkeys[k_prime_index]);
			n->parent->bkeys[k_prime_index] = _ref_bkey(n->bkeys[0]);
		}
	}

	/*
	 * Case: n is the leftmost child.
	 * Take a key-pointer pair from the neighbor to the right.
	 * Move the neighbor's leftmost key-pointer pair to n's rightmost position.
	 */

	else {
		if (n->is_leaf) {
			n->bkeys[n->num_keys]    = neighbor->bkeys[0];
			n->pointers[n->num_keys] = neighbor->pointers[0];
			_unref_bkey(bptree, n->parent->bkeys[k_prime_index]);
			n->parent->bkeys[k_prime_index] = _ref_bkey(neighbor->bkeys[1]);
		} else {
			n->bkeys[n->num_keys]        = bk_prime;
			n->pointers[n->num_keys + 1] = neighbor->pointers[0];
			tmp                          = (bptree_node_t *) n->pointers[n->num_keys + 1];
			tmp->parent                  = n;
			_unref_bkey(bptree, n->parent->bkeys[k_prime_index]);
			n->parent->bkeys[k_prime_index] = _ref_bkey(neighbor->bkeys[0]);
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
	bptree_key_t * bk_prime;
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

	capacity = n->is_leaf ? bptree->order : bptree->order - 1;

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
int bptree_remove(bptree_t *bptree, const char *key)
{
	bptree_node_t *  key_leaf = NULL;
	bptree_record_t *rec      = NULL;
	bptree_key_t *   bkey     = NULL;
	int              r        = 0;

	rec = _find(bptree, key, &key_leaf, NULL, &bkey);

	/* CHANGE */

	if (rec && key_leaf) {
		r = _delete_entry(bptree, key_leaf, bkey, rec) ? 0 : -1;
		_destroy_record(bptree, rec);
	}

	return r;
}

static void _destroy_tree_nodes(bptree_t *bptree, bptree_node_t *n)
{
	int i;

	if (n->is_leaf) {
		for (i = 0; i < n->num_keys; i++) {
			_unref_bkey(bptree, n->bkeys[i]);
			_destroy_record(bptree, n->pointers[i]);
		}
	} else {
		for (i = 0; i < n->num_keys + 1; i++) {
			_destroy_tree_nodes(bptree, n->pointers[i]);
			if (i < n->num_keys)
				_unref_bkey(bptree, n->bkeys[i]);
		}
	}

	_destroy_node(bptree, n);
}

int bptree_destroy(bptree_t *bptree)
{
	if (bptree->root)
		_destroy_tree_nodes(bptree, bptree->root);
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

bptree_iter_t *bptree_iter_create(bptree_t *bptree, const char *key_start, const char *key_end)
{
	bptree_iter_t *iter;

	if (!(iter = malloc(sizeof(bptree_iter_t))))
		return NULL;

	iter->bptree    = bptree;
	iter->key_start = key_start;
	iter->key_end   = key_end;
	iter->c         = NULL;
	iter->i         = 0;

	return iter;
}

void *bptree_iter_current(bptree_iter_t *iter, size_t *data_size, const char **key)
{
	bptree_record_t *rec;

	if (iter->c) {
		rec = iter->c->pointers[iter->i];

		if (data_size)
			*data_size = rec->data_size;
		if (key)
			*key = iter->c->bkeys[iter->i]->key;

		return rec->data;
	} else {
		if (data_size)
			*data_size = 0;
		if (key)
			*key = NULL;

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

void *bptree_iter_next(bptree_iter_t *iter, size_t *data_size, const char **key)
{
	if (iter->c) {
		if (iter->i == (iter->c->num_keys - 1)) {
			iter->c = iter->c->pointers[iter->bptree->order - 1];
			iter->i = 0;
		} else
			iter->i++;

		if (iter->key_end && iter->c && strcmp(iter->c->bkeys[iter->i]->key, iter->key_end) > 0) {
			iter->c = NULL;
			iter->i = 0;
		}
	} else {
		if (iter->key_start) {
			if (!_find(iter->bptree, iter->key_start, &iter->c, &iter->i, NULL))
				return NULL;
		} else {
			iter->c = _get_first_leaf_node(iter->bptree);
			iter->i = 0;
		}
	}

	return bptree_iter_current(iter, data_size, key);
}

void bptree_iter_reset(bptree_iter_t *iter, const char *key_start, const char *key_end)
{
	iter->c         = NULL;
	iter->i         = 0;
	iter->key_start = key_start;
	iter->key_end   = key_end;
}

void bptree_iter(bptree_t *bptree, bptree_iterate_fn_t f, const char *key_start, const char *key_end)
{
	bptree_iter_t iter = {.bptree = bptree, .key_start = key_start, .key_end = key_end, .c = NULL, .i = 0};
	const char *  key;
	void *        data;
	size_t        data_size;

	do {
		data = bptree_iter_next(&iter, &data_size, &key);

		if (!key)
			break;

		f(key, data, data_size);
	} while (true);
}

void bptree_iter_destroy(bptree_iter_t *iter)
{
	free(iter);
}