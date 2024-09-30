/*
 * SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "../src/internal/bptree.c"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

void print_node(bptree_node_t *n)
{
	int i;

	print_message("{");
	if (n->is_leaf) {
		for (i = 0; i < n->num_keys; i++)
			print_message(" %s", n->bkeys[i]->key);
	} else {
		for (i = 0; i <= n->num_keys; i++) {
			print_message(" %s:", i < n->num_keys ? n->bkeys[i]->key : "_");
			print_node(n->pointers[i]);
		}
	}
	print_message(" }");
}

void print_bptree(bptree_t *bptree)
{
	if (!bptree->root) {
		print_message("{ }\n");
		return;
	}
	print_node(bptree->root);
	print_message("\n");
}

void verify_node(bptree_t       *bptree,
                 bptree_node_t  *n,
                 bptree_node_t **next_leaf,
                 bptree_key_t  **bkey,
                 size_t         *num_entries,
                 size_t         *data_size,
                 size_t         *meta_size,
                 bool            last)
{
	bptree_record_t *rec;
	int              i;

	if (n->is_leaf) {
		if (*next_leaf)
			assert_ptr_equal(n, *next_leaf);
		assert_true(n->num_keys < bptree->order);
		if (n != bptree->root)
			assert_true(n->num_keys >= _cut(bptree->order - 1));
		*num_entries += n->num_keys;
		*meta_size   += sizeof(*n) + (bptree->order - 1) * sizeof(bptree_key_t *) + bptree->order * sizeof(void *);
		for (i = 0; i < n->num_keys; i++) {
			int ref = i < n->num_keys - 1 ? 1 : last ? 1 : 2;
			assert_non_null(n->bkeys[i]);
			assert_non_null(n->pointers[i]);
			if (*bkey)
				assert_true(strcmp((*bkey)->key, n->bkeys[i]->key) < 0);
			*bkey = n->bkeys[i];
			assert_true((*bkey)->ref_count == ref);
			*meta_size += sizeof(bptree_key_t) + strlen((*bkey)->key) + 1 + sizeof(bptree_record_t);
			rec         = n->pointers[i];
			assert_true(rec->ref_count > 0);
			*data_size += rec->data_size;
		}
		*next_leaf = n->pointers[bptree->order - 1];
		return;
	}
	assert_true(n->num_keys < bptree->order);
	if (n != bptree->root)
		assert_true(n->num_keys >= _cut(bptree->order) - 1);
	*meta_size += sizeof(*n) + (bptree->order - 1) * sizeof(bptree_key_t *) + bptree->order * sizeof(void *);
	for (i = 0; i <= n->num_keys; i++) {
		assert_non_null(n->pointers[i]);
		assert_ptr_equal(((bptree_node_t *) n->pointers[i])->parent, n);
		verify_node(bptree, n->pointers[i], next_leaf, bkey, num_entries, data_size, meta_size, last && i == n->num_keys);
		if (i < n->num_keys)
			assert_ptr_equal(n->bkeys[i], *bkey);
	}
}

/* verify:
 * 1. that all the nodes in the bptree have a valid numbers of pointers
 * 2. that all the rightmost keys in the leaf block are correctly copied to the internal nodes
 * 3. that each leaf block correctly points to the next leaf block
 * 4. that all the keys have the proper reference counts
 * 5. That every node correctly points to its parent
 * 6. That the keys are in order
 * 7. That the number of entries in the stats match the actual number
 * 8. That the meta_size is correct
 * 9. That the data_size is correct
 */
void verify_bptree(bptree_t *bptree)
{
	bptree_node_t *next_leaf   = NULL;
	bptree_key_t  *bkey        = NULL;
	size_t         num_entries = 0;
	size_t         check_data_size, data_size = 0;
	size_t         check_meta_size, meta_size = sizeof(*bptree);

	assert_non_null(bptree);
	if (!bptree->root)
		goto out;

	assert_null(bptree->root->parent);
	verify_node(bptree, bptree->root, &next_leaf, &bkey, &num_entries, &data_size, &meta_size, true);
	assert_null(next_leaf);

out:
	assert_int_equal(bptree_get_entry_count(bptree), num_entries);
	bptree_get_size(bptree, &check_meta_size, &check_data_size);
	assert_int_equal(check_meta_size, meta_size);
	assert_int_equal(check_data_size, data_size);
	return;
}

typedef struct checker {
	char    **keys;
	void    **values;
	size_t   *sizes;
	unsigned *ref_counts;
	bool     *skips;
	int       num_entries;
	int       idx;
} checker_t;

static void checker_fn(const char *key, void *value, size_t size, unsigned ref_count, void *arg)
{
	checker_t *checker = (checker_t *) arg;

	while (checker->idx < checker->num_entries && checker->skips[checker->idx])
		checker->idx++;
	assert_true(checker->idx < checker->num_entries);
	assert_string_equal(checker->keys[checker->idx], key);
	assert_ptr_equal(checker->values[checker->idx], value);
	assert_int_equal(checker->sizes[checker->idx], size);
	assert_int_equal(checker->ref_counts[checker->idx], ref_count);
	checker->idx++;
}

static void test_bptree_invalid()
{
	assert_null(bptree_create(0));
	assert_null(bptree_create(3));
}

static void test_bptree_empty()
{
	bptree_t *bptree = bptree_create(4);
	verify_bptree(bptree);
	print_bptree(bptree);
	assert_int_equal(bptree_get_height(bptree), 0);
	bptree_destroy(bptree);
}

static void insert_from_checker(bptree_t *bptree, checker_t *checker, int idx)
{
	assert_int_equal(bptree_add(bptree, checker->keys[idx], checker->values[idx], checker->sizes[idx]), 0);
	checker->skips[idx] = false;
}

static void insert_from_checker_ids(bptree_t *bptree, checker_t *checker, int *ids, int count)
{
	int i;

	for (i = 0; i < count; i++)
		insert_from_checker(bptree, checker, ids[i]);
}

static void lookup_from_checker(bptree_t *bptree, checker_t *checker, int idx)
{
	size_t   data_size;
	unsigned data_ref_count;

	assert_false(checker->skips[idx]);
	assert_ptr_equal(bptree_lookup(bptree, checker->keys[idx], &data_size, &data_ref_count), checker->values[idx]);
	assert_int_equal(data_size, checker->sizes[idx]);
	assert_int_equal(data_ref_count, checker->ref_counts[idx]);
}

static void lookup_all_from_checker(bptree_t *bptree, checker_t *checker)
{
	int i;

	for (i = 0; i < checker->num_entries; i++) {
		if (!checker->skips[i])
			lookup_from_checker(bptree, checker, i);
	}
}

static void remove_from_checker(bptree_t *bptree, checker_t *checker, int idx)
{
	assert_int_equal(bptree_del(bptree, checker->keys[idx]), 0);
	checker->skips[idx] = true;
}

static void remove_from_checker_ids(bptree_t *bptree, checker_t *checker, int *ids, int count)
{
	int i;

	for (i = 0; i < count; i++)
		remove_from_checker(bptree, checker, ids[i]);
}

static void assert_checker_finished(checker_t *checker)
{
	while (checker->idx < checker->num_entries && checker->skips[checker->idx])
		checker->idx++;
	assert_int_equal(checker->idx, checker->num_entries);
}

static checker_t *init_checker(int num)
{
	uintptr_t  i;
	checker_t *checker;
	char      *key_buf;

	assert_non_null(checker = malloc(sizeof(*checker)));
	assert_non_null(checker->keys = malloc(num * sizeof(char *)));
	assert_non_null(checker->values = malloc(num * sizeof(void *)));
	assert_non_null(checker->sizes = malloc(num * sizeof(size_t)));
	assert_non_null(checker->ref_counts = malloc(num * sizeof(unsigned)));
	assert_non_null(checker->skips = malloc(num * sizeof(bool)));
	checker->num_entries = num;
	checker->idx         = 0;

	assert_non_null(key_buf = calloc(num, 2));
	for (i = 0; i < num; i++) {
		key_buf[2 * i]         = 'A' + i;
		checker->keys[i]       = &key_buf[2 * i];
		checker->values[i]     = (void *) i;
		checker->sizes[i]      = 10 + i;
		checker->ref_counts[i] = 1;
		checker->skips[i]      = true;
	}
	return checker;
}

static void free_checker(checker_t *checker)
{
	free(checker->keys[0]); /* key_buf */
	free(checker->keys);
	free(checker->values);
	free(checker->sizes);
	free(checker->ref_counts);
	free(checker);
}

static void test_bptree_one_entry()
{
	checker_t *checker = init_checker(1);
	bptree_t  *bptree  = bptree_create(4);

	assert_non_null(bptree);
	insert_from_checker(bptree, checker, 0);
	verify_bptree(bptree);
	assert_int_equal(bptree_get_height(bptree), 0);
	lookup_from_checker(bptree, checker, 0);
	bptree_destroy_with_fn(bptree, checker_fn, checker);
	assert_checker_finished(checker);
	free_checker(checker);
}

static void do_test_bptree_actions(int *setup_ids, int setup_count, int *action_ids, int action_count, bool is_insert, int height)
{
	checker_t *checker = init_checker(is_insert ? setup_count + action_count : setup_count);
	bptree_t  *bptree  = bptree_create(4);

	assert_non_null(bptree);
	insert_from_checker_ids(bptree, checker, setup_ids, setup_count);
	print_bptree(bptree);
	if (action_ids && action_count > 0) {
		if (is_insert)
			insert_from_checker_ids(bptree, checker, action_ids, action_count);
		else
			remove_from_checker_ids(bptree, checker, action_ids, action_count);
		print_bptree(bptree);
	}
	verify_bptree(bptree);
	if (!is_insert && setup_count == action_count)
		assert_null(bptree->root);
	if (height >= 0)
		assert_int_equal(bptree_get_height(bptree), height);
	lookup_all_from_checker(bptree, checker);
	bptree_iter(bptree, NULL, NULL, checker_fn, checker);
	assert_checker_finished(checker);
	bptree_destroy(bptree);
	free_checker(checker);
}

static void test_bptree_full_root()
{
	int ids[] = {2, 0, 1};

	do_test_bptree_actions(ids, 3, NULL, 0, false, 0);
}

static void test_bptree_remove_one_from_root()
{
	int insert_ids[] = {2, 1, 0};
	int remove_ids[] = {2};

	do_test_bptree_actions(insert_ids, 3, remove_ids, 1, false, 0);
}

static void test_bptree_remove_all_from_root()
{
	int ids[] = {1, 2, 0};

	do_test_bptree_actions(ids, 3, ids, 3, false, 0);
}

static void test_bptree_split_root_leaf_1()
{
	int ids[] = {1, 2, 3, 0};

	do_test_bptree_actions(ids, 3, &ids[3], 1, true, 1);
}

static void test_bptree_split_root_leaf_2()
{
	int ids[] = {0, 2, 3, 1};

	do_test_bptree_actions(ids, 3, &ids[3], 1, true, 1);
}

static void test_bptree_split_root_leaf_3()
{
	int ids[] = {0, 1, 3, 2};

	do_test_bptree_actions(ids, 3, &ids[3], 1, true, 1);
}

static void test_bptree_split_root_leaf_4()
{
	int ids[] = {0, 1, 2, 3};

	do_test_bptree_actions(ids, 3, &ids[3], 1, true, 1);
}

static void test_bptree_split_leaf_1()
{
	int ids[] = {0, 1, 3, 4, 5, 2};

	do_test_bptree_actions(ids, 5, &ids[5], 1, true, 1);
}

static void test_bptree_split_leaf_2()
{
	int ids[] = {0, 1, 2, 4, 5, 3};

	do_test_bptree_actions(ids, 5, &ids[5], 1, true, 1);
}

static void test_bptree_split_leaf_3()
{
	int ids[] = {0, 1, 2, 3, 5, 4};

	do_test_bptree_actions(ids, 5, &ids[5], 1, true, 1);
}

static void test_bptree_split_leaf_4()
{
	int ids[] = {0, 1, 2, 3, 4, 5};

	do_test_bptree_actions(ids, 5, &ids[5], 1, true, 1);
}

static void test_bptree_split_leaf_5()
{
	int ids[] = {1, 3, 4, 5, 2, 0};

	do_test_bptree_actions(ids, 5, &ids[5], 1, true, 1);
}

static void test_bptree_split_leaf_6()
{
	int ids[] = {0, 3, 4, 5, 2, 1};

	do_test_bptree_actions(ids, 5, &ids[5], 1, true, 1);
}

static void test_bptree_split_leaf_7()
{
	int ids[] = {0, 3, 4, 5, 1, 2};

	do_test_bptree_actions(ids, 5, &ids[5], 1, true, 1);
}

static void test_bptree_split_root_node_1()
{
	int ids[] = {11, 12, 8, 9, 5, 6, 2, 3, 10, 7, 4, 1, 0};

	do_test_bptree_actions(ids, 12, &ids[12], 1, true, 2);
}

static void test_bptree_split_root_node_2()
{
	int ids[] = {11, 12, 8, 9, 5, 6, 1, 2, 10, 7, 4, 0, 3};

	do_test_bptree_actions(ids, 12, &ids[12], 1, true, 2);
}

static void test_bptree_split_root_node_3()
{
	int ids[] = {11, 12, 8, 9, 4, 5, 1, 2, 10, 7, 3, 0, 6};

	do_test_bptree_actions(ids, 12, &ids[12], 1, true, 2);
}

static void test_bptree_split_root_node_4()
{
	int ids[] = {11, 12, 7, 8, 4, 5, 1, 2, 10, 6, 3, 0, 9};

	do_test_bptree_actions(ids, 12, &ids[12], 1, true, 2);
}

static void test_bptree_split_node_1()
{
	int ids[] = {0, 1, 2, 3, 6, 7, 8, 9, 10, 11, 12, 13, 5, 4};

	do_test_bptree_actions(ids, 13, &ids[13], 1, true, 2);
}

static void test_bptree_split_node_2()
{
	int ids[] = {0, 1, 2, 3, 4, 5, 8, 9, 10, 11, 12, 13, 6, 7};

	do_test_bptree_actions(ids, 13, &ids[13], 1, true, 2);
}

static void test_bptree_split_node_3()
{
	int ids[] = {0, 1, 2, 3, 4, 5, 6, 7, 9, 11, 12, 13, 8, 10};

	do_test_bptree_actions(ids, 13, &ids[13], 1, true, 2);
}

static void test_bptree_split_node_4()
{
	int ids[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};

	do_test_bptree_actions(ids, 13, &ids[13], 1, true, 2);
}

static void test_bptree_multi_split()
{
	int ids[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21};

	do_test_bptree_actions(ids, 21, &ids[21], 1, true, 3);
}

static void test_remove_last_root()
{
	int ins_ids[] = {0, 1, 2};
	int rm_ids[]  = {2};

	do_test_bptree_actions(ins_ids, 3, rm_ids, 1, false, 0);
}

static void test_remove_last_leaf1()
{
	int ins_ids[] = {1, 2, 4, 5, 0, 3};
	int rm_ids[]  = {2};

	do_test_bptree_actions(ins_ids, 6, rm_ids, 1, false, 1);
}

static void test_remove_last_leaf2()
{
	int ins_ids[] = {0, 1, 3, 4, 5, 6, 7, 8, 9, 10, 2};
	int rm_ids[]  = {4};

	do_test_bptree_actions(ins_ids, 11, rm_ids, 1, false, 2);
}

static void test_remove_last_leaf3()
{
	int ins_ids[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
	int rm_ids[]  = {10};

	do_test_bptree_actions(ins_ids, 11, rm_ids, 1, false, 2);
}

static void test_redistribute_left1()
{
	int ins_ids[] = {0, 1, 2, 3, 4, 5, 7, 8, 9, 10, 6};
	int rm_ids[]  = {9};

	do_test_bptree_actions(ins_ids, 11, rm_ids, 1, false, 2);
}

static void test_redistribute_left2()
{
	int ins_ids[] = {1, 2, 3, 4, 5, 6, 7, 0};
	int rm_ids[]  = {4};

	do_test_bptree_actions(ins_ids, 8, rm_ids, 1, false, 1);
}

static void test_redistribute_right1()
{
	int ins_ids[] = {0, 1, 3, 4, 5, 6, 2};
	int rm_ids[]  = {1};

	do_test_bptree_actions(ins_ids, 7, rm_ids, 1, false, 1);
}

static void test_redistribute_right2()
{
	int ins_ids[] = {0, 1, 3, 4, 5, 6, 7, 8, 9, 10, 2};
	int rm_ids[]  = {0};

	do_test_bptree_actions(ins_ids, 11, rm_ids, 1, false, 2);
}

static void test_coalesce_left()
{
	int ins_ids[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
	int rm_ids[]  = {8};

	do_test_bptree_actions(ins_ids, 10, rm_ids, 1, false, 2);
}

static void test_coalesce_right()
{
	int ins_ids[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
	int rm_ids[]  = {5};

	do_test_bptree_actions(ins_ids, 10, rm_ids, 1, false, 2);
}

static void test_coalesce_redistribute_right()
{
	int ins_ids[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
	int rm_ids[]  = {3};

	do_test_bptree_actions(ins_ids, 12, rm_ids, 1, false, 2);
}

static void test_coalesce_redistribute_left()
{
	int ins_ids[] = {4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 0, 1, 2, 3};
	int rm_ids[]  = {8};

	do_test_bptree_actions(ins_ids, 18, rm_ids, 1, false, 2);
}

static void test_coalesce_coalesce_left()
{
	int ins_ids[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
	int rm_ids[]  = {7};

	do_test_bptree_actions(ins_ids, 14, rm_ids, 1, false, 2);
}

static void test_coalesce_coalesce_right()
{
	int ins_ids[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
	int rm_ids[]  = {0};

	do_test_bptree_actions(ins_ids, 14, rm_ids, 1, false, 2);
}

static void test_coalesce_till_root()
{
	int ins_ids[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21};
	int rm_ids[]  = {2};

	do_test_bptree_actions(ins_ids, 22, rm_ids, 1, false, 2);
}

static void test_bptree_remove_3_height()
{
	int ids[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21};

	do_test_bptree_actions(ids, 22, ids, 22, false, 0);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_bptree_invalid),
		cmocka_unit_test(test_bptree_empty),
		cmocka_unit_test(test_bptree_one_entry),
		cmocka_unit_test(test_bptree_full_root),
		cmocka_unit_test(test_bptree_remove_one_from_root),
		cmocka_unit_test(test_bptree_remove_all_from_root),
		cmocka_unit_test(test_bptree_split_root_leaf_1),
		cmocka_unit_test(test_bptree_split_root_leaf_2),
		cmocka_unit_test(test_bptree_split_root_leaf_3),
		cmocka_unit_test(test_bptree_split_root_leaf_4),
		cmocka_unit_test(test_bptree_split_leaf_1),
		cmocka_unit_test(test_bptree_split_leaf_2),
		cmocka_unit_test(test_bptree_split_leaf_3),
		cmocka_unit_test(test_bptree_split_leaf_4),
		cmocka_unit_test(test_bptree_split_leaf_5),
		cmocka_unit_test(test_bptree_split_leaf_6),
		cmocka_unit_test(test_bptree_split_leaf_7),
		cmocka_unit_test(test_bptree_split_root_node_1),
		cmocka_unit_test(test_bptree_split_root_node_2),
		cmocka_unit_test(test_bptree_split_root_node_3),
		cmocka_unit_test(test_bptree_split_root_node_4),
		cmocka_unit_test(test_bptree_split_node_1),
		cmocka_unit_test(test_bptree_split_node_2),
		cmocka_unit_test(test_bptree_split_node_3),
		cmocka_unit_test(test_bptree_split_node_4),
		cmocka_unit_test(test_bptree_multi_split),
		cmocka_unit_test(test_remove_last_root),
		cmocka_unit_test(test_remove_last_leaf1),
		cmocka_unit_test(test_remove_last_leaf2),
		cmocka_unit_test(test_remove_last_leaf3),
		cmocka_unit_test(test_redistribute_left1),
		cmocka_unit_test(test_redistribute_left2),
		cmocka_unit_test(test_redistribute_right1),
		cmocka_unit_test(test_redistribute_right2),
		cmocka_unit_test(test_coalesce_left),
		cmocka_unit_test(test_coalesce_right),
		cmocka_unit_test(test_coalesce_redistribute_right),
		cmocka_unit_test(test_coalesce_redistribute_left),
		cmocka_unit_test(test_coalesce_coalesce_left),
		cmocka_unit_test(test_coalesce_coalesce_right),
		cmocka_unit_test(test_coalesce_till_root),
		cmocka_unit_test(test_bptree_remove_3_height),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
