/*
 * SPDX-FileCopyrightText: (C) 2017-2025 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/socket.h>
#define UNIT_TESTING /* enable cmocka memory testing in mem.c and kvs.c*/
#include "../src/internal/mem.c"
#include "../src/resource/kvs.c"
#include "../src/resource/ubr.c"
#include "ucmd-mod.h"

#include <cmocka.h>

#define MAX_TEST_ENTRIES 250
#define TEST_KEY         "test_key"
#define MERGE_KEY        "merge_key"
#define TEST_OWNER       "test_owner"

static void test_type_F(void **state)
{
	struct iovec           test_iov[]    = {{"test", sizeof("test")}, {"value", sizeof("value")}};
	size_t                 size          = sizeof(test_iov) / sizeof(test_iov[0]);
	size_t                 combined_size = sizeof("test") + sizeof("value");
	size_t                 value_size;
	struct kv_store_value *value =
		_create_kv_store_value(test_iov, size, SID_KVS_VAL_FL_VECTOR, SID_KVS_VAL_OP_MERGE, &value_size);
	assert_ptr_not_equal(value, NULL);
	assert_int_equal(memcmp(value->data, "test\0value", value->size), 0);
	assert_int_equal(value->size, combined_size);
	assert_int_equal(value->int_flags, KV_STORE_VALUE_INT_ALLOC);
	assert_int_equal(value->ext_flags, SID_KVS_VAL_OP_NONE);
	_destroy_kv_store_value(value);
}

static void test_type_E(void **state)
{
	struct iovec          *return_iov, test_iov[] = {{"test", sizeof("test")}, {"value", sizeof("value")}};
	size_t                 size = sizeof(test_iov) / sizeof(test_iov[0]);
	size_t                 value_size;
	struct kv_store_value *value =
		_create_kv_store_value(test_iov, size, SID_KVS_VAL_FL_VECTOR, SID_KVS_VAL_OP_NONE, &value_size);
	assert_ptr_not_equal(value, NULL);
	return_iov = (struct iovec *) value->data;

	for (int i = 0; i < value->size; i++) {
		assert_int_equal(return_iov[i].iov_len, test_iov[i].iov_len);
		assert_string_equal(return_iov[i].iov_base, test_iov[i].iov_base);
	}
	assert_int_equal(value->size, size);
	assert_int_equal(value->int_flags, KV_STORE_VALUE_INT_ALLOC);
	assert_int_equal(value->ext_flags, SID_KVS_VAL_FL_VECTOR);
	_destroy_kv_store_value(value);
}

static void test_type_G(void **state)
{
	struct iovec           test_iov[] = {{"test", sizeof("test")}, {"value", sizeof("value")}};
	size_t                 size       = sizeof(test_iov) / sizeof(test_iov[0]);
	size_t                 value_size;
	struct kv_store_value *value = _create_kv_store_value(test_iov,
	                                                      size,
	                                                      SID_KVS_VAL_FL_REF | SID_KVS_VAL_FL_VECTOR,
	                                                      SID_KVS_VAL_OP_NONE,
	                                                      &value_size);
	assert_ptr_not_equal(value, NULL);
	assert_ptr_equal(_get_ptr(value->data), test_iov);
	assert_int_equal(value->size, size);
	assert_int_equal(value->int_flags, 0);
	assert_int_equal(value->ext_flags, SID_KVS_VAL_FL_REF | SID_KVS_VAL_FL_VECTOR);
	_destroy_kv_store_value(value);
}

static void test_type_H(void **state)
{
	struct iovec           test_iov[] = {{"test", sizeof("test")}, {"value", sizeof("value")}};
	size_t                 size       = sizeof(test_iov) / sizeof(test_iov[0]);
	size_t                 value_size;
	struct iovec           old_iov[size];
	struct kv_store_value *value;
	int                    i;

	memcpy(old_iov, test_iov, sizeof(old_iov));
	value = _create_kv_store_value(test_iov,
	                               size,
	                               SID_KVS_VAL_FL_REF | SID_KVS_VAL_FL_VECTOR,
	                               SID_KVS_VAL_OP_MERGE,
	                               &value_size);
	assert_ptr_not_equal(value, NULL);
	assert_ptr_equal(_get_ptr(value->data), test_iov);
	assert_int_equal(value->size, size);
	for (i = 0; i < size; i++)
		assert_ptr_not_equal(test_iov[i].iov_base, old_iov[i].iov_base);
	assert_int_equal(value->int_flags, KV_STORE_VALUE_INT_ALLOC);
	assert_int_equal(value->ext_flags, SID_KVS_VAL_FL_REF | SID_KVS_VAL_FL_VECTOR);
	_destroy_kv_store_value(value);
	for (i = 0; i < size; i++) {
		assert_ptr_equal(test_iov[i].iov_base, NULL);
		assert_int_equal(test_iov[i].iov_len, 0);
	}
}

static void test_kvstore_iterate(void **state)
{
	struct iovec         test_iov[VVALUE_SINGLE_CNT];
	size_t               data_size, kv_size;
	const char          *key;
	struct iovec        *return_iov;
	sid_kvs_iter_t      *iter;
	sid_kv_fl_t          ucmd_flags = SID_KV_FL_NONE;
	sid_kvs_val_fl_t     flags;
	uint64_t             seqnum       = 0;
	uint16_t             gennum       = 0;
	sid_res_t           *kv_store_res = NULL;
	struct kv_update_arg update_arg;
	struct kv_unset_nfo  unset_nfo;
	size_t               meta_size = 0;

	kv_store_res                   = sid_res_create(SID_RES_NO_PARENT,
                                      &sid_res_type_kvs,
                                      SID_RES_FL_RESTRICT_WALK_UP,
                                      "testkvstore",
                                      &main_kv_store_res_params,
                                      SID_RES_PRIO_NORMAL,
                                      SID_RES_NO_SERVICE_LINKS);

	_vvalue_header_prep(test_iov, VVALUE_CNT(test_iov), &seqnum, &ucmd_flags, &gennum, (char *) TEST_OWNER);
	test_iov[VVALUE_IDX_DATA].iov_base = "test";
	test_iov[VVALUE_IDX_DATA].iov_len  = sizeof("test");

	update_arg = (struct kv_update_arg) {.res = kv_store_res, .gen_buf = NULL, .custom = NULL, .ret_code = -EREMOTEIO};

	/* Add the whole vector with TEST_KEY as the key */
	assert_int_equal(sid_kvs_va_set(kv_store_res,
	                                .key      = TEST_KEY,
	                                .value    = test_iov,
	                                .size     = VVALUE_IDX_DATA + 1,
	                                .flags    = SID_KVS_VAL_FL_VECTOR,
	                                .op_flags = SID_KVS_VAL_OP_NONE,
	                                .fn       = _kv_cb_write,
	                                .fn_arg   = &update_arg),
	                 0);

	assert_ptr_not_equal(iter = sid_kvs_iter_create(kv_store_res, NULL, NULL), NULL);
	/* validate the contents of the kv store */
	while ((return_iov = sid_kvs_iter_next(iter, &data_size, &key, &flags))) {
		assert_int_equal(strcmp(TEST_KEY, key), 0);
		assert_true(flags == SID_KVS_VAL_FL_VECTOR);
		assert_int_equal(strcmp(return_iov[VVALUE_IDX_DATA].iov_base, "test"), 0);
		assert_int_equal(return_iov[VVALUE_IDX_DATA].iov_len, sizeof("test"));
	}

	sid_kvs_iter_destroy(iter);
	sid_kvs_get_size(kv_store_res, &meta_size, &kv_size);

	assert_int_equal(kv_store_num_entries(kv_store_res), 1);
	/* TODO: if update_arg is NULL in the following call it causes SEGV */
	update_arg.ret_code = 0;
	unset_nfo.owner     = TEST_OWNER;
	unset_nfo.seqnum    = 0;
	update_arg.custom   = &unset_nfo;
	assert_int_equal(sid_kvs_va_unset(kv_store_res, .key = TEST_KEY, .fn = _kv_cb_main_unset, .fn_arg = &update_arg), 0);
	assert_int_equal(update_arg.ret_code, 0);
	assert_int_equal(kv_store_num_entries(kv_store_res), 0);
	sid_kvs_get_size(kv_store_res, &meta_size, &data_size);
	assert_int_equal(data_size, 0);

	sid_res_unref(kv_store_res);
}

static size_t add_sequential_test_data(char               *key,
                                       struct iovec        test_iov[MAX_TEST_ENTRIES],
                                       sid_res_t          *kv_store_res,
                                       int                 num_entries,
                                       sid_kvs_val_fl_t    flags,
                                       sid_kvs_val_op_fl_t op_flags)
{
	size_t size = 0;

	for (int i = 0; i < num_entries; i++) {
		int   strlen = snprintf(NULL, 0, "%d", i);
		char *str    = malloc(strlen + 1);
		snprintf(str, strlen + 1, "%d", i);
		test_iov[i].iov_base  = str;
		test_iov[i].iov_len   = strlen + 1;
		size                 += strlen + 1;
	}
	assert_int_equal(sid_kvs_va_set(kv_store_res,
	                                .key      = MERGE_KEY,
	                                .value    = test_iov,
	                                .size     = MAX_TEST_ENTRIES,
	                                .flags    = flags,
	                                .op_flags = op_flags),
	                 0);

	/* if the kv store is making a copy, free this copy */
	if ((flags & SID_KVS_VAL_FL_REF) == 0) {
		for (int i = 0; i < num_entries; i++) {
			free(test_iov[i].iov_base);
		}
	}
	return size;
}

static void release_test_data(int num_entries, struct iovec test_iov[MAX_TEST_ENTRIES], sid_kvs_val_fl_t flags)
{
	/* non references are released when the kv-store makes a copy */
	if ((flags & SID_KVS_VAL_FL_REF) == 0)
		return;

	for (int i = 0; i < num_entries; i++) {
		free(test_iov[i].iov_base);
		test_iov[i].iov_base = NULL;
		test_iov[i].iov_len  = 0;
	}
}

/*
 * Note: Currently the kv store merges data in order.  This may change, if it does the
 * validation will need to be updated.
 */
static int validate_merged_data(int num_entries, char *data)
{
	char  int_buff[20];
	char *temp_ptr;
	temp_ptr = data;
	for (int i = 0; i < num_entries; i++) {
		int strlen = snprintf(int_buff, 20, "%d", i);
		if (strncmp(temp_ptr, temp_ptr, strlen) != 0)
			return 1;
		temp_ptr += strlen + 1;
	}
	return 0;
}

static void test_kvstore_merge_op(void **state)
{
	struct iovec     test_iov[MAX_TEST_ENTRIES];
	size_t           data_size;
	const char      *key;
	void            *data;
	sid_kvs_iter_t  *iter;
	sid_kvs_val_fl_t flags        = SID_KVS_VAL_FL_VECTOR;
	sid_res_t       *kv_store_res = NULL;

	kv_store_res                  = sid_res_create(SID_RES_NO_PARENT,
                                      &sid_res_type_kvs,
                                      SID_RES_FL_RESTRICT_WALK_UP,
                                      "testkvstore",
                                      &main_kv_store_res_params,
                                      SID_RES_PRIO_NORMAL,
                                      SID_RES_NO_SERVICE_LINKS);

	add_sequential_test_data(MERGE_KEY, test_iov, kv_store_res, MAX_TEST_ENTRIES, flags, SID_KVS_VAL_OP_MERGE);
	assert_int_equal(kv_store_num_entries(kv_store_res), 1);

	data = sid_kvs_va_get(kv_store_res, .key = MERGE_KEY, .size = &data_size);

	/* Validate the concatenated contents of the kv store.
	 * The data variable contains all of the test_iov[].iov_base
	 * values in merged into continuous memory - it will not be
	 * returned as an iovec.*/
	assert_int_equal(validate_merged_data(MAX_TEST_ENTRIES, data), 0);
	assert_ptr_not_equal(iter = sid_kvs_iter_create(kv_store_res, NULL, NULL), NULL);
	while ((data = sid_kvs_iter_next(iter, &data_size, &key, &flags))) {
		assert_int_equal(strcmp(MERGE_KEY, key), 0);
		assert_int_equal(validate_merged_data(MAX_TEST_ENTRIES, data), 0);
	}

	sid_kvs_iter_destroy(iter);
	assert_int_equal(kv_store_num_entries(kv_store_res), 1);
	assert_int_equal(sid_kvs_va_unset(kv_store_res, .key = MERGE_KEY), 0);
	assert_int_equal(kv_store_num_entries(kv_store_res), 0);
	release_test_data(MAX_TEST_ENTRIES, test_iov, flags);
	sid_res_unref(kv_store_res);
}

int main(void)
{
	cmocka_set_message_output(CM_OUTPUT_STDOUT);
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_type_F),
		cmocka_unit_test(test_type_E),
		cmocka_unit_test(test_type_G),
		cmocka_unit_test(test_type_H),
		cmocka_unit_test(test_kvstore_iterate),
		cmocka_unit_test(test_kvstore_merge_op),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
