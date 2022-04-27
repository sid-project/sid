#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
/* define __USE_GNU for ucred definition */
#define __USE_GNU
#include <sys/socket.h>
#define UNIT_TESTING /* enable cmocka memory testing in mem.c and kv-store.c*/
#include "../src/internal/mem.c"
#include "../src/resource/kv-store.c"
#include "../src/resource/ubridge.c"
#include "ucmd-module.h"

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
		_create_kv_store_value(test_iov, size, KV_STORE_VALUE_VECTOR, KV_STORE_VALUE_OP_MERGE, &value_size);
	assert_ptr_not_equal(value, NULL);
	assert_int_equal(memcmp(value->data, "test\0value", value->size), 0);
	assert_int_equal(value->size, combined_size);
	assert_int_equal(value->int_flags, KV_STORE_VALUE_INT_ALLOC);
	assert_int_equal(value->ext_flags, KV_STORE_VALUE_NO_OP);
	_destroy_kv_store_value(value);
}

static void test_type_E(void **state)
{
	struct iovec *         return_iov, test_iov[] = {{"test", sizeof("test")}, {"value", sizeof("value")}};
	size_t                 size = sizeof(test_iov) / sizeof(test_iov[0]);
	size_t                 value_size;
	struct kv_store_value *value =
		_create_kv_store_value(test_iov, size, KV_STORE_VALUE_VECTOR, KV_STORE_VALUE_NO_OP, &value_size);
	assert_ptr_not_equal(value, NULL);
	return_iov = (struct iovec *) value->data;

	for (int i = 0; i < value->size; i++) {
		assert_int_equal(return_iov[i].iov_len, test_iov[i].iov_len);
		assert_string_equal(return_iov[i].iov_base, test_iov[i].iov_base);
	}
	assert_int_equal(value->size, size);
	assert_int_equal(value->int_flags, KV_STORE_VALUE_INT_ALLOC);
	assert_int_equal(value->ext_flags, KV_STORE_VALUE_VECTOR);
	_destroy_kv_store_value(value);
}

static void test_type_G(void **state)
{
	struct iovec           test_iov[] = {{"test", sizeof("test")}, {"value", sizeof("value")}};
	size_t                 size       = sizeof(test_iov) / sizeof(test_iov[0]);
	size_t                 value_size;
	struct kv_store_value *value = _create_kv_store_value(test_iov,
	                                                      size,
	                                                      KV_STORE_VALUE_REF | KV_STORE_VALUE_VECTOR,
	                                                      KV_STORE_VALUE_NO_OP,
	                                                      &value_size);
	assert_ptr_not_equal(value, NULL);
	assert_ptr_equal(_get_ptr(value->data), test_iov);
	assert_int_equal(value->size, size);
	assert_int_equal(value->int_flags, 0);
	assert_int_equal(value->ext_flags, KV_STORE_VALUE_REF | KV_STORE_VALUE_VECTOR);
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
	                               KV_STORE_VALUE_REF | KV_STORE_VALUE_VECTOR,
	                               KV_STORE_VALUE_OP_MERGE,
	                               &value_size);
	assert_ptr_not_equal(value, NULL);
	assert_ptr_equal(_get_ptr(value->data), test_iov);
	assert_int_equal(value->size, size);
	for (i = 0; i < size; i++)
		assert_ptr_not_equal(test_iov[i].iov_base, old_iov[i].iov_base);
	assert_int_equal(value->int_flags, KV_STORE_VALUE_INT_ALLOC);
	assert_int_equal(value->ext_flags, KV_STORE_VALUE_REF | KV_STORE_VALUE_VECTOR);
	_destroy_kv_store_value(value);
	for (i = 0; i < size; i++) {
		assert_ptr_equal(test_iov[i].iov_base, NULL);
		assert_int_equal(test_iov[i].iov_len, 0);
	}
}

static void test_kvstore_iterate(void **state)
{
	struct iovec           test_iov[_VVALUE_IDX_COUNT];
	size_t                 data_size, kv_size;
	const char *           key;
	struct iovec *         return_iov;
	kv_store_iter_t *      iter;
	sid_ucmd_kv_flags_t    ucmd_flags = DEFAULT_VALUE_FLAGS_CORE;
	kv_store_value_flags_t flags;
	uint64_t               seqnum       = 0;
	sid_resource_t *       kv_store_res = NULL;
	struct kv_update_arg   update_arg;
	size_t                 meta_size = 0;

	kv_store_res = sid_resource_create(SID_RESOURCE_NO_PARENT,
	                                   &sid_resource_type_kv_store,
	                                   SID_RESOURCE_RESTRICT_WALK_UP,
	                                   "testkvstore",
	                                   &main_kv_store_res_params,
	                                   SID_RESOURCE_PRIO_NORMAL,
	                                   SID_RESOURCE_NO_SERVICE_LINKS);

	VVALUE_HEADER_PREP(test_iov, seqnum, seqnum, ucmd_flags, (char *) TEST_OWNER);
	test_iov[VVALUE_IDX_DATA].iov_base = "test";
	test_iov[VVALUE_IDX_DATA].iov_len  = sizeof("test");

	update_arg = (struct kv_update_arg) {.res      = kv_store_res,
	                                     .gen_buf  = NULL,
	                                     .owner    = TEST_OWNER,
	                                     .custom   = NULL,
	                                     .ret_code = -EREMOTEIO};

	/* Add the whole vector with TEST_KEY as the key */
	assert_ptr_not_equal(kv_store_set_value(kv_store_res,
	                                        TEST_KEY,
	                                        test_iov,
	                                        VVALUE_IDX_DATA + 1,
	                                        KV_STORE_VALUE_VECTOR,
	                                        KV_STORE_VALUE_NO_OP,
	                                        _kv_cb_overwrite,
	                                        &update_arg),
	                     NULL);

	assert_ptr_not_equal(iter = kv_store_iter_create(kv_store_res, NULL, NULL), NULL);
	/* validate the contents of the kv store */
	while ((return_iov = kv_store_iter_next(iter, &data_size, &key, &flags))) {
		assert_int_equal(strcmp(TEST_KEY, key), 0);
		assert_true(flags == KV_STORE_VALUE_VECTOR);
		assert_int_equal(strcmp(return_iov[VVALUE_IDX_DATA].iov_base, "test"), 0);
		assert_int_equal(return_iov[VVALUE_IDX_DATA].iov_len, sizeof("test"));
	}

	kv_store_iter_destroy(iter);
	kv_store_get_size(kv_store_res, &meta_size, &kv_size);

	assert_int_equal(kv_store_num_entries(kv_store_res), 1);
	/* TODO: if update_arg is NULL in the following call it causes SEGV */
	assert_int_equal(kv_store_unset_value(kv_store_res, TEST_KEY, _kv_cb_main_unset, &update_arg), 0);
	assert_int_equal(kv_store_num_entries(kv_store_res), 0);
	kv_store_get_size(kv_store_res, &meta_size, &data_size);
	assert_int_equal(data_size, 0);

	sid_resource_destroy(kv_store_res);
}

static size_t add_sequential_test_data(char *                    key,
                                       struct iovec              test_iov[MAX_TEST_ENTRIES],
                                       sid_resource_t *          kv_store_res,
                                       int                       num_entries,
                                       kv_store_value_flags_t    flags,
                                       kv_store_value_op_flags_t op_flags)
{
	size_t size = 0;

	for (int i = 0; i < num_entries; i++) {
		int   strlen = snprintf(NULL, 0, "%d", i);
		char *str    = malloc(strlen + 1);
		snprintf(str, strlen + 1, "%d", i);
		test_iov[i].iov_base = str;
		test_iov[i].iov_len  = strlen + 1;
		size += strlen + 1;
	}
	assert_ptr_not_equal(kv_store_set_value(kv_store_res, MERGE_KEY, test_iov, MAX_TEST_ENTRIES, flags, op_flags, NULL, NULL),
	                     NULL);

	/* if the kv store is making a copy, free this copy */
	if ((flags & KV_STORE_VALUE_REF) == 0) {
		for (int i = 0; i < num_entries; i++) {
			free(test_iov[i].iov_base);
		}
	}
	return size;
}

static void release_test_data(int num_entries, struct iovec test_iov[MAX_TEST_ENTRIES], kv_store_value_flags_t flags)
{
	/* non references are released when the kv-store makes a copy */
	if ((flags & KV_STORE_VALUE_REF) == 0)
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
	struct iovec           test_iov[MAX_TEST_ENTRIES];
	size_t                 data_size;
	const char *           key;
	void *                 data;
	kv_store_iter_t *      iter;
	kv_store_value_flags_t flags        = KV_STORE_VALUE_VECTOR;
	sid_resource_t *       kv_store_res = NULL;

	kv_store_res = sid_resource_create(SID_RESOURCE_NO_PARENT,
	                                   &sid_resource_type_kv_store,
	                                   SID_RESOURCE_RESTRICT_WALK_UP,
	                                   "testkvstore",
	                                   &main_kv_store_res_params,
	                                   SID_RESOURCE_PRIO_NORMAL,
	                                   SID_RESOURCE_NO_SERVICE_LINKS);

	add_sequential_test_data(MERGE_KEY, test_iov, kv_store_res, MAX_TEST_ENTRIES, flags, KV_STORE_VALUE_OP_MERGE);
	assert_int_equal(kv_store_num_entries(kv_store_res), 1);

	data = kv_store_get_value(kv_store_res, MERGE_KEY, &data_size, NULL);

	/* Validate the concatenated contents of the kv store.
	 * The data variable contains all of the test_iov[].iov_base
	 * values in merged into continuous memory - it will not be
	 * returned as an iovec.*/
	assert_int_equal(validate_merged_data(MAX_TEST_ENTRIES, data), 0);
	assert_ptr_not_equal(iter = kv_store_iter_create(kv_store_res, NULL, NULL), NULL);
	while ((data = kv_store_iter_next(iter, &data_size, &key, &flags))) {
		assert_int_equal(strcmp(MERGE_KEY, key), 0);
		assert_int_equal(validate_merged_data(MAX_TEST_ENTRIES, data), 0);
	}

	kv_store_iter_destroy(iter);
	assert_int_equal(kv_store_num_entries(kv_store_res), 1);
	assert_int_equal(kv_store_unset_value(kv_store_res, MERGE_KEY, NULL, NULL), 0);
	assert_int_equal(kv_store_num_entries(kv_store_res), 0);
	release_test_data(MAX_TEST_ENTRIES, test_iov, flags);
	sid_resource_destroy(kv_store_res);
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
