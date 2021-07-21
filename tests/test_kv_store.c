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
	struct iovec           test_iov[_KV_VALUE_IDX_COUNT];
	size_t                 data_size, kv_size;
	struct iovec *         return_iov;
	kv_store_iter_t *      iter;
	sid_ucmd_kv_flags_t    ucmd_flags = DEFAULT_KV_FLAGS_CORE;
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

	KV_VALUE_PREPARE_HEADER(test_iov, seqnum, ucmd_flags, (char *) TEST_OWNER);
	test_iov[KV_VALUE_IDX_DATA].iov_base = "test";
	test_iov[KV_VALUE_IDX_DATA].iov_len  = sizeof("test");

	update_arg = (struct kv_update_arg) {.res      = kv_store_res,
	                                     .gen_buf  = NULL,
	                                     .owner    = TEST_OWNER,
	                                     .custom   = NULL,
	                                     .ret_code = -EREMOTEIO};

	/* Add the whole vector with TEST_KEY as the key */
	assert_ptr_not_equal(kv_store_set_value(kv_store_res,
	                                        TEST_KEY,
	                                        test_iov,
	                                        KV_VALUE_IDX_DATA + 1,
	                                        KV_STORE_VALUE_VECTOR,
	                                        KV_STORE_VALUE_NO_OP,
	                                        _kv_overwrite,
	                                        &update_arg),
	                     NULL);

	assert_ptr_not_equal(iter = kv_store_iter_create(kv_store_res), NULL);
	/* validate the contents of the kv store */
	while ((return_iov = kv_store_iter_next(iter, &data_size, &flags))) {
		assert_true(flags == KV_STORE_VALUE_VECTOR);
		assert_int_equal(strcmp(return_iov[KV_VALUE_IDX_DATA].iov_base, "test"), 0);
		assert_int_equal(return_iov[KV_VALUE_IDX_DATA].iov_len, sizeof("test"));
	}

	kv_store_iter_destroy(iter);
	kv_store_get_size(kv_store_res, &meta_size, &kv_size);

	assert_int_equal(kv_store_num_entries(kv_store_res), 1);
	/* TODO: if update_arg is NULL in the following call it causes SEGV */
	assert_int_equal(kv_store_unset_value(kv_store_res, TEST_KEY, _main_kv_store_unset, &update_arg), 0);
	assert_int_equal(kv_store_num_entries(kv_store_res), 0);
	kv_store_get_size(kv_store_res, &meta_size, &data_size);
	assert_int_equal(data_size, 0);

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
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
