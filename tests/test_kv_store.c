#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#define UNIT_TESTING /* enable cmocka memory testing in mem.c and kv-store.c*/
#include "../src/internal/mem.c"
#include "../src/resource/kv-store.c"

#include <cmocka.h>

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

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_type_G),
		cmocka_unit_test(test_type_H),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
