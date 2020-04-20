#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#define UNIT_TESTING /* enable cmocka memory testing in mem.c and kv-store.c*/
#include <cmocka.h>
#include "../src/misc/mem.c"
#include "../src/resource/kv-store.c"

static void test_type_G(void **state)
{
	struct iovec test_iov[] = {
		{"test", sizeof("test")},
		{"value", sizeof("value")}
	};
	size_t size = sizeof(test_iov)/sizeof(test_iov[0]);
	struct kv_store_value *value = _create_kv_store_value(test_iov, size,
	                                                      KV_STORE_VALUE_REF | KV_STORE_VALUE_VECTOR, 0);
	assert_ptr_not_equal(value, NULL);
	assert_ptr_equal(value->data_p, test_iov);
	assert_int_equal(value->size, size);
	assert_int_equal(value->int_flags, 0);
	assert_int_equal(value->ext_flags,
	                 KV_STORE_VALUE_REF | KV_STORE_VALUE_VECTOR);
	_destroy_kv_store_value(value);
}

static void test_type_H(void **state)
{
	struct iovec test_iov[] = {
		{"test", sizeof("test")},
		{"value", sizeof("value")}
	};
	size_t size = sizeof(test_iov)/sizeof(test_iov[0]);
	struct kv_store_value *value = _create_kv_store_value(test_iov, size,
	                                                      KV_STORE_VALUE_REF | KV_STORE_VALUE_VECTOR,
	                                                      KV_STORE_VALUE_OP_MERGE);
	assert_ptr_not_equal(value, NULL);
	_destroy_kv_store_value(value);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_type_G),
		cmocka_unit_test(test_type_H),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
